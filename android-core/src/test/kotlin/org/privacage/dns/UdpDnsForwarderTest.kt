package org.privacage.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class UdpDnsForwarderTest {

    @Test
    fun forwardsAllowedQueryToResolverAndReturnsMatchingResponse() {
        val query = dnsQuery("news.example.org")
        val expectedResponse = dnsResponse(query)
        val server = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        server.soTimeout = 3000
        val serverFailure = AtomicReference<Throwable?>(null)
        val serverThread = Thread {
            try {
                val buffer = ByteArray(2048)
                val incoming = DatagramPacket(buffer, buffer.size)
                server.receive(incoming)
                assertContentEquals(query, buffer.copyOf(incoming.length))
                server.send(DatagramPacket(expectedResponse, expectedResponse.size, incoming.socketAddress))
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }
        serverThread.start()

        try {
            val forwarder = UdpDnsForwarder(
                resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort),
                socketProtector = UdpSocketProtector { true },
                policyEngine = DnsPolicyEngine(setOf("tracker.example")),
                timeoutMillis = 2000
            )
            assertContentEquals(expectedResponse, forwarder.forward(query))
            serverThread.join(3000)
            assertTrue(!serverThread.isAlive, "DNS test server thread did not finish")
            serverFailure.get()?.let { throw AssertionError("DNS test server failed", it) }
        } finally {
            server.close()
            serverThread.join(3000)
        }
    }

    @Test
    fun retriesTruncatedUdpResponseOverProtectedTcp() {
        val query = dnsQuery("news.example.org")
        val truncatedResponse = dnsResponse(query).apply {
            this[2] = (this[2].toInt() or 0x02).toByte()
        }
        val completeResponse = dnsResponse(query)
        // Reserve the TCP port first, then bind UDP to the same numeric port. Binding
        // TCP after choosing a UDP ephemeral port can race with unrelated local TCP users.
        val (udpServer, tcpServer) = createPairedDnsServers()
        udpServer.soTimeout = 3000
        tcpServer.soTimeout = 3000
        val tcpProtected = AtomicBoolean(false)
        val serverFailure = AtomicReference<Throwable?>(null)

        val serverThread = Thread {
            try {
                val udpBuffer = ByteArray(2048)
                val udpRequest = DatagramPacket(udpBuffer, udpBuffer.size)
                udpServer.receive(udpRequest)
                udpServer.send(
                    DatagramPacket(truncatedResponse, truncatedResponse.size, udpRequest.socketAddress)
                )

                tcpServer.accept().use { connection ->
                    connection.soTimeout = 3000
                    val input = DataInputStream(connection.getInputStream())
                    val queryLength = input.readUnsignedShort()
                    val tcpQuery = ByteArray(queryLength)
                    input.readFully(tcpQuery)
                    assertContentEquals(query, tcpQuery)

                    val output = DataOutputStream(connection.getOutputStream())
                    output.writeShort(completeResponse.size)
                    output.write(completeResponse)
                    output.flush()
                }
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }
        serverThread.start()

        try {
            val forwarder = UdpDnsForwarder(
                resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), udpServer.localPort),
                socketProtector = UdpSocketProtector { true },
                policyEngine = DnsPolicyEngine(emptySet()),
                timeoutMillis = 2000,
                tcpSocketProtector = TcpSocketProtector {
                    tcpProtected.set(true)
                    true
                }
            )
            assertContentEquals(completeResponse, forwarder.forward(query))
            assertTrue(tcpProtected.get(), "TCP fallback socket must be protected before connect")
            serverThread.join(3000)
            assertTrue(!serverThread.isAlive, "DNS test server thread did not finish")
            serverFailure.get()?.let { throw AssertionError("DNS test server failed", it) }
        } finally {
            udpServer.close()
            tcpServer.close()
            serverThread.join(3000)
        }
    }

    @Test
    fun refusesToForwardBlockedQuery() {
        val forwarder = UdpDnsForwarder(
            resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), 9),
            socketProtector = UdpSocketProtector { true },
            policyEngine = DnsPolicyEngine(setOf("tracker.example"))
        )
        assertFailsWith<IOException> {
            forwarder.forward(dnsQuery("tracker.example"))
        }
    }

    @Test
    fun refusesToOpenUnprotectedUpstreamSocket() {
        val forwarder = UdpDnsForwarder(
            resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), 9),
            socketProtector = UdpSocketProtector { false },
            policyEngine = DnsPolicyEngine(emptySet())
        )
        assertFailsWith<IOException> {
            forwarder.forward(dnsQuery("news.example.org"))
        }
    }

    @Test
    fun rejectsResponseWithMismatchedQuestion() {
        val query = dnsQuery("news.example.org")
        val wrongQuestion = dnsResponse(query)
        wrongQuestion[13] = 'm'.code.toByte()
        val failure = forwardWithResponse(query, wrongQuestion)
        assertEquals("DNS response question does not match query", failure.message)
    }

    @Test
    fun rejectsResponseWithTruncatedResourceRecordData() {
        val query = dnsQuery("news.example.org")
        val response = dnsResponse(query)
        response[7] = 1 // ANCOUNT = 1
        val truncatedRecord = byteArrayOf(
            0xc0.toByte(), 0x0c,
            0, 1,
            0, 1,
            0, 0, 0, 60,
            0, 4,
            192.toByte(), 0
        )
        val failure = forwardWithResponse(query, response + truncatedRecord)
        assertEquals("DNS resource record data is truncated", failure.message)
    }

    @Test
    fun rejectsTrailingBytesAfterDeclaredResourceRecords() {
        val query = dnsQuery("news.example.org")
        val response = dnsResponse(query) + byteArrayOf(0x55)
        val failure = forwardWithResponse(query, response)
        assertEquals("DNS response contains trailing bytes after its resource records", failure.message)
    }

    private fun createPairedDnsServers(): Pair<DatagramSocket, ServerSocket> {
        var lastBindFailure: IOException? = null
        repeat(10) {
            val tcpServer = ServerSocket()
            try {
                tcpServer.reuseAddress = true
                tcpServer.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                val udpServer = try {
                    DatagramSocket(null).apply {
                        bind(InetSocketAddress(InetAddress.getLoopbackAddress(), tcpServer.localPort))
                    }
                } catch (failure: IOException) {
                    tcpServer.close()
                    lastBindFailure = failure
                    return@repeat
                }
                return udpServer to tcpServer
            } catch (failure: IOException) {
                tcpServer.close()
                lastBindFailure = failure
            }
        }
        throw IOException("Unable to allocate paired loopback UDP/TCP ports for DNS test", lastBindFailure)
    }

    private fun forwardWithResponse(query: ByteArray, response: ByteArray): IOException {
        val server = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        server.soTimeout = 3000
        val serverFailure = AtomicReference<Throwable?>(null)
        val serverThread = Thread {
            try {
                val buffer = ByteArray(2048)
                val incoming = DatagramPacket(buffer, buffer.size)
                server.receive(incoming)
                server.send(DatagramPacket(response, response.size, incoming.socketAddress))
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }
        serverThread.start()

        try {
            val forwarder = UdpDnsForwarder(
                resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort),
                socketProtector = UdpSocketProtector { true },
                policyEngine = DnsPolicyEngine(emptySet()),
                timeoutMillis = 2000
            )
            val failure = assertFailsWith<IOException> { forwarder.forward(query) }
            serverThread.join(3000)
            assertTrue(!serverThread.isAlive, "DNS test server thread did not finish")
            serverFailure.get()?.let { throw AssertionError("DNS test server failed", it) }
            return failure
        } finally {
            server.close()
            serverThread.join(3000)
        }
    }

    private fun dnsQuery(name: String): ByteArray {
        val qname = name.split('.').flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        } + listOf(0.toByte())
        return byteArrayOf(
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ) + qname.toByteArray() + byteArrayOf(0, 1, 0, 1)
    }

    private fun dnsResponse(query: ByteArray): ByteArray {
        val response = query.copyOf()
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }
}
