package org.privacage.dns

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
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
        val server = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        server.soTimeout = 3000
        val serverThread = Thread {
            val buffer = ByteArray(2048)
            val incoming = DatagramPacket(buffer, buffer.size)
            server.receive(incoming)
            val wrongQuestion = dnsResponse(query)
            wrongQuestion[13] = 'm'.code.toByte()
            server.send(DatagramPacket(wrongQuestion, wrongQuestion.size, incoming.socketAddress))
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
            assertEquals("DNS response question does not match query", failure.message)
            serverThread.join(3000)
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
