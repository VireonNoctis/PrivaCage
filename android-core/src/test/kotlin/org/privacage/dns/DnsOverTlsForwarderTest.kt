package org.privacage.dns

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocketFactory

class DnsOverTlsForwarderTest {
    @Test fun normalizesValidHostname() { assertEquals("dns.google", DnsOverTlsForwarder.validateHostname("DNS.GOOGLE.")) }
    @Test fun rejectsSingleLabelHostname() { assertFailsWith<IllegalArgumentException> { DnsOverTlsForwarder.validateHostname("resolver") } }
    @Test fun rejectsMalformedHostname() { assertFailsWith<IllegalArgumentException> { DnsOverTlsForwarder.validateHostname("dns..google") } }
    @Test
    fun rejectsInvalidTimeoutAndPortBeforeAnyNetworkOperation() {
        assertFailsWith<IllegalArgumentException> {
            DnsOverTlsForwarder(
                InetAddress.getLoopbackAddress(), "dns.google",
                TcpSocketProtector { true }, DnsPolicyEngine(emptySet()), timeoutMillis = 0
            )
        }
        assertFailsWith<IllegalArgumentException> {
            DnsOverTlsForwarder(
                InetAddress.getLoopbackAddress(), "dns.google",
                TcpSocketProtector { true }, DnsPolicyEngine(emptySet()), port = 65_536
            )
        }
    }

    @Test
    fun unprotectedUpstreamSocketFailsClosedBeforeConnect() {
        var protectionCalls = 0
        val forwarder = DnsOverTlsForwarder(
            InetAddress.getLoopbackAddress(),
            "dns.google",
            TcpSocketProtector { protectionCalls += 1; false },
            DnsPolicyEngine(emptySet()),
            timeoutMillis = 100,
            port = 9
        )
        val query = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1
        )

        val failure = assertFailsWith<IOException> { forwarder.forward(query) }
        assertEquals(1, protectionCalls)
        assertTrue(failure.message.orEmpty().contains("Failed to protect"))
    }

    @Test
    fun tlsHandshakeFailureSendsNoDnsQueryInPlaintext() {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val receivedBytes = AtomicInteger(-1)
        val serverThread = Thread {
            try {
                server.accept().use { accepted ->
                    receivedBytes.set(accepted.getInputStream().readBytes().size)
                }
            } catch (_: IOException) {
                receivedBytes.set(-2)
            }
        }
        serverThread.start()

        val failingTlsFactory = object : SSLSocketFactory() {
            override fun getDefaultCipherSuites(): Array<String> = emptyArray()
            override fun getSupportedCipherSuites(): Array<String> = emptyArray()
            override fun createSocket(socket: Socket, host: String, port: Int, autoClose: Boolean): Socket {
                throw SSLHandshakeException("test certificate/hostname validation failure")
            }
            override fun createSocket(host: String, port: Int): Socket = throw UnsupportedOperationException()
            override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
                throw UnsupportedOperationException()
            override fun createSocket(host: InetAddress, port: Int): Socket = throw UnsupportedOperationException()
            override fun createSocket(
                address: InetAddress,
                port: Int,
                localAddress: InetAddress,
                localPort: Int
            ): Socket = throw UnsupportedOperationException()
            override fun createSocket(): Socket = throw UnsupportedOperationException()
        }

        val query = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1
        )
        try {
            val forwarder = DnsOverTlsForwarder(
                InetAddress.getLoopbackAddress(),
                "dns.google",
                TcpSocketProtector { true },
                DnsPolicyEngine(emptySet()),
                timeoutMillis = 1_000,
                port = server.localPort,
                socketFactory = failingTlsFactory
            )
            val failure = assertFailsWith<SSLHandshakeException> { forwarder.forward(query) }
            assertTrue(failure.message.orEmpty().contains("certificate/hostname"))
            serverThread.join(2_000)
            assertEquals(0, receivedBytes.get())
        } finally {
            server.close()
            serverThread.join(2_000)
        }
    }

    @Test fun blockedQueryIsRejectedBeforeSocketProtection() {
        var protected = false
        val forwarder = DnsOverTlsForwarder(
            InetAddress.getLoopbackAddress(), "dns.google",
            TcpSocketProtector { _: Socket -> protected = true; true },
            DnsPolicyEngine(setOf("tracker.example"))
        )
        val query = byteArrayOf(0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0,7,116,114,97,99,107,101,114,7,101,120,97,109,112,108,101,0,0,1,0,1)
        val failure = assertFailsWith<IOException> { forwarder.forward(query) }
        assertTrue(failure.message.orEmpty().contains("blocked DNS query"))
        assertTrue(!protected, "Blocked query must not open an upstream socket")
    }
}
