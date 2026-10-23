package org.privacage.dns

import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DnsOverTlsForwarderTest {
    @Test fun normalizesValidHostname() { assertEquals("dns.google", DnsOverTlsForwarder.validateHostname("DNS.GOOGLE.")) }
    @Test fun rejectsSingleLabelHostname() { assertFailsWith<IllegalArgumentException> { DnsOverTlsForwarder.validateHostname("resolver") } }
    @Test fun rejectsMalformedHostname() { assertFailsWith<IllegalArgumentException> { DnsOverTlsForwarder.validateHostname("dns..google") } }
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
