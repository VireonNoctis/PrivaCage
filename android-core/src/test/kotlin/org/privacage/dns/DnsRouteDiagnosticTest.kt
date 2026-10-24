package org.privacage.dns

import java.net.SocketTimeoutException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsRouteDiagnosticTest {
    @Test
    fun probeQueryIsOneRecursiveAQuestionForExampleCom() {
        val query = DnsRouteDiagnostic.buildQuery(0x1234)
        assertEquals(0x1234, u16(query, 0))
        assertEquals(0x0100, u16(query, 2))
        assertEquals(1, u16(query, 4))
        assertEquals(1, u16(query, query.size - 4))
        assertEquals(1, u16(query, query.size - 2))
        assertTrue(query.toString(Charsets.ISO_8859_1).contains("example"))
        assertTrue(query.toString(Charsets.ISO_8859_1).contains("com"))
    }

    @Test
    fun reportsValidNoErrorAnswerAsResolved() {
        val result = DnsRouteDiagnostic.run(DnsUpstreamTransport { query -> response(query, 0x8180, answer = true) })
        assertTrue(result.responseReceived)
        assertTrue(result.validDnsResponse)
        assertTrue(result.resolved)
        assertEquals(0, result.responseCode)
        assertEquals(1, result.answerCount)
    }

    @Test
    fun distinguishesResolverReachabilityFromNxdomain() {
        val result = DnsRouteDiagnostic.run(DnsUpstreamTransport { query -> response(query, 0x8183) })
        assertTrue(result.responseReceived)
        assertTrue(result.validDnsResponse)
        assertFalse(result.resolved)
        assertEquals(3, result.responseCode)
        assertTrue(result.message.contains("NXDOMAIN"))
    }

    @Test
    fun noErrorWithoutAnswerDoesNotClaimTheProbeResolved() {
        val result = DnsRouteDiagnostic.run(DnsUpstreamTransport { query -> response(query, 0x8180) })
        assertTrue(result.responseReceived)
        assertTrue(result.validDnsResponse)
        assertFalse(result.resolved)
        assertEquals(0, result.answerCount)
        assertTrue(result.message.contains("no answer records"))
    }

    @Test
    fun rejectsMismatchedTransactionId() {
        val result = DnsRouteDiagnostic.run(DnsUpstreamTransport { query ->
            response(query, 0x8180).also { it[1] = (it[1].toInt() xor 1).toByte() }
        })
        assertTrue(result.responseReceived)
        assertFalse(result.validDnsResponse)
        assertFalse(result.resolved)
        assertTrue(result.message.contains("transaction ID does not match"))
    }

    @Test
    fun reportsTimeoutWithoutClaimingTheResolverResponded() {
        val result = DnsRouteDiagnostic.run(DnsUpstreamTransport { throw SocketTimeoutException("receive timed out") })
        assertFalse(result.responseReceived)
        assertFalse(result.validDnsResponse)
        assertFalse(result.resolved)
        assertTrue(result.message.contains("Timed out"))
    }

    @Test
    fun rejectsResponseQuestionThatDoesNotMatchProbe() {
        val result = DnsRouteDiagnostic.run(DnsUpstreamTransport { query ->
            response(query, 0x8180).also { it[13] = 'n'.code.toByte() }
        })
        assertTrue(result.responseReceived)
        assertFalse(result.validDnsResponse)
        assertTrue(result.message.contains("question does not match"))
    }

    private fun response(query: ByteArray, flags: Int, answer: Boolean = false): ByteArray {
        val headerAndQuestion = query.copyOf()
        headerAndQuestion[2] = (flags ushr 8).toByte()
        headerAndQuestion[3] = flags.toByte()
        headerAndQuestion[6] = 0
        headerAndQuestion[7] = if (answer) 1 else 0
        if (!answer) return headerAndQuestion
        val ipv4Answer = byteArrayOf(
            0xc0.toByte(), 0x0c, // Owner is the question name.
            0, 1,                // A
            0, 1,                // IN
            0, 0, 0, 60,         // TTL
            0, 4,                // RDLENGTH
            93.toByte(), 184.toByte(), 216.toByte(), 34
        )
        return headerAndQuestion + ipv4Answer
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
