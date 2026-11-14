package org.privacage.dns

import java.io.IOException
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * An explicit, bounded DNS A-record probe through the configured upstream transport.
 *
 * This checks one resolver path at one point in time. It is not a test of every app, protocol,
 * IP family, or route on the device. The caller is responsible for using a protected upstream
 * socket when called from a VpnService.
 */
object DnsRouteDiagnostic {
    const val PROBE_HOSTNAME = "example.com"
    private const val DNS_HEADER_SIZE = 12
    private const val DNS_TYPE_A = 1
    private const val DNS_CLASS_IN = 1
    private val random = SecureRandom()

    data class Result(
        val responseReceived: Boolean,
        val validDnsResponse: Boolean,
        val resolved: Boolean,
        val elapsedMillis: Long,
        val responseCode: Int?,
        val answerCount: Int?,
        val message: String
    )

    /** Sends one diagnostic query. Query names and packets are not persisted by this class. */
    fun run(transport: DnsUpstreamTransport): Result {
        val query = buildQuery(random.nextInt(0x10000))
        val started = System.nanoTime()
        var responseReceived = false
        return try {
            val response = transport.forward(query)
            responseReceived = true
            val summary = parseResponse(query, response)
            val elapsed = elapsedMillisSince(started)
            val resolved = summary.responseCode == 0 && summary.answerCount > 0
            val codeName = responseCodeName(summary.responseCode)
            val message = when {
                summary.responseCode != 0 ->
                    "Resolver returned $codeName (DNS response code ${summary.responseCode}). The configured transport responded, but the probe did not resolve successfully."
                summary.answerCount == 0 ->
                    "Resolver returned NOERROR but no answer records for the fixed probe. The transport responded, but name resolution was not demonstrated."
                else ->
                    "Resolver returned NOERROR with ${summary.answerCount} answer record(s)."
            }
            Result(true, true, resolved, elapsed, summary.responseCode, summary.answerCount, message)
        } catch (exception: Exception) {
            val detail = when (exception) {
                is SocketTimeoutException -> "Timed out waiting for the configured resolver."
                else -> exception.message?.take(180)?.let { " ${it}" }
                    ?: " ${exception.javaClass.simpleName}"
            }
            Result(
                responseReceived = responseReceived,
                validDnsResponse = false,
                resolved = false,
                elapsedMillis = elapsedMillisSince(started),
                responseCode = null,
                answerCount = null,
                message = if (responseReceived) {
                    "A response arrived but failed DNS validation.$detail"
                } else {
                    "No valid DNS response was received.$detail"
                }
            )
        }
    }

    internal fun buildQuery(transactionId: Int): ByteArray {
        require(transactionId in 0..0xffff) { "DNS transaction ID must fit in 16 bits" }
        val qname = PROBE_HOSTNAME.split('.').flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        } + listOf(0.toByte())
        return byteArrayOf(
            (transactionId ushr 8).toByte(),
            transactionId.toByte(),
            0x01, 0x00, // Standard query with recursion desired.
            0x00, 0x01, // Exactly one question.
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        ) + qname.toByteArray() + byteArrayOf(0, DNS_TYPE_A.toByte(), 0, DNS_CLASS_IN.toByte())
    }

    private data class ResponseSummary(val responseCode: Int, val answerCount: Int)

    private fun parseResponse(query: ByteArray, response: ByteArray): ResponseSummary {
        if (response.size < DNS_HEADER_SIZE) throw IOException("DNS response is shorter than the header")
        if (u16(response, 0) != u16(query, 0)) throw IOException("DNS response transaction ID does not match the probe")
        val flags = u16(response, 2)
        if ((flags and 0x8000) == 0) throw IOException("Upstream packet is not a DNS response")
        if ((flags and 0x7800) != 0) throw IOException("DNS response uses an unsupported opcode")
        if (u16(response, 4) != 1) throw IOException("DNS response must echo exactly one question")

        val queryQuestion = readQuestion(query)
        val responseQuestion = readQuestion(response)
        if (
            !responseQuestion.name.equals(queryQuestion.name, ignoreCase = true) ||
            responseQuestion.type != queryQuestion.type ||
            responseQuestion.recordClass != queryQuestion.recordClass
        ) {
            throw IOException("DNS response question does not match the probe")
        }
        return ResponseSummary(flags and 0x000f, u16(response, 6))
    }

    private data class Question(val name: String, val type: Int, val recordClass: Int)

    private fun readQuestion(message: ByteArray): Question {
        var offset = DNS_HEADER_SIZE
        val labels = mutableListOf<String>()
        var expandedLength = 1
        while (true) {
            if (offset !in message.indices) throw IOException("DNS question name is truncated")
            val length = message[offset++].toInt() and 0xff
            if (length == 0) break
            if ((length and 0xc0) != 0 || length > 63 || offset + length > message.size) {
                throw IOException("DNS question label is invalid or truncated")
            }
            val label = message.copyOfRange(offset, offset + length)
            if (label.any { (it.toInt() and 0xff) !in 0x21..0x7e }) {
                throw IOException("DNS question contains an unsupported label")
            }
            labels += label.toString(Charsets.US_ASCII)
            expandedLength += length + 1
            if (expandedLength > 255) throw IOException("DNS question name is too long")
            offset += length
        }
        if (labels.isEmpty() || offset + 4 > message.size) throw IOException("DNS question is incomplete")
        return Question(
            name = labels.joinToString("."),
            type = u16(message, offset),
            recordClass = u16(message, offset + 2)
        )
    }

    private fun responseCodeName(code: Int): String = when (code) {
        0 -> "NOERROR"
        1 -> "FORMERR"
        2 -> "SERVFAIL"
        3 -> "NXDOMAIN"
        4 -> "NOTIMP"
        5 -> "REFUSED"
        else -> "RCODE $code"
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun elapsedMillisSince(startedNanos: Long): Long =
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)
}
