package org.privacage.dns

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

/** Callback used by Android integration to call VpnService.protect(socket). */
fun interface UdpSocketProtector {
    fun protect(socket: DatagramSocket): Boolean
}

/**
 * One-query UDP DNS forwarder with bounded wait time and response identity checks.
 *
 * The caller supplies a socket protector so the upstream socket can bypass the local VPN
 * interface. The class does not create a VPN or handle TCP DNS fallback.
 */
class UdpDnsForwarder(
    private val resolver: InetSocketAddress,
    private val socketProtector: UdpSocketProtector,
    private val timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS
) {

    init {
        require(!resolver.isUnresolved) { "DNS resolver address must be resolved" }
        require(resolver.port in 1..65535) { "DNS resolver port must be between 1 and 65535" }
        require(timeoutMillis in 1..MAX_TIMEOUT_MILLIS) { "DNS timeout must be between 1 and 60000 ms" }
    }

    /**
     * Sends one supported DNS query and returns its matching DNS response.
     *
     * Throws IOException for protection failures, socket errors, timeouts, or invalid responses.
     * Does not retry or silently convert failures into synthetic answers.
     */
    @Throws(IOException::class)
    fun forward(query: ByteArray): ByteArray {
        if (query.size > MAX_UDP_DNS_PAYLOAD) throw IOException("DNS query exceeds UDP payload limit")
        val expectedQuestion = readSupportedQuery(query)

        DatagramSocket().use { socket ->
            if (!socketProtector.protect(socket)) {
                throw IOException("Failed to protect upstream DNS socket from VPN routing")
            }

            socket.soTimeout = timeoutMillis
            socket.connect(resolver)
            socket.send(DatagramPacket(query, query.size))

            val buffer = ByteArray(MAX_UDP_DNS_PAYLOAD)
            val incoming = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(incoming)
            } catch (e: SocketTimeoutException) {
                throw e
            }

            val response = buffer.copyOf(incoming.length)
            validateResponse(query, expectedQuestion, response)
            return response
        }
    }

    private fun readSupportedQuery(message: ByteArray): DnsQuestionView {
        return when (val decision = DnsPolicyEngine(emptySet()).evaluate(message)) {
            is DnsDecision.Allow -> decision.question
            is DnsDecision.Block -> decision.question
            is DnsDecision.Malformed -> throw IOException("Refusing to forward malformed DNS query: ${decision.reason}")
        }
    }

    private fun validateResponse(
        query: ByteArray,
        expectedQuestion: DnsQuestionView,
        response: ByteArray
    ) {
        if (response.size < DNS_HEADER_SIZE) throw IOException("DNS response header is truncated")
        if (u16(response, 0) != u16(query, 0)) throw IOException("DNS response ID does not match query")
        val flags = u16(response, 2)
        if ((flags and FLAG_QR) == 0) throw IOException("Upstream packet is not a DNS response")
        if ((flags and OPCODE_MASK) != 0) throw IOException("Upstream response uses an unsupported opcode")
        if (u16(response, 4) != 1) throw IOException("Upstream response must echo exactly one question")

        val actualQuestion = readResponseQuestion(response)
        if (
            actualQuestion.name != expectedQuestion.name ||
            actualQuestion.type != expectedQuestion.type ||
            actualQuestion.recursionDesired != expectedQuestion.recursionDesired
        ) {
            throw IOException("DNS response question does not match query")
        }
    }

    private fun readResponseQuestion(message: ByteArray): DnsQuestionView {
        var offset = DNS_HEADER_SIZE
        val labels = ArrayList<String>()
        var totalNameLength = 0

        while (true) {
            if (offset >= message.size) throw IOException("DNS response question name is truncated")
            val length = message[offset++].toInt() and 0xff
            if (length == 0) break
            if ((length and 0xc0) != 0 || length > 63 || offset + length > message.size) {
                throw IOException("DNS response contains an unsupported question label")
            }

            val bytes = message.copyOfRange(offset, offset + length)
            if (bytes.any { (it.toInt() and 0xff) !in 0x21..0x7e }) {
                throw IOException("DNS response question contains unsupported characters")
            }
            labels += bytes.toString(Charsets.US_ASCII).lowercase()
            totalNameLength += length + 1
            if (totalNameLength > 254) throw IOException("DNS response question name is too long")
            offset += length
        }

        if (labels.isEmpty() || offset + DNS_QUESTION_TAIL_SIZE > message.size) {
            throw IOException("DNS response question is incomplete")
        }
        val type = u16(message, offset)
        val recordClass = u16(message, offset + 2)
        if (recordClass != CLASS_IN) throw IOException("DNS response question class is unsupported")

        return DnsQuestionView(
            id = u16(message, 0),
            name = labels.joinToString("."),
            type = type,
            recursionDesired = (u16(message, 2) and FLAG_RD) != 0
        )
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    companion object {
        private const val DEFAULT_TIMEOUT_MILLIS = 2500
        private const val MAX_TIMEOUT_MILLIS = 60_000
        private const val MAX_UDP_DNS_PAYLOAD = 65_507
        private const val DNS_HEADER_SIZE = 12
        private const val DNS_QUESTION_TAIL_SIZE = 4
        private const val CLASS_IN = 1
        private const val FLAG_QR = 0x8000
        private const val FLAG_RD = 0x0100
        private const val OPCODE_MASK = 0x7800
    }
}
