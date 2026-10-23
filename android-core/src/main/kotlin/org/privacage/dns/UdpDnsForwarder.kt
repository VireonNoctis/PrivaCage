package org.privacage.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket

/** Callback used by Android integration to call VpnService.protect(socket). */
interface DnsUpstreamTransport {
    @Throws(IOException::class)
    fun forward(query: ByteArray): ByteArray
}

fun interface UdpSocketProtector {
    fun protect(socket: DatagramSocket): Boolean
}

/** TCP counterpart to [UdpSocketProtector], used only for DNS truncation fallback. */
fun interface TcpSocketProtector {
    fun protect(socket: Socket): Boolean
}

/**
 * UDP DNS forwarder with bounded waits, response structure checks, and TCP fallback for TC replies.
 *
 * A caller-supplied protector must be provided for TCP fallback; without it, a truncated UDP
 * response fails explicitly rather than opening a socket that could loop back through a VPN.
 */
class UdpDnsForwarder(
    private val resolver: InetSocketAddress,
    private val socketProtector: UdpSocketProtector,
    private val policyEngine: DnsPolicyEngine,
    private val timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
    private val tcpSocketProtector: TcpSocketProtector? = null
) : DnsUpstreamTransport {

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
    override fun forward(query: ByteArray): ByteArray {
        if (query.size > MAX_UDP_DNS_PAYLOAD) throw IOException("DNS query exceeds UDP payload limit")
        val expectedQuestion = readSupportedQuery(query)

        val udpResponse = DatagramSocket().use { socket ->
            if (!socketProtector.protect(socket)) {
                throw IOException("Failed to protect upstream DNS socket from VPN routing")
            }

            socket.soTimeout = timeoutMillis
            socket.connect(resolver)
            socket.send(DatagramPacket(query, query.size, resolver))

            val buffer = ByteArray(MAX_UDP_DNS_PAYLOAD)
            val incoming = DatagramPacket(buffer, buffer.size)
            socket.receive(incoming)
            buffer.copyOf(incoming.length)
        }

        return if (validateResponse(query, expectedQuestion, udpResponse)) {
            forwardOverTcp(query, expectedQuestion)
        } else {
            udpResponse
        }
    }

    private fun forwardOverTcp(query: ByteArray, expectedQuestion: DnsQuestionView): ByteArray {
        val protector = tcpSocketProtector
            ?: throw IOException("Upstream DNS response is truncated and TCP fallback is not configured")

        Socket().use { socket ->
            if (!protector.protect(socket)) {
                throw IOException("Failed to protect upstream TCP DNS socket from VPN routing")
            }

            socket.connect(resolver, timeoutMillis)
            socket.soTimeout = timeoutMillis
            val output = DataOutputStream(socket.getOutputStream())
            output.writeShort(query.size)
            output.write(query)
            output.flush()

            val input = DataInputStream(socket.getInputStream())
            val responseLength = input.readUnsignedShort()
            if (responseLength < DNS_HEADER_SIZE) {
                throw IOException("TCP DNS response is shorter than the DNS header")
            }
            if (responseLength > MAX_UDP_DNS_PAYLOAD) {
                throw IOException("TCP DNS response is too large to return to the UDP client")
            }

            val response = ByteArray(responseLength)
            input.readFully(response)
            if (validateResponse(query, expectedQuestion, response)) {
                throw IOException("TCP DNS response is still marked truncated")
            }
            return response
        }
    }

    private fun readSupportedQuery(message: ByteArray): DnsQuestionView {
        return when (val decision = policyEngine.evaluate(message)) {
            is DnsDecision.Allow -> decision.question
            is DnsDecision.Block -> throw IOException(
                "Refusing to forward blocked DNS query matching rule: ${decision.matchedRule}"
            )
            is DnsDecision.Malformed -> throw IOException("Refusing to forward malformed DNS query: ${decision.reason}")
        }
    }

    /** Returns true when the response's TC flag requires TCP fallback. */
    private fun validateResponse(
        query: ByteArray,
        expectedQuestion: DnsQuestionView,
        response: ByteArray
    ): Boolean {
        if (response.size < DNS_HEADER_SIZE) throw IOException("DNS response header is truncated")
        if (u16(response, 0) != u16(query, 0)) throw IOException("DNS response ID does not match query")
        val flags = u16(response, 2)
        if ((flags and FLAG_QR) == 0) throw IOException("Upstream packet is not a DNS response")
        if ((flags and OPCODE_MASK) != 0) throw IOException("Upstream response uses an unsupported opcode")
        if (u16(response, 4) != 1) throw IOException("Upstream response must echo exactly one question")

        val parsedQuestion = readResponseQuestion(response)
        val actualQuestion = parsedQuestion.question
        if (
            actualQuestion.name != expectedQuestion.name ||
            actualQuestion.type != expectedQuestion.type ||
            actualQuestion.recursionDesired != expectedQuestion.recursionDesired
        ) {
            throw IOException("DNS response question does not match query")
        }

        var offset = parsedQuestion.endOffset
        val recordCount = u16(response, 6) + u16(response, 8) + u16(response, 10)
        repeat(recordCount) {
            offset = skipResourceRecord(response, offset)
        }
        if (offset != response.size) {
            throw IOException("DNS response contains trailing bytes after its resource records")
        }
        return (flags and FLAG_TC) != 0
    }

    private fun readResponseQuestion(message: ByteArray): ParsedResponseQuestion {
        val parsedName = readDnsName(message, DNS_HEADER_SIZE, requirePrintableAscii = true)
        if (parsedName.name.isEmpty()) throw IOException("DNS response question name is empty")
        val offset = parsedName.nextOffset
        if (offset + DNS_QUESTION_TAIL_SIZE > message.size) {
            throw IOException("DNS response question is incomplete")
        }

        val type = u16(message, offset)
        val recordClass = u16(message, offset + 2)
        if (recordClass != CLASS_IN) throw IOException("DNS response question class is unsupported")

        return ParsedResponseQuestion(
            question = DnsQuestionView(
                id = u16(message, 0),
                name = parsedName.name,
                type = type,
                recursionDesired = (u16(message, 2) and FLAG_RD) != 0
            ),
            endOffset = offset + DNS_QUESTION_TAIL_SIZE
        )
    }

    private fun skipResourceRecord(message: ByteArray, start: Int): Int {
        val owner = readDnsName(message, start, requirePrintableAscii = false)
        val fixedFieldsEnd = owner.nextOffset + RESOURCE_RECORD_FIXED_SIZE
        if (fixedFieldsEnd > message.size) {
            throw IOException("DNS resource record fixed fields are truncated")
        }

        val dataLength = u16(message, owner.nextOffset + 8)
        val dataEnd = fixedFieldsEnd + dataLength
        if (dataEnd > message.size) {
            throw IOException("DNS resource record data is truncated")
        }
        return dataEnd
    }

    /**
     * Parses a DNS wire-format name, validating compression pointers and bounding pointer walks.
     * Resource-record owner names are structurally checked without assuming ASCII labels.
     */
    private fun readDnsName(
        message: ByteArray,
        start: Int,
        requirePrintableAscii: Boolean
    ): ParsedDnsName {
        if (start !in message.indices) throw IOException("DNS name starts outside the message")

        var offset = start
        var nextOffset = -1
        var expandedLength = 1
        val visitedOffsets = HashSet<Int>()
        val labels = ArrayList<String>()

        while (true) {
            if (offset !in message.indices) throw IOException("DNS name is truncated")
            if (!visitedOffsets.add(offset)) throw IOException("DNS compression pointer loop detected")

            val length = message[offset].toInt() and 0xff
            when {
                (length and COMPRESSION_MASK) == COMPRESSION_MASK -> {
                    if (offset + 1 >= message.size) {
                        throw IOException("DNS compression pointer is truncated")
                    }
                    val pointer = ((length and COMPRESSION_POINTER_MASK) shl 8) or
                        (message[offset + 1].toInt() and 0xff)
                    if (pointer >= offset || pointer >= message.size) {
                        throw IOException("DNS compression pointer is invalid")
                    }
                    if (nextOffset == -1) nextOffset = offset + 2
                    offset = pointer
                }
                (length and COMPRESSION_MASK) != 0 -> {
                    throw IOException("DNS label uses an unsupported label encoding")
                }
                else -> {
                    offset++
                    if (length == 0) {
                        return ParsedDnsName(
                            name = labels.joinToString("."),
                            nextOffset = if (nextOffset == -1) offset else nextOffset
                        )
                    }
                    if (length > MAX_LABEL_LENGTH || offset + length > message.size) {
                        throw IOException("DNS label is invalid or truncated")
                    }

                    val labelBytes = message.copyOfRange(offset, offset + length)
                    if (requirePrintableAscii && labelBytes.any {
                            (it.toInt() and 0xff) !in 0x21..0x7e
                        }
                    ) {
                        throw IOException("DNS response question contains unsupported characters")
                    }
                    labels += labelBytes.toString(Charsets.US_ASCII).lowercase()
                    expandedLength += length + 1
                    if (expandedLength > MAX_DNS_NAME_LENGTH) {
                        throw IOException("DNS name exceeds the wire-format limit")
                    }
                    offset += length
                }
            }
        }
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private data class ParsedDnsName(val name: String, val nextOffset: Int)
    private data class ParsedResponseQuestion(val question: DnsQuestionView, val endOffset: Int)

    companion object {
        private const val DEFAULT_TIMEOUT_MILLIS = 2500
        private const val MAX_TIMEOUT_MILLIS = 60_000
        private const val MAX_UDP_DNS_PAYLOAD = 65_507
        private const val DNS_HEADER_SIZE = 12
        private const val DNS_QUESTION_TAIL_SIZE = 4
        private const val RESOURCE_RECORD_FIXED_SIZE = 10
        private const val MAX_LABEL_LENGTH = 63
        private const val MAX_DNS_NAME_LENGTH = 255
        private const val CLASS_IN = 1
        private const val FLAG_QR = 0x8000
        private const val FLAG_TC = 0x0200
        private const val FLAG_RD = 0x0100
        private const val OPCODE_MASK = 0x7800
        private const val COMPRESSION_MASK = 0xc0
        private const val COMPRESSION_POINTER_MASK = 0x3f
    }
}
