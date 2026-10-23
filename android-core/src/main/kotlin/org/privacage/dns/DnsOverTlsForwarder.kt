package org.privacage.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** RFC 7858 DNS-over-TLS with platform trust, mandatory hostname verification and no plaintext fallback. */
class DnsOverTlsForwarder(
    private val resolverAddress: InetAddress,
    tlsHostname: String,
    private val socketProtector: TcpSocketProtector,
    private val policyEngine: DnsPolicyEngine,
    private val timeoutMillis: Int = 3_000,
    private val port: Int = 853,
    private val socketFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
) : DnsUpstreamTransport {
    private val tlsHostname = validateHostname(tlsHostname)
    init {
        require(timeoutMillis in 1..60_000) { "DNS timeout must be between 1 and 60000 ms" }
        require(port in 1..65535) { "DNS-over-TLS port must be between 1 and 65535" }
    }

    override fun forward(query: ByteArray): ByteArray {
        if (query.size !in 12..65535) throw IOException("DNS query length is invalid")
        val expected = when (val decision = policyEngine.evaluate(query)) {
            is DnsDecision.Allow -> decision.question
            is DnsDecision.Block -> throw IOException("Refusing to forward blocked DNS query matching rule: ${decision.matchedRule}")
            is DnsDecision.Malformed -> throw IOException("Refusing to forward malformed DNS query: ${decision.reason}")
        }
        val raw = Socket()
        try {
            if (!socketProtector.protect(raw)) throw IOException("Failed to protect DNS-over-TLS socket from VPN routing")
            raw.connect(InetSocketAddress(resolverAddress, port), timeoutMillis)
            raw.soTimeout = timeoutMillis
            val tls = socketFactory.createSocket(raw, tlsHostname, port, true) as SSLSocket
            tls.use { socket ->
                socket.soTimeout = timeoutMillis
                val parameters: SSLParameters = socket.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                socket.sslParameters = parameters
                val protocols = socket.enabledProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
                if (protocols.isEmpty()) throw IOException("No supported TLS 1.2+ protocol is available")
                socket.enabledProtocols = protocols
                socket.startHandshake()
                val output = DataOutputStream(socket.outputStream)
                output.writeShort(query.size); output.write(query); output.flush()
                val input = DataInputStream(socket.inputStream)
                val length = input.readUnsignedShort()
                if (length !in 12..65535) throw IOException("DNS-over-TLS response length is invalid")
                val response = ByteArray(length)
                input.readFully(response)
                validateResponse(query, expected, response)
                return response
            }
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("DNS-over-TLS connection failed", exception)
        } finally {
            try { raw.close() } catch (_: IOException) { }
        }
    }

    private fun validateResponse(query: ByteArray, expected: DnsQuestionView, response: ByteArray) {
        if (u16(response, 0) != u16(query, 0)) throw IOException("DNS-over-TLS response ID does not match query")
        val flags = u16(response, 2)
        if ((flags and 0x8000) == 0) throw IOException("Upstream TLS packet is not a DNS response")
        if ((flags and 0x7800) != 0) throw IOException("Upstream TLS response uses an unsupported opcode")
        if ((flags and 0x0200) != 0) throw IOException("DNS-over-TLS response is unexpectedly truncated")
        if (u16(response, 4) != 1) throw IOException("Upstream TLS response must echo exactly one question")
        val q = readQuestion(response)
        if (q.name != expected.name || q.type != expected.type || q.recursionDesired != expected.recursionDesired) {
            throw IOException("DNS-over-TLS response question does not match query")
        }
        var offset = q.endOffset
        repeat(u16(response, 6) + u16(response, 8) + u16(response, 10)) { offset = skipRecord(response, offset) }
        if (offset != response.size) throw IOException("DNS-over-TLS response contains trailing bytes")
    }

    private fun readQuestion(message: ByteArray): ParsedQuestion {
        var offset = 12
        val labels = ArrayList<String>()
        var expanded = 1
        while (true) {
            if (offset !in message.indices) throw IOException("DNS response question is truncated")
            val length = message[offset++].toInt() and 0xff
            if (length == 0) break
            if ((length and 0xc0) != 0 || length > 63 || offset + length > message.size) throw IOException("DNS response question label is invalid")
            val bytes = message.copyOfRange(offset, offset + length)
            if (bytes.any { (it.toInt() and 0xff) !in 0x21..0x7e }) throw IOException("DNS response question contains unsupported characters")
            labels += bytes.toString(Charsets.US_ASCII).lowercase()
            expanded += length + 1
            if (expanded > 255) throw IOException("DNS response question name is too long")
            offset += length
        }
        if (labels.isEmpty() || offset + 4 > message.size) throw IOException("DNS response question is incomplete")
        if (u16(message, offset + 2) != 1) throw IOException("DNS response question class is unsupported")
        return ParsedQuestion(labels.joinToString("."), u16(message, offset), (u16(message, 2) and 0x0100) != 0, offset + 4)
    }

    private fun skipRecord(message: ByteArray, start: Int): Int {
        var offset = start
        var fixedStart = -1
        var hops = 0
        while (true) {
            if (offset !in message.indices) throw IOException("DNS resource-record name is truncated")
            if (++hops > 255) throw IOException("DNS resource-record name is malformed")
            val length = message[offset].toInt() and 0xff
            when {
                (length and 0xc0) == 0xc0 -> {
                    if (offset + 1 >= message.size) throw IOException("DNS compression pointer is truncated")
                    val pointer = ((length and 0x3f) shl 8) or (message[offset + 1].toInt() and 0xff)
                    if (pointer >= offset || pointer >= message.size) throw IOException("DNS compression pointer is invalid")
                    fixedStart = offset + 2
                    break
                }
                (length and 0xc0) != 0 -> throw IOException("DNS resource-record name encoding is unsupported")
                length == 0 -> { fixedStart = offset + 1; break }
                length > 63 || offset + 1 + length > message.size -> throw IOException("DNS resource-record label is invalid")
                else -> offset += 1 + length
            }
        }
        if (fixedStart + 10 > message.size) throw IOException("DNS resource-record fixed fields are truncated")
        val end = fixedStart + 10 + u16(message, fixedStart + 8)
        if (end > message.size) throw IOException("DNS resource-record data is truncated")
        return end
    }

    private fun u16(bytes: ByteArray, offset: Int) = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    private data class ParsedQuestion(val name: String, val type: Int, val recursionDesired: Boolean, val endOffset: Int)

    companion object {
        fun validateHostname(value: String): String {
            val trimmed = value.trim().trimEnd('.')
            require(trimmed.isNotEmpty()) { "DNS-over-TLS certificate hostname is required" }
            val ascii = try { IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).lowercase() }
            catch (exception: IllegalArgumentException) { throw IllegalArgumentException("DNS-over-TLS hostname is not a valid DNS name", exception) }
            require(ascii.length <= 253 && ascii.contains('.')) { "DNS-over-TLS hostname must be a fully qualified DNS name" }
            require(ascii.split('.').all { label ->
                label.isNotEmpty() && label.length <= 63 && label.first() != '-' && label.last() != '-' &&
                    label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
            }) { "DNS-over-TLS hostname contains an invalid label" }
            require(ascii != "localhost") { "DNS-over-TLS hostname must not be localhost" }
            return ascii
        }
    }
}
