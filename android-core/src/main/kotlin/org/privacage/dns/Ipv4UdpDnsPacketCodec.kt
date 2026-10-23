package org.privacage.dns

/**
 * Decodes IPv4 UDP packets addressed to DNS port 53 and builds valid IPv4 UDP replies.
 *
 * Packet codec only: it does not read a TUN descriptor, forward allowed queries, create
 * an Android VPN, or support IPv6, fragmented IPv4, TCP DNS, or encrypted DNS.
 */
object Ipv4UdpDnsPacketCodec {

    fun decode(packet: ByteArray): Ipv4UdpDnsDecode {
        if (packet.size < IPV4_MIN_HEADER_SIZE) {
            return Ipv4UdpDnsDecode.Malformed("IPv4 header is truncated")
        }
        if (((packet[0].toInt() ushr 4) and 0x0f) != IPV4_VERSION) {
            return Ipv4UdpDnsDecode.Malformed("Packet is not IPv4")
        }

        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength < IPV4_MIN_HEADER_SIZE || headerLength > packet.size) {
            return Ipv4UdpDnsDecode.Malformed("Invalid IPv4 header length")
        }

        val totalLength = u16(packet, 2)
        if (totalLength != packet.size || totalLength < headerLength + UDP_HEADER_SIZE) {
            return Ipv4UdpDnsDecode.Malformed("IPv4 total length is invalid")
        }
        if (checksum(packet, 0, headerLength) != 0) {
            return Ipv4UdpDnsDecode.Malformed("IPv4 header checksum is invalid")
        }
        val fragmentField = u16(packet, 6)
        if ((fragmentField and RESERVED_IPV4_FLAG) != 0) {
            return Ipv4UdpDnsDecode.Malformed("IPv4 reserved flag is set")
        }
        if ((packet[9].toInt() and 0xff) != PROTOCOL_UDP) {
            return Ipv4UdpDnsDecode.NotDns("IPv4 packet is not UDP")
        }
        if ((fragmentField and FRAGMENT_MASK) != 0) {
            return Ipv4UdpDnsDecode.Malformed("Fragmented IPv4 packets are not supported")
        }

        val udpOffset = headerLength
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_SIZE || udpLength != totalLength - headerLength) {
            return Ipv4UdpDnsDecode.Malformed("UDP length does not match the IPv4 payload")
        }

        val sourcePort = u16(packet, udpOffset)
        val destinationPort = u16(packet, udpOffset + 2)
        if (destinationPort != DNS_PORT) {
            return Ipv4UdpDnsDecode.NotDns("UDP destination port is not DNS")
        }

        if (u16(packet, udpOffset + 6) != 0 && udpChecksum(packet, udpOffset, udpLength) != 0) {
            return Ipv4UdpDnsDecode.Malformed("UDP checksum is invalid")
        }

        return Ipv4UdpDnsDecode.Query(
            originalPacket = packet.copyOf(),
            ipHeaderLength = headerLength,
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsPayload = packet.copyOfRange(udpOffset + UDP_HEADER_SIZE, totalLength)
        )
    }

    /** Builds a reply with reversed IP/UDP endpoints and recalculated checksums. */
    fun buildUdpResponse(query: Ipv4UdpDnsDecode.Query, dnsPayload: ByteArray): ByteArray {
        // Re-decode the packet instead of trusting mutable arrays or fields on the public result.
        val validated = decode(query.originalPacket) as? Ipv4UdpDnsDecode.Query
            ?: throw IllegalArgumentException("Response source is not a valid IPv4 UDP DNS query")

        val headerLength = validated.ipHeaderLength
        val udpLength = UDP_HEADER_SIZE + dnsPayload.size
        val totalLength = headerLength + udpLength
        require(totalLength <= IPV4_MAX_PACKET_SIZE) { "IPv4 response exceeds maximum packet size" }

        val response = ByteArray(totalLength)
        validated.originalPacket.copyInto(response, endIndex = headerLength)
        putU16(response, 2, totalLength)

        validated.destinationAddress.copyInto(response, destinationOffset = 12)
        validated.sourceAddress.copyInto(response, destinationOffset = 16)
        putU16(response, 6, u16(validated.originalPacket, 6) and DONT_FRAGMENT_FLAG)
        response[8] = DEFAULT_TTL.toByte()
        response[10] = 0
        response[11] = 0
        putU16(response, 10, checksum(response, 0, headerLength))

        val udpOffset = headerLength
        putU16(response, udpOffset, validated.destinationPort)
        putU16(response, udpOffset + 2, validated.sourcePort)
        putU16(response, udpOffset + 4, udpLength)
        putU16(response, udpOffset + 6, 0)
        dnsPayload.copyInto(response, destinationOffset = udpOffset + UDP_HEADER_SIZE)

        val calculatedUdpChecksum = udpChecksum(response, udpOffset, udpLength)
        putU16(response, udpOffset + 6, if (calculatedUdpChecksum == 0) 0xffff else calculatedUdpChecksum)
        return response
    }

    /**
     * Creates a DNS REFUSED response for a valid supported query. The question is preserved;
     * additional records, including EDNS OPT, are omitted. Returns null for invalid queries.
     */
    fun buildRefusedDnsResponse(query: ByteArray): ByteArray? {
        if (DnsPolicyEngine(emptySet()).evaluate(query) is DnsDecision.Malformed) return null

        var questionEnd = DNS_HEADER_SIZE
        while (true) {
            if (questionEnd >= query.size) return null
            val labelLength = query[questionEnd++].toInt() and 0xff
            if (labelLength == 0) break
            if ((labelLength and 0xc0) != 0 || labelLength > 63) return null
            if (questionEnd + labelLength > query.size) return null
            questionEnd += labelLength
        }
        questionEnd += DNS_QUESTION_TAIL_SIZE
        if (questionEnd > query.size) return null

        val response = query.copyOfRange(0, questionEnd)
        val queryFlags = u16(query, 2)
        putU16(response, 2, FLAG_QR or (queryFlags and (FLAG_RD or FLAG_CD)) or RCODE_REFUSED)
        putU16(response, 4, 1)
        putU16(response, 6, 0)
        putU16(response, 8, 0)
        putU16(response, 10, 0)
        return response
    }

    private fun udpChecksum(packet: ByteArray, udpOffset: Int, udpLength: Int): Int {
        var sum = 0L
        for (index in 12 until 20 step 2) sum += u16(packet, index).toLong()
        sum += PROTOCOL_UDP.toLong()
        sum += udpLength.toLong()
        sum += checksumSum(packet, udpOffset, udpLength)
        return foldChecksum(sum)
    }

    private fun checksum(bytes: ByteArray, offset: Int, length: Int): Int =
        foldChecksum(checksumSum(bytes, offset, length))

    private fun checksumSum(bytes: ByteArray, offset: Int, length: Int): Long {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += u16(bytes, index).toLong()
            index += 2
        }
        if (index < end) sum += ((bytes[index].toInt() and 0xff) shl 8).toLong()
        return sum
    }

    private fun foldChecksum(initial: Long): Int {
        var sum = initial
        while ((sum ushr 16) != 0L) sum = (sum and 0xffffL) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private const val IPV4_VERSION = 4
    private const val IPV4_MIN_HEADER_SIZE = 20
    private const val IPV4_MAX_PACKET_SIZE = 65_535
    private const val UDP_HEADER_SIZE = 8
    private const val DNS_HEADER_SIZE = 12
    private const val DNS_QUESTION_TAIL_SIZE = 4
    private const val DNS_PORT = 53
    private const val PROTOCOL_UDP = 17
    private const val RESERVED_IPV4_FLAG = 0x8000
    private const val FRAGMENT_MASK = 0x3fff
    private const val DONT_FRAGMENT_FLAG = 0x4000
    private const val DEFAULT_TTL = 64
    private const val FLAG_QR = 0x8000
    private const val FLAG_RD = 0x0100
    private const val FLAG_CD = 0x0010
    private const val RCODE_REFUSED = 0x0005
}

sealed interface Ipv4UdpDnsDecode {
    data class Query(
        val originalPacket: ByteArray,
        val ipHeaderLength: Int,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val dnsPayload: ByteArray
    ) : Ipv4UdpDnsDecode

    data class NotDns(val reason: String) : Ipv4UdpDnsDecode
    data class Malformed(val reason: String) : Ipv4UdpDnsDecode
}
