package org.privacage.dns

/**
 * Codec for IPv6 packets carrying a directly encapsulated UDP DNS query.
 *
 * This intentionally rejects IPv6 extension headers, fragments, jumbograms, and DNS-over-TCP.
 * It is designed for the DNS-only route installed by PrivaCage, not a general IPv6 stack.
 * Replies are bounded to the app's 1500-byte TUN MTU and are never silently truncated.
 */
object Ipv6UdpDnsPacketCodec {
    private const val IPV6_HEADER_SIZE = 40
    private const val UDP_HEADER_SIZE = 8
    private const val UDP_PROTOCOL = 17
    private const val DNS_PORT = 53
    private const val IPV6_VERSION = 6
    private const val TUN_MTU = 1500
    private const val MIN_DNS_MESSAGE_SIZE = 12

    fun decode(packet: ByteArray): Ipv6UdpDnsDecode {
        if (packet.size < IPV6_HEADER_SIZE) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 header is truncated")
        }
        if (((packet[0].toInt() ushr 4) and 0x0f) != IPV6_VERSION) {
            return Ipv6UdpDnsDecode.Malformed("Packet is not IPv6")
        }

        val payloadLength = u16(packet, 4)
        if (payloadLength == 0) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 jumbograms are not supported")
        }
        if (payloadLength + IPV6_HEADER_SIZE != packet.size) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 payload length does not match the packet")
        }

        val nextHeader = packet[6].toInt() and 0xff
        if (nextHeader != UDP_PROTOCOL) {
            return if (nextHeader in IPV6_EXTENSION_HEADERS) {
                Ipv6UdpDnsDecode.Malformed("IPv6 extension headers are not supported")
            } else {
                Ipv6UdpDnsDecode.NotDns("IPv6 packet is not directly encapsulated UDP")
            }
        }

        if (payloadLength < UDP_HEADER_SIZE) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 UDP payload is shorter than its header")
        }
        val udpOffset = IPV6_HEADER_SIZE
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_SIZE || udpLength != payloadLength) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 UDP length does not match the packet")
        }

        val sourcePort = u16(packet, udpOffset)
        val destinationPort = u16(packet, udpOffset + 2)
        if (u16(packet, udpOffset + 6) == 0) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 UDP checksum must not be zero")
        }
        if (udpChecksum(packet, udpOffset, udpLength) != 0) {
            return Ipv6UdpDnsDecode.Malformed("IPv6 UDP checksum is invalid")
        }
        if (destinationPort != DNS_PORT) {
            return Ipv6UdpDnsDecode.NotDns("UDP destination port is not DNS")
        }

        val dnsPayload = packet.copyOfRange(udpOffset + UDP_HEADER_SIZE, packet.size)
        if (dnsPayload.size < MIN_DNS_MESSAGE_SIZE) {
            return Ipv6UdpDnsDecode.Malformed("DNS message is shorter than its header")
        }
        return Ipv6UdpDnsDecode.Query(
            originalPacket = packet.copyOf(),
            sourceAddress = packet.copyOfRange(8, 24),
            destinationAddress = packet.copyOfRange(24, 40),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsPayload = dnsPayload
        )
    }

    /** Revalidates the original packet before constructing a response for a caller-held query. */
    fun buildUdpResponse(query: Ipv6UdpDnsDecode.Query, dnsPayload: ByteArray): ByteArray {
        val validated = decode(query.originalPacket) as? Ipv6UdpDnsDecode.Query
            ?: throw IllegalArgumentException("Response source is not a valid IPv6 UDP DNS query")
        return buildUdpResponseForValidatedQuery(validated, dnsPayload)
    }

    /** Fast path for a query decoded immediately before this call by the packet processor. */
    internal fun buildUdpResponseForValidatedQuery(
        query: Ipv6UdpDnsDecode.Query,
        dnsPayload: ByteArray
    ): ByteArray {
        require(dnsPayload.size >= MIN_DNS_MESSAGE_SIZE) { "DNS response is shorter than its header" }
        val udpLength = UDP_HEADER_SIZE + dnsPayload.size
        val totalLength = IPV6_HEADER_SIZE + udpLength
        require(totalLength <= TUN_MTU) {
            "IPv6 DNS response exceeds the " + TUN_MTU + "-byte TUN MTU; response was not truncated"
        }
        require(udpLength <= 65_535) { "IPv6 UDP response exceeds the maximum UDP payload length" }

        val response = ByteArray(totalLength)
        response[0] = 0x60
        response[1] = 0
        putU16(response, 4, udpLength)
        response[6] = UDP_PROTOCOL.toByte()
        response[7] = 64

        query.destinationAddress.copyInto(response, destinationOffset = 8)
        query.sourceAddress.copyInto(response, destinationOffset = 24)

        val udpOffset = IPV6_HEADER_SIZE
        putU16(response, udpOffset, query.destinationPort)
        putU16(response, udpOffset + 2, query.sourcePort)
        putU16(response, udpOffset + 4, udpLength)
        putU16(response, udpOffset + 6, 0)
        dnsPayload.copyInto(response, destinationOffset = udpOffset + UDP_HEADER_SIZE)

        val calculated = udpChecksum(response, udpOffset, udpLength)
        putU16(response, udpOffset + 6, if (calculated == 0) 0xffff else calculated)
        return response
    }

    private fun udpChecksum(packet: ByteArray, udpOffset: Int, udpLength: Int): Int {
        var sum = 0L
        var index = 8
        while (index < 40) {
            sum += u16(packet, index).toLong()
            index += 2
        }
        // IPv6 pseudo-header: 32-bit upper-layer length, three zero bytes, next-header value.
        sum += (udpLength ushr 16).toLong()
        sum += (udpLength and 0xffff).toLong()
        sum += UDP_PROTOCOL.toLong()
        sum += checksumSum(packet, udpOffset, udpLength)
        return foldChecksum(sum)
    }

    private fun checksumSum(bytes: ByteArray, offset: Int, length: Int): Long {
        var sum = 0L
        val end = offset + length
        var index = offset
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

    private val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 50, 51, 60, 135, 139, 140)
}

sealed interface Ipv6UdpDnsDecode {
    data class Query(
        val originalPacket: ByteArray,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val dnsPayload: ByteArray
    ) : Ipv6UdpDnsDecode

    data class NotDns(val reason: String) : Ipv6UdpDnsDecode
    data class Malformed(val reason: String) : Ipv6UdpDnsDecode
}
