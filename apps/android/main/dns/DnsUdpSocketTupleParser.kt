package org.privacage.android

import java.net.InetAddress

/**
 * Extracts the UDP 5-tuple endpoints needed for best-effort Android socket-owner lookup.
 *
 * This parser intentionally accepts only unfragmented IPv4 packets and IPv6 packets with a
 * directly encapsulated UDP header. IPv6 extension headers and jumbograms are not supported,
 * matching the DNS packet codec's current supported envelope. A null result means attribution
 * must remain unavailable; callers must not guess a package from the hostname or foreground UI.
 */
internal data class DnsUdpSocketTuple(
    val sourceAddress: InetAddress,
    val sourcePort: Int,
    val destinationAddress: InetAddress,
    val destinationPort: Int
)

internal object DnsUdpSocketTupleParser {
    private const val IPV4_MIN_HEADER_SIZE = 20
    private const val IPV6_HEADER_SIZE = 40
    private const val UDP_HEADER_SIZE = 8
    private const val UDP_PROTOCOL = 17
    private const val DNS_PORT = 53

    fun parse(packet: ByteArray): DnsUdpSocketTuple? {
        if (packet.isEmpty()) return null
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> parseIpv4(packet)
            6 -> parseIpv6(packet)
            else -> null
        }
    }

    private fun parseIpv4(packet: ByteArray): DnsUdpSocketTuple? {
        if (packet.size < IPV4_MIN_HEADER_SIZE + UDP_HEADER_SIZE) return null

        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength < IPV4_MIN_HEADER_SIZE || packet.size < headerLength + UDP_HEADER_SIZE) return null

        val totalLength = unsignedShort(packet, 2)
        if (totalLength != packet.size || totalLength < headerLength + UDP_HEADER_SIZE) return null
        if ((packet[9].toInt() and 0xff) != UDP_PROTOCOL) return null

        val flagsAndFragmentOffset = unsignedShort(packet, 6)
        // Reject both first and later fragments so no partial packet is mistaken for a full tuple.
        if ((flagsAndFragmentOffset and 0x3fff) != 0) return null

        val udpLength = unsignedShort(packet, headerLength + 4)
        if (udpLength < UDP_HEADER_SIZE || udpLength != totalLength - headerLength) return null

        val sourcePort = unsignedShort(packet, headerLength)
        val destinationPort = unsignedShort(packet, headerLength + 2)
        if (destinationPort != DNS_PORT) return null

        return DnsUdpSocketTuple(
            sourceAddress = InetAddress.getByAddress(packet.copyOfRange(12, 16)),
            sourcePort = sourcePort,
            destinationAddress = InetAddress.getByAddress(packet.copyOfRange(16, 20)),
            destinationPort = destinationPort
        )
    }

    private fun parseIpv6(packet: ByteArray): DnsUdpSocketTuple? {
        if (packet.size < IPV6_HEADER_SIZE + UDP_HEADER_SIZE) return null

        val payloadLength = unsignedShort(packet, 4)
        if (payloadLength == 0 || payloadLength + IPV6_HEADER_SIZE != packet.size) return null
        // Extension headers are deliberately unsupported. Do not guess where UDP begins.
        if ((packet[6].toInt() and 0xff) != UDP_PROTOCOL) return null
        if (payloadLength < UDP_HEADER_SIZE) return null

        val udpOffset = IPV6_HEADER_SIZE
        val udpLength = unsignedShort(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_SIZE || udpLength != payloadLength) return null
        if (unsignedShort(packet, udpOffset + 6) == 0) return null

        val sourcePort = unsignedShort(packet, udpOffset)
        val destinationPort = unsignedShort(packet, udpOffset + 2)
        if (destinationPort != DNS_PORT) return null

        return DnsUdpSocketTuple(
            sourceAddress = InetAddress.getByAddress(packet.copyOfRange(8, 24)),
            sourcePort = sourcePort,
            destinationAddress = InetAddress.getByAddress(packet.copyOfRange(24, 40)),
            destinationPort = destinationPort
        )
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
