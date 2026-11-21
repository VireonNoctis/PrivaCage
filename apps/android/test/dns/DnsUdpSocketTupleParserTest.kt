package org.privacage.android

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class DnsUdpSocketTupleParserTest {
    @Test
    fun parsesIpv4DnsTuple() {
        val tuple = DnsUdpSocketTupleParser.parse(ipv4Packet())

        assertNotNull(tuple)
        assertEquals("10.0.0.2", tuple!!.sourceAddress.hostAddress)
        assertEquals(53000, tuple.sourcePort)
        assertEquals("10.0.0.1", tuple.destinationAddress.hostAddress)
        assertEquals(53, tuple.destinationPort)
    }

    @Test
    fun parsesIpv6DnsTuple() {
        val tuple = DnsUdpSocketTupleParser.parse(ipv6Packet())

        assertNotNull(tuple)
        assertEquals("fd00:0:0:0:0:0:0:2", tuple!!.sourceAddress.hostAddress)
        assertEquals(53001, tuple.sourcePort)
        assertEquals("fd00:0:0:0:0:0:0:1", tuple.destinationAddress.hostAddress)
        assertEquals(53, tuple.destinationPort)
    }

    @Test
    fun rejectsUnsupportedIpVersion() {
        val packet = ipv4Packet()
        packet[0] = 0x70
        assertNull(DnsUdpSocketTupleParser.parse(packet))
    }

    @Test
    fun rejectsNonDnsDestinationPort() {
        val packet = ipv4Packet()
        putU16(packet, 22, 5353)
        assertNull(DnsUdpSocketTupleParser.parse(packet))
    }

    @Test
    fun rejectsIpv4Fragmentation() {
        val packet = ipv4Packet()
        putU16(packet, 6, 0x2000)
        assertNull(DnsUdpSocketTupleParser.parse(packet))
    }

    @Test
    fun rejectsIpv6ExtensionHeadersInsteadOfMisreadingTheirBytesAsUdp() {
        val packet = ipv6Packet()
        packet[6] = 0
        assertNull(DnsUdpSocketTupleParser.parse(packet))
    }

    @Test
    fun rejectsLengthMismatchAndTruncatedPacket() {
        val packet = ipv4Packet()
        putU16(packet, 2, packet.size - 1)
        assertNull(DnsUdpSocketTupleParser.parse(packet))
        assertNull(DnsUdpSocketTupleParser.parse(byteArrayOf(0x45, 0x00)))
    }

    @Test
    fun rejectsZeroIpv6UdpChecksum() {
        val packet = ipv6Packet()
        packet[46] = 0
        packet[47] = 0
        assertNull(DnsUdpSocketTupleParser.parse(packet))
    }

    private fun ipv4Packet(): ByteArray {
        val packet = ByteArray(40)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17
        InetAddress.getByName("10.0.0.2").address.copyInto(packet, 12)
        InetAddress.getByName("10.0.0.1").address.copyInto(packet, 16)
        putU16(packet, 20, 53000)
        putU16(packet, 22, 53)
        putU16(packet, 24, 20)
        packet[26] = 0
        packet[27] = 1
        return packet
    }

    private fun ipv6Packet(): ByteArray {
        val packet = ByteArray(60)
        packet[0] = 0x60
        putU16(packet, 4, packet.size - 40)
        packet[6] = 17
        packet[7] = 64
        InetAddress.getByName("fd00::2").address.copyInto(packet, 8)
        InetAddress.getByName("fd00::1").address.copyInto(packet, 24)
        putU16(packet, 40, 53001)
        putU16(packet, 42, 53)
        putU16(packet, 44, packet.size - 40)
        packet[46] = 0
        packet[47] = 1
        return packet
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }
}
