package org.privacage.dns

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertArrayEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class Ipv6UdpDnsPacketCodecTest {
    @Test
    fun decodesIpv6DnsAndBuildsReverseReplyWithValidChecksum() {
        val packet = makeQueryPacket("tracker.example")
        val query = assertIs<Ipv6UdpDnsDecode.Query>(Ipv6UdpDnsPacketCodec.decode(packet))
        assertEquals("tracker.example", assertIs<DnsDecision.Allow>(DnsPolicyEngine(emptySet()).evaluate(query.dnsPayload)).question.name)

        val refused = Ipv4UdpDnsPacketCodec.buildRefusedDnsResponse(query.dnsPayload)!!
        val reply = Ipv6UdpDnsPacketCodec.buildUdpResponse(query, refused)
        assertEquals(6, (reply[0].toInt() ushr 4) and 0x0f)
        assertEquals(17, reply[6].toInt() and 0xff)
        assertArrayEquals(query.destinationAddress, reply.copyOfRange(8, 24))
        assertArrayEquals(query.sourceAddress, reply.copyOfRange(24, 40))
        assertEquals(53, u16(reply, 40))
        assertEquals(53000, u16(reply, 42))
        assertEquals(0, udpChecksum(reply, 40, u16(reply, 44)))
    }

    @Test
    fun policyProcessorReturnsIpv6RefusedReplyForBlockedDomain() {
        val packet = makeQueryPacket("tracker.example")
        val result = DnsPacketProcessor(DnsPolicyEngine(setOf("tracker.example")))
            .processIpv6Packet(packet)
        val blocked = assertIs<DnsPacketProcessingResult.BlockedIpv6>(result)
        assertEquals("tracker.example", blocked.domain)
        assertEquals("tracker.example", blocked.matchedRule)
        val reply = blocked.responsePacket
        assertEquals(6, (reply[0].toInt() ushr 4) and 0x0f)
        assertEquals(0, udpChecksum(reply, 40, u16(reply, 44)))
    }

    @Test
    fun rejectsInvalidUdpChecksum() {
        val packet = makeQueryPacket("example.com")
        packet[packet.lastIndex] = (packet.last().toInt() xor 0x01).toByte()
        assertIs<Ipv6UdpDnsDecode.Malformed>(Ipv6UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsZeroUdpChecksum() {
        val packet = makeQueryPacket("example.com")
        packet[46] = 0
        packet[47] = 0
        assertIs<Ipv6UdpDnsDecode.Malformed>(Ipv6UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsIpv6ExtensionHeadersInsteadOfMisparsingThemAsUdp() {
        val packet = makeQueryPacket("example.com")
        packet[6] = 0
        assertIs<Ipv6UdpDnsDecode.Malformed>(Ipv6UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsMismatchedDeclaredPayloadLength() {
        val packet = makeQueryPacket("example.com")
        packet[5] = (packet[5].toInt() + 1).toByte()
        assertIs<Ipv6UdpDnsDecode.Malformed>(Ipv6UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun refusesResponsesThatWouldExceedTheConfiguredTunMtu() {
        val query = assertIs<Ipv6UdpDnsDecode.Query>(Ipv6UdpDnsPacketCodec.decode(makeQueryPacket("example.com")))
        val oversized = ByteArray(1460)
        assertTrue(runCatching { Ipv6UdpDnsPacketCodec.buildUdpResponse(query, oversized) }.isFailure)
    }

    private fun makeQueryPacket(domain: String): ByteArray {
        val dns = ByteArrayOutputStream()
        dns.write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        domain.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            dns.write(bytes.size)
            dns.write(bytes)
        }
        dns.write(byteArrayOf(0, 0, 1, 0, 1))
        val dnsPayload = dns.toByteArray()
        val udpLength = 8 + dnsPayload.size
        val packet = ByteArray(40 + udpLength)
        packet[0] = 0x60
        packet[4] = (udpLength ushr 8).toByte()
        packet[5] = udpLength.toByte()
        packet[6] = 17
        packet[7] = 64
        InetAddress.getByName("2001:db8::1").address.copyInto(packet, 8)
        InetAddress.getByName("fd42:1111:2222::2").address.copyInto(packet, 24)
        putU16(packet, 40, 53000)
        putU16(packet, 42, 53)
        putU16(packet, 44, udpLength)
        dnsPayload.copyInto(packet, 48)
        putU16(packet, 46, udpChecksum(packet, 40, udpLength).let { if (it == 0) 0xffff else it })
        return packet
    }

    private fun udpChecksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = 8
        while (index < 40) {
            sum += u16(packet, index).toLong()
            index += 2
        }
        sum += length.toLong()
        sum += 17L
        var pos = offset
        val end = offset + length
        while (pos + 1 < end) {
            sum += u16(packet, pos).toLong()
            pos += 2
        }
        if (pos < end) sum += ((packet[pos].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffffL) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }
}
