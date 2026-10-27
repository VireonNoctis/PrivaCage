package org.privacage.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsPacketProcessorTest {

    @Test
    fun blockedQueryProducesActualRefusedIpv4UdpResponse() {
        val result = DnsPacketProcessor(DnsPolicyEngine(setOf("tracker.example")))
            .processIpv4Packet(ipv4UdpPacket(dnsQuery("tracker.example")))

        val blocked = assertIs<DnsPacketProcessingResult.Blocked>(result)
        assertEquals("tracker.example", blocked.domain)
        assertEquals("tracker.example", blocked.matchedRule)
        assertEquals(53, u16(blocked.responsePacket, 20))
        assertEquals(53000, u16(blocked.responsePacket, 22))
        assertEquals(0x8105, u16(blocked.responsePacket, 30))
    }

    @Test
    fun allowedQueryIsExplicitlyReturnedForForwarding() {
        val result = DnsPacketProcessor(DnsPolicyEngine(setOf("tracker.example")))
            .processIpv4Packet(ipv4UdpPacket(dnsQuery("news.example.org")))

        val forward = assertIs<DnsPacketProcessingResult.ForwardRequired>(result)
        assertEquals("news.example.org", forward.question.name)
        assertEquals(53, forward.query.destinationPort)
    }

    @Test
    fun malformedDnsPayloadIsDroppedRatherThanForwarded() {
        val result = DnsPacketProcessor(DnsPolicyEngine(emptySet()))
            .processIpv4Packet(ipv4UdpPacket(byteArrayOf(1, 2, 3)))

        assertIs<DnsPacketProcessingResult.Drop>(result)
    }

    @Test
    fun nonDnsTrafficIsNotClaimedAsProcessed() {
        val result = DnsPacketProcessor(DnsPolicyEngine(emptySet()))
            .processIpv4Packet(ipv4UdpPacket(dnsQuery("news.example.org"), destinationPort = 443))

        assertIs<DnsPacketProcessingResult.NotDns>(result)
    }

    @Test
    fun seededArbitraryIpPacketsAlwaysProduceAnExplicitResult() {
        val processor = DnsPacketProcessor(DnsPolicyEngine(setOf("tracker.example")))
        val random = java.util.Random(0x5043414745L)

        // Include boundary sizes plus random bytes whose first nibble selects IPv4 or IPv6.
        val sizes = listOf(0, 1, 19, 20, 27, 28, 39, 40, 47, 48, 127, 512, 1499)
        for (size in sizes) {
            val packet = ByteArray(size)
            random.nextBytes(packet)
            val result = runCatching { processor.processIpPacket(packet) }
            kotlin.test.assertTrue("Packet of length $size escaped the decoder", result.isSuccess)
            kotlin.test.assertNotNull(result.getOrNull())
        }
        repeat(512) { caseIndex ->
            val packet = ByteArray(random.nextInt(0, 1500))
            random.nextBytes(packet)
            val result = runCatching { processor.processIpPacket(packet) }
            kotlin.test.assertTrue("Arbitrary packet case $caseIndex escaped the decoder", result.isSuccess)
        }
    }

    @Test
    fun rejectsUnsupportedIpv4FragmentsInsteadOfForwardingPartialDatagrams() {
        val packet = ipv4UdpPacket(dnsQuery("news.example.org"))
        // IPv4 flags/fragment offset: set MF to mark a fragmented datagram.
        putU16(packet, 6, 0x2000)
        putU16(packet, 10, 0)
        putU16(packet, 10, checksum(packet.copyOfRange(0, 20)))

        val result = DnsPacketProcessor(DnsPolicyEngine(emptySet())).processIpPacket(packet)

        assertIs<DnsPacketProcessingResult.Drop>(result)
    }

    private fun dnsQuery(name: String): ByteArray {
        val qname = name.split('.').flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        } + listOf(0.toByte())
        return byteArrayOf(
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ) + qname.toByteArray() + byteArrayOf(0, 1, 0, 1)
    }

    private fun ipv4UdpPacket(dnsPayload: ByteArray, destinationPort: Int = 53): ByteArray {
        val udpLength = 8 + dnsPayload.size
        val packet = ByteArray(20 + udpLength)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        putU16(packet, 4, 0x1234)
        packet[8] = 64
        packet[9] = 17
        packet[12] = 10
        packet[15] = 2
        packet[16] = 10
        packet[19] = 1
        putU16(packet, 20, 53000)
        putU16(packet, 22, destinationPort)
        putU16(packet, 24, udpLength)
        dnsPayload.copyInto(packet, destinationOffset = 28)
        putU16(packet, 26, udpChecksum(packet, 20, udpLength).let { if (it == 0) 0xffff else it })
        putU16(packet, 10, checksum(packet.copyOfRange(0, 20)))
        return packet
    }

    private fun udpChecksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        for (index in 12 until 20 step 2) sum += u16(packet, index).toLong()
        sum += 17L + length
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += u16(packet, index).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
        return foldChecksum(sum)
    }

    private fun checksum(bytes: ByteArray): Int {
        var sum = 0L
        var index = 0
        while (index + 1 < bytes.size) {
            sum += u16(bytes, index).toLong()
            index += 2
        }
        if (index < bytes.size) sum += ((bytes[index].toInt() and 0xff) shl 8).toLong()
        return foldChecksum(sum)
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
}
