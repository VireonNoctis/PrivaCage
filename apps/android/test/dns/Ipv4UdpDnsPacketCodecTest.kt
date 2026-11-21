package org.privacage.dns

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Ipv4UdpDnsPacketCodecTest {

    @Test
    fun decodesValidIpv4UdpDnsQuery() {
        val dns = dnsQuery("tracker.example")
        val packet = ipv4UdpPacket(dns)
        val decoded = assertIs<Ipv4UdpDnsDecode.Query>(Ipv4UdpDnsPacketCodec.decode(packet))

        assertEquals(20, decoded.ipHeaderLength)
        assertEquals(53000, decoded.sourcePort)
        assertEquals(53, decoded.destinationPort)
        assertContentEquals(dns, decoded.dnsPayload)
        assertContentEquals(byteArrayOf(10, 0, 0, 2), decoded.sourceAddress)
        assertContentEquals(byteArrayOf(10, 0, 0, 1), decoded.destinationAddress)
    }

    @Test
    fun ignoresUdpTrafficNotAddressedToDnsPort() {
        val decoded = Ipv4UdpDnsPacketCodec.decode(ipv4UdpPacket(dnsQuery("tracker.example"), destinationPort = 443))
        assertIs<Ipv4UdpDnsDecode.NotDns>(decoded)
    }

    @Test
    fun rejectsInvalidIpv4HeaderChecksum() {
        val packet = ipv4UdpPacket(dnsQuery("tracker.example"))
        packet[8] = 63
        assertIs<Ipv4UdpDnsDecode.Malformed>(Ipv4UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsFragmentedIpv4Packets() {
        val packet = ipv4UdpPacket(dnsQuery("tracker.example"), fragmentField = 0x2000)
        assertIs<Ipv4UdpDnsDecode.Malformed>(Ipv4UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsReservedIpv4Flag() {
        val packet = ipv4UdpPacket(dnsQuery("tracker.example"), fragmentField = 0x8000)
        assertIs<Ipv4UdpDnsDecode.Malformed>(Ipv4UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun acceptsDontFragmentFlag() {
        val packet = ipv4UdpPacket(dnsQuery("tracker.example"), fragmentField = 0x4000)
        assertIs<Ipv4UdpDnsDecode.Query>(Ipv4UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsUdpLengthMismatch() {
        val packet = ipv4UdpPacket(dnsQuery("tracker.example"))
        putU16(packet, 24, u16(packet, 24) - 1)
        assertIs<Ipv4UdpDnsDecode.Malformed>(Ipv4UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun rejectsInvalidUdpChecksum() {
        val packet = ipv4UdpPacket(dnsQuery("tracker.example"))
        packet[packet.lastIndex] = (packet.last().toInt() xor 0x01).toByte()
        assertIs<Ipv4UdpDnsDecode.Malformed>(Ipv4UdpDnsPacketCodec.decode(packet))
    }

    @Test
    fun buildsRefusedDnsResponseAndReversesPacketEndpoints() {
        val dnsQuery = dnsQuery("tracker.example")
        val originalPacket = ipv4UdpPacket(dnsQuery)
        val decoded = assertIs<Ipv4UdpDnsDecode.Query>(Ipv4UdpDnsPacketCodec.decode(originalPacket))
        val refusedDns = Ipv4UdpDnsPacketCodec.buildRefusedDnsResponse(decoded.dnsPayload)
        requireNotNull(refusedDns)

        val response = Ipv4UdpDnsPacketCodec.buildUdpResponse(decoded, refusedDns)
        assertEquals(response.size, u16(response, 2))
        assertEquals(0, internetChecksum(response.copyOfRange(0, 20)))
        assertEquals(0, udpChecksum(response, 20, u16(response, 24)))

        assertContentEquals(byteArrayOf(10, 0, 0, 1), response.copyOfRange(12, 16))
        assertContentEquals(byteArrayOf(10, 0, 0, 2), response.copyOfRange(16, 20))
        assertEquals(53, u16(response, 20))
        assertEquals(53000, u16(response, 22))

        val dnsOffset = 28
        assertEquals(0x8105, u16(response, dnsOffset + 2))
        assertEquals(1, u16(response, dnsOffset + 4))
        assertEquals(0, u16(response, dnsOffset + 6))
        assertEquals(0, u16(response, dnsOffset + 8))
        assertEquals(0, u16(response, dnsOffset + 10))
        assertContentEquals(dnsQuery.copyOfRange(12, dnsQuery.size), refusedDns.copyOfRange(12, refusedDns.size))
    }

    @Test
    fun refusedResponseStripsEdnsOptRecord() {
        val query = dnsQueryWithEdns("tracker.example")
        val response = Ipv4UdpDnsPacketCodec.buildRefusedDnsResponse(query)
        requireNotNull(response)
        assertEquals(0, u16(response, 10))
        assertEquals(query.size - 11, response.size)
        assertEquals(0x8105, u16(response, 2))
    }

    @Test
    fun malformedDnsQueryDoesNotGetARefusedResponse() {
        assertNull(Ipv4UdpDnsPacketCodec.buildRefusedDnsResponse(byteArrayOf(1, 2, 3)))
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

    private fun dnsQueryWithEdns(name: String): ByteArray {
        val base = dnsQuery(name)
        base[11] = 1
        return base + byteArrayOf(
            0, 0, 41, 4, 0xd0.toByte(),
            0, 0, 0, 0, 0, 0
        )
    }

    private fun ipv4UdpPacket(
        dnsPayload: ByteArray,
        destinationPort: Int = 53,
        fragmentField: Int = 0
    ): ByteArray {
        val udpLength = 8 + dnsPayload.size
        val packet = ByteArray(20 + udpLength)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        putU16(packet, 4, 0x1234)
        putU16(packet, 6, fragmentField)
        packet[8] = 64
        packet[9] = 17
        packet[12] = 10
        packet[15] = 2
        packet[16] = 10
        packet[19] = 1

        putU16(packet, 20, 53000)
        putU16(packet, 22, destinationPort)
        putU16(packet, 24, udpLength)
        putU16(packet, 26, 0)
        dnsPayload.copyInto(packet, destinationOffset = 28)

        putU16(packet, 26, udpChecksum(packet, 20, udpLength).let { if (it == 0) 0xffff else it })
        putU16(packet, 10, internetChecksum(packet.copyOfRange(0, 20)))
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

    private fun internetChecksum(bytes: ByteArray): Int {
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

    @Test
    fun everyTruncatedIpv4PrefixAndSeededMutationFailsClosedWithoutThrowing() {
        val valid = ipv4UdpPacket(dnsQuery("tracker.example"))
        for (length in 0 until valid.size) {
            val outcome = runCatching { Ipv4UdpDnsPacketCodec.decode(valid.copyOf(length)) }
            assertTrue(outcome.isSuccess, "IPv4 parser threw for prefix length $length")
            assertTrue(outcome.getOrThrow() !is Ipv4UdpDnsDecode.Query, "Truncated IPv4 prefix was accepted")
        }

        val random = java.util.Random(0x49505634L)
        for (caseIndex in 0 until 512) {
            val input = ByteArray(random.nextInt(0, 1601))
            random.nextBytes(input)
            assertTrue(
                runCatching { Ipv4UdpDnsPacketCodec.decode(input) }.isSuccess,
                "IPv4 parser threw on seeded malformed packet $caseIndex"
            )
        }

        for (index in valid.indices) {
            val mutated = valid.copyOf()
            mutated[index] = (mutated[index].toInt() xor 0x80).toByte()
            assertTrue(
                runCatching { Ipv4UdpDnsPacketCodec.decode(mutated) }.isSuccess,
                "IPv4 parser threw after mutating byte $index"
            )
        }
    }
}
