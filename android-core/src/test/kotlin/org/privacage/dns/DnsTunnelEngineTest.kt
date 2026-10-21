package org.privacage.dns

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsTunnelEngineTest {

    @Test
    fun forwardsAllowedQueryAndReturnsIpv4ResponsePacket() {
        val query = dnsQuery("news.example.org")
        val expectedDnsResponse = dnsResponse(query)
        val server = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        server.soTimeout = 3000
        val serverFailure = AtomicReference<Throwable?>(null)
        val serverThread = Thread {
            try {
                val buffer = ByteArray(2048)
                val incoming = DatagramPacket(buffer, buffer.size)
                server.receive(incoming)
                server.send(DatagramPacket(expectedDnsResponse, expectedDnsResponse.size, incoming.socketAddress))
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }
        serverThread.start()

        try {
            val policy = DnsPolicyEngine(setOf("tracker.example"))
            val forwarder = UdpDnsForwarder(
                resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort),
                socketProtector = UdpSocketProtector { true },
                policyEngine = policy,
                timeoutMillis = 2000
            )
            val engine = DnsTunnelEngine(DnsPacketProcessor(policy), forwarder)
            val result = assertIs<DnsTunnelResult.Response>(engine.processIpv4Packet(ipv4UdpPacket(query)))

            assertEquals("news.example.org", result.domain)
            assertEquals(DnsTunnelAction.FORWARDED, result.action)
            assertContentEquals(expectedDnsResponse, result.packet.copyOfRange(28, result.packet.size))
            assertEquals(0, checksum(result.packet.copyOfRange(0, 20)))
            assertEquals(0, udpChecksum(result.packet, 20, u16(result.packet, 24)))
            assertEquals(53, u16(result.packet, 20))
            assertEquals(53000, u16(result.packet, 22))

            serverThread.join(3000)
            assertTrue(!serverThread.isAlive, "DNS test server thread did not finish")
            serverFailure.get()?.let { throw AssertionError("DNS test server failed", it) }
        } finally {
            server.close()
            serverThread.join(3000)
        }
    }

    @Test
    fun blockedQueryGetsRefusedWithoutOpeningUpstreamSocket() {
        val protectionCalled = AtomicBoolean(false)
        val policy = DnsPolicyEngine(setOf("tracker.example"))
        val forwarder = UdpDnsForwarder(
            resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), 9),
            socketProtector = UdpSocketProtector {
                protectionCalled.set(true)
                true
            },
            policyEngine = policy
        )
        val engine = DnsTunnelEngine(DnsPacketProcessor(policy), forwarder)

        val result = assertIs<DnsTunnelResult.Response>(
            engine.processIpv4Packet(ipv4UdpPacket(dnsQuery("tracker.example")))
        )
        assertEquals(DnsTunnelAction.BLOCKED, result.action)
        assertEquals(0x8105, u16(result.packet, 30))
        assertTrue(!protectionCalled.get(), "Blocked DNS query must not reach the upstream forwarder")
    }

    @Test
    fun upstreamProtectionFailurePropagatesToCaller() {
        val policy = DnsPolicyEngine(emptySet())
        val forwarder = UdpDnsForwarder(
            resolver = InetSocketAddress(InetAddress.getLoopbackAddress(), 9),
            socketProtector = UdpSocketProtector { false },
            policyEngine = policy
        )
        val engine = DnsTunnelEngine(DnsPacketProcessor(policy), forwarder)

        assertFailsWith<IOException> {
            engine.processIpv4Packet(ipv4UdpPacket(dnsQuery("news.example.org")))
        }
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

    private fun dnsResponse(query: ByteArray): ByteArray {
        val response = query.copyOf()
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }

    private fun ipv4UdpPacket(dnsPayload: ByteArray): ByteArray {
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
        putU16(packet, 22, 53)
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
