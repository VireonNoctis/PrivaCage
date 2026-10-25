package org.privacage.dns

import java.io.IOException
import java.util.concurrent.atomic.AtomicLong

/**
 * End-to-end packet coordinator for the supported IPv4/IPv6 UDP DNS subset.
 *
 * It returns a response packet for blocked or successfully forwarded DNS queries. It does not
 * read or write a TUN descriptor; an Android VpnService must own that lifecycle and I/O loop.
 */
class DnsTunnelEngine(
    private val processor: DnsPacketProcessor,
    private val upstreamForwarder: DnsUpstreamTransport
) {
    val stats = DnsTunnelStats()

    /** Dispatches only supported IPv4 and IPv6 packet versions. */
    fun processIpPacket(packet: ByteArray): DnsTunnelResult {
        if (packet.isEmpty()) {
            stats.recordUnsupportedOrMalformed()
            return DnsTunnelResult.Drop("IP packet is empty")
        }
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> processIpv4Packet(packet)
            6 -> processIpv6Packet(packet)
            else -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.Drop("Unsupported IP version")
            }
        }
    }

    @Throws(IOException::class)
    fun processIpv4Packet(packet: ByteArray): DnsTunnelResult {
        return when (val result = processor.processIpv4Packet(packet)) {
            is DnsPacketProcessingResult.NotDns -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.NotDns(result.reason)
            }
            is DnsPacketProcessingResult.Drop -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.Drop(result.reason)
            }
            is DnsPacketProcessingResult.Blocked -> {
                stats.recordBlocked()
                DnsTunnelResult.Response(
                    packet = result.responsePacket,
                    domain = result.domain,
                    action = DnsTunnelAction.BLOCKED
                )
            }
            is DnsPacketProcessingResult.ForwardRequired -> {
                val dnsResponse = try {
                    upstreamForwarder.forward(result.query.dnsPayload)
                } catch (exception: IOException) {
                    stats.recordUpstreamFailure()
                    throw exception
                }
                val responsePacket = Ipv4UdpDnsPacketCodec.buildUdpResponse(result.query, dnsResponse)
                stats.recordForwarded()
                DnsTunnelResult.Response(
                    packet = responsePacket,
                    domain = result.question.name,
                    action = DnsTunnelAction.FORWARDED
                )
            }
            is DnsPacketProcessingResult.ForwardRequiredIpv6,
            is DnsPacketProcessingResult.BlockedIpv6 -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.Drop("IPv6 packet reached the IPv4 processing entry point")
            }
        }
    }

    @Throws(IOException::class)
    fun processIpv6Packet(packet: ByteArray): DnsTunnelResult {
        return when (val result = processor.processIpv6Packet(packet)) {
            is DnsPacketProcessingResult.NotDns -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.NotDns(result.reason)
            }
            is DnsPacketProcessingResult.Drop -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.Drop(result.reason)
            }
            is DnsPacketProcessingResult.BlockedIpv6 -> {
                stats.recordBlocked()
                DnsTunnelResult.Response(
                    packet = result.responsePacket,
                    domain = result.domain,
                    action = DnsTunnelAction.BLOCKED
                )
            }
            is DnsPacketProcessingResult.ForwardRequiredIpv6 -> {
                val dnsResponse = try {
                    upstreamForwarder.forward(result.query.dnsPayload)
                } catch (exception: IOException) {
                    stats.recordUpstreamFailure()
                    throw exception
                }
                val responsePacket = try {
                    Ipv6UdpDnsPacketCodec.buildUdpResponseForValidatedQuery(result.query, dnsResponse)
                } catch (exception: IllegalArgumentException) {
                    stats.recordUpstreamFailure()
                    return DnsTunnelResult.Drop(
                        exception.message ?: "IPv6 DNS response could not fit within the TUN packet limit"
                    )
                }
                stats.recordForwarded()
                DnsTunnelResult.Response(
                    packet = responsePacket,
                    domain = result.question.name,
                    action = DnsTunnelAction.FORWARDED
                )
            }
            is DnsPacketProcessingResult.ForwardRequired,
            is DnsPacketProcessingResult.Blocked -> {
                stats.recordUnsupportedOrMalformed()
                DnsTunnelResult.Drop("IPv4 packet reached the IPv6 processing entry point")
            }
        }
    }
}

/**
 * Session counters contain outcome totals only. DNS names and packet payloads are never retained.
 */
class DnsTunnelStats {
    private val blocked = AtomicLong()
    private val forwarded = AtomicLong()
    private val unsupportedOrMalformed = AtomicLong()
    private val upstreamFailures = AtomicLong()

    internal fun recordBlocked() { blocked.incrementAndGet() }
    internal fun recordForwarded() { forwarded.incrementAndGet() }
    internal fun recordUnsupportedOrMalformed() { unsupportedOrMalformed.incrementAndGet() }
    internal fun recordUpstreamFailure() { upstreamFailures.incrementAndGet() }

    fun snapshot(): DnsTunnelStatsSnapshot = DnsTunnelStatsSnapshot(
        blockedQueries = blocked.get(),
        forwardedQueries = forwarded.get(),
        unsupportedOrMalformedPackets = unsupportedOrMalformed.get(),
        upstreamFailures = upstreamFailures.get()
    )
}

data class DnsTunnelStatsSnapshot(
    val blockedQueries: Long,
    val forwardedQueries: Long,
    val unsupportedOrMalformedPackets: Long,
    val upstreamFailures: Long
)

enum class DnsTunnelAction {
    BLOCKED,
    FORWARDED
}

sealed interface DnsTunnelResult {
    data class Response(
        val packet: ByteArray,
        val domain: String,
        val action: DnsTunnelAction
    ) : DnsTunnelResult

    data class Drop(val reason: String) : DnsTunnelResult
    data class NotDns(val reason: String) : DnsTunnelResult
}
