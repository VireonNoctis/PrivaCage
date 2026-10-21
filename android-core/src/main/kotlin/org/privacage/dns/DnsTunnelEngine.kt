package org.privacage.dns

import java.io.IOException

/**
 * End-to-end single-packet coordinator for the supported IPv4/UDP/DNS subset.
 *
 * It returns a response packet for blocked or successfully forwarded DNS queries. It does not
 * read or write a TUN descriptor; an Android VpnService must own that lifecycle and I/O loop.
 */
class DnsTunnelEngine(
    private val processor: DnsPacketProcessor,
    private val upstreamForwarder: UdpDnsForwarder
) {

    /**
     * Processes one IPv4 packet. Upstream socket errors and timeouts propagate as IOException
     * so the platform adapter can record and handle them instead of inventing a DNS answer.
     */
    @Throws(IOException::class)
    fun processIpv4Packet(packet: ByteArray): DnsTunnelResult {
        return when (val result = processor.processIpv4Packet(packet)) {
            is DnsPacketProcessingResult.NotDns -> DnsTunnelResult.NotDns(result.reason)
            is DnsPacketProcessingResult.Drop -> DnsTunnelResult.Drop(result.reason)
            is DnsPacketProcessingResult.Blocked -> DnsTunnelResult.Response(
                packet = result.responsePacket,
                domain = result.domain,
                action = DnsTunnelAction.BLOCKED
            )
            is DnsPacketProcessingResult.ForwardRequired -> {
                val dnsResponse = upstreamForwarder.forward(result.query.dnsPayload)
                DnsTunnelResult.Response(
                    packet = Ipv4UdpDnsPacketCodec.buildUdpResponse(result.query, dnsResponse),
                    domain = result.question.name,
                    action = DnsTunnelAction.FORWARDED
                )
            }
        }
    }
}

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
