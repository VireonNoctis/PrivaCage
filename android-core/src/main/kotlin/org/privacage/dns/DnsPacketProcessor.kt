package org.privacage.dns

/**
 * Applies the DNS policy to supported IPv4/IPv6 UDP DNS packets.
 *
 * Only DNS packets sent to the virtual DNS endpoints are routed to this processor. Unsupported
 * IPv6 extension headers, fragments, TCP DNS, and non-DNS traffic are not forwarded by this core.
 */
class DnsPacketProcessor(
    private val policyEngine: DnsPolicyEngine
) {
    fun processIpPacket(packet: ByteArray): DnsPacketProcessingResult {
        if (packet.isEmpty()) return DnsPacketProcessingResult.Drop("IP packet is empty")
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> processIpv4Packet(packet)
            6 -> processIpv6Packet(packet)
            else -> DnsPacketProcessingResult.Drop("Unsupported IP version")
        }
    }

    fun processIpv4Packet(packet: ByteArray): DnsPacketProcessingResult {
        return when (val decoded = Ipv4UdpDnsPacketCodec.decode(packet)) {
            is Ipv4UdpDnsDecode.NotDns -> DnsPacketProcessingResult.NotDns(decoded.reason)
            is Ipv4UdpDnsDecode.Malformed -> DnsPacketProcessingResult.Drop(decoded.reason)
            is Ipv4UdpDnsDecode.Query -> when (val decision = policyEngine.evaluate(decoded.dnsPayload)) {
                is DnsDecision.Allow -> DnsPacketProcessingResult.ForwardRequired(
                    query = decoded,
                    question = decision.question
                )
                is DnsDecision.Block -> {
                    val refusedDns = Ipv4UdpDnsPacketCodec.buildRefusedDnsResponseForValidatedQuery(decoded.dnsPayload)
                        ?: return DnsPacketProcessingResult.Drop(
                            "Policy matched a query that could not be encoded as a DNS response"
                        )
                    DnsPacketProcessingResult.Blocked(
                        domain = decision.question.name,
                        matchedRule = decision.matchedRule,
                        responsePacket = Ipv4UdpDnsPacketCodec.buildUdpResponseForValidatedQuery(decoded, refusedDns)
                    )
                }
                is DnsDecision.Malformed -> DnsPacketProcessingResult.Drop(decision.reason)
            }
        }
    }

    fun processIpv6Packet(packet: ByteArray): DnsPacketProcessingResult {
        return when (val decoded = Ipv6UdpDnsPacketCodec.decode(packet)) {
            is Ipv6UdpDnsDecode.NotDns -> DnsPacketProcessingResult.NotDns(decoded.reason)
            is Ipv6UdpDnsDecode.Malformed -> DnsPacketProcessingResult.Drop(decoded.reason)
            is Ipv6UdpDnsDecode.Query -> when (val decision = policyEngine.evaluate(decoded.dnsPayload)) {
                is DnsDecision.Allow -> DnsPacketProcessingResult.ForwardRequiredIpv6(
                    query = decoded,
                    question = decision.question
                )
                is DnsDecision.Block -> {
                    val refusedDns = Ipv4UdpDnsPacketCodec.buildRefusedDnsResponseForValidatedQuery(decoded.dnsPayload)
                        ?: return DnsPacketProcessingResult.Drop(
                            "Policy matched an IPv6 DNS query that could not be encoded as a DNS response"
                        )
                    DnsPacketProcessingResult.BlockedIpv6(
                        domain = decision.question.name,
                        matchedRule = decision.matchedRule,
                        responsePacket = Ipv6UdpDnsPacketCodec.buildUdpResponseForValidatedQuery(decoded, refusedDns)
                    )
                }
                is DnsDecision.Malformed -> DnsPacketProcessingResult.Drop(decision.reason)
            }
        }
    }
}

sealed interface DnsPacketProcessingResult {
    data class ForwardRequired(
        val query: Ipv4UdpDnsDecode.Query,
        val question: DnsQuestionView
    ) : DnsPacketProcessingResult

    data class ForwardRequiredIpv6(
        val query: Ipv6UdpDnsDecode.Query,
        val question: DnsQuestionView
    ) : DnsPacketProcessingResult

    data class Blocked(
        val domain: String,
        val matchedRule: String,
        val responsePacket: ByteArray
    ) : DnsPacketProcessingResult

    data class BlockedIpv6(
        val domain: String,
        val matchedRule: String,
        val responsePacket: ByteArray
    ) : DnsPacketProcessingResult

    data class Drop(val reason: String) : DnsPacketProcessingResult
    data class NotDns(val reason: String) : DnsPacketProcessingResult
}
