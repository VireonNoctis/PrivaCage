package org.privacage.dns

/**
 * Applies DNS policy to IPv4 UDP DNS packets and creates replies for blocked queries.
 *
 * Allowed queries are returned as ForwardRequired; this class does not send them anywhere.
 * The caller must forward them through a socket protected from the Android VPN.
 */
class DnsPacketProcessor(
    private val policyEngine: DnsPolicyEngine
) {

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
}

sealed interface DnsPacketProcessingResult {
    data class ForwardRequired(
        val query: Ipv4UdpDnsDecode.Query,
        val question: DnsQuestionView
    ) : DnsPacketProcessingResult

    data class Blocked(
        val domain: String,
        val matchedRule: String,
        val responsePacket: ByteArray
    ) : DnsPacketProcessingResult

    data class Drop(val reason: String) : DnsPacketProcessingResult
    data class NotDns(val reason: String) : DnsPacketProcessingResult
}
