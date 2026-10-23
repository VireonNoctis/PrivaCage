package org.privacage.dns

/**
 * Deterministic policy evaluation for classic DNS query messages.
 *
 * This class does not open sockets, intercept device traffic, or enforce network policy.
 * A platform-specific DNS transport must capture and route messages to this engine.
 */
class DnsPolicyEngine(blockedDomains: Set<String>) {

    private val ruleRoot = RuleNode()

    init {
        blockedDomains.map(::normalizeRule).toSet().forEach { rule ->
            var node = ruleRoot
            for (label in rule.split('.').asReversed()) {
                node = node.children.getOrPut(label) { RuleNode() }
            }
            node.terminalRule = rule
        }
    }

    fun evaluate(message: ByteArray): DnsDecision {
        val question = try {
            parseQuery(message)
        } catch (e: DnsFormatException) {
            return DnsDecision.Malformed(e.message ?: "Malformed DNS query")
        }

        val matchingRule = matchingRuleForNormalizedName(question.name)

        return if (matchingRule == null) {
            DnsDecision.Allow(question)
        } else {
            DnsDecision.Block(question, matchingRule)
        }
    }

    /**
     * Previews the blocklist decision for a hostname without sending a DNS request.
     * Uses the same suffix-boundary and most-specific-rule logic as live packet evaluation.
     */
    fun matchingRuleForDomain(domainName: String): String? =
        matchingRuleForNormalizedName(normalizeRule(domainName))

    private fun matchingRuleForNormalizedName(name: String): String? {
        var node = ruleRoot
        var matchingRule: String? = null

        for (label in name.split('.').asReversed()) {
            node = node.children[label] ?: break
            node.terminalRule?.let { matchingRule = it }
        }
        return matchingRule
    }

    private class RuleNode {
        val children: MutableMap<String, RuleNode> = HashMap()
        var terminalRule: String? = null
    }

    private fun normalizeRule(rule: String): String {
        val trimmed = rule.trim()
        val normalized = (if (trimmed.endsWith('.')) trimmed.dropLast(1) else trimmed).lowercase()
        require(normalized.isNotEmpty()) { "Blocked domain must not be empty" }
        require(normalized.length <= 253) { "Blocked domain exceeds 253 characters" }
        val labels = normalized.split('.')
        require(labels.size >= 2) { "Blocked domain must be a fully qualified hostname: $rule" }
        require(labels.all(::isValidLabel)) { "Invalid blocked domain: $rule" }
        return normalized
    }

    private fun isValidLabel(label: String): Boolean {
        if (label.isEmpty() || label.length > 63) return false
        if (label.first() == '-' || label.last() == '-') return false
        return label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
    }

    private fun parseQuery(message: ByteArray): DnsQuestionView {
        if (message.size < DNS_HEADER_SIZE) throw DnsFormatException("DNS header is truncated")

        val flags = u16(message, 2)
        if ((flags and FLAG_QR) != 0) throw DnsFormatException("DNS message is a response, not a query")
        if ((flags and OPCODE_MASK) != 0) throw DnsFormatException("Unsupported DNS opcode")
        if ((flags and FLAG_RESERVED_Z) != 0) throw DnsFormatException("Reserved DNS header bit is set")

        if (u16(message, 4) != 1) throw DnsFormatException("Exactly one DNS question is required")
        if (u16(message, 6) != 0 || u16(message, 8) != 0) {
            throw DnsFormatException("A query must not contain answer or authority records")
        }

        val additionalCount = u16(message, 10)
        if (additionalCount > 1) {
            throw DnsFormatException("Only one additional OPT record is supported")
        }

        var offset = DNS_HEADER_SIZE
        val labels = ArrayList<String>()
        var totalNameLength = 0

        while (true) {
            if (offset >= message.size) throw DnsFormatException("DNS QNAME is truncated")
            val length = message[offset++].toInt() and 0xff
            if (length == 0) break
            if ((length and 0xc0) != 0) {
                throw DnsFormatException("Compressed DNS question names are not accepted")
            }
            if (length > 63 || offset + length > message.size) {
                throw DnsFormatException("Invalid or truncated DNS label")
            }

            val bytes = message.copyOfRange(offset, offset + length)
            if (bytes.any { (it.toInt() and 0xff) !in 0x21..0x7e }) {
                throw DnsFormatException("DNS label contains unsupported non-ASCII characters")
            }
            val label = bytes.toString(Charsets.US_ASCII).lowercase()
            if (!isValidLabel(label)) throw DnsFormatException("Invalid DNS label")
            labels += label
            totalNameLength += length + 1
            if (totalNameLength > 254) throw DnsFormatException("DNS name is too long")
            offset += length
        }

        if (labels.isEmpty()) throw DnsFormatException("Root DNS name is not a blockable hostname")
        if (offset + 4 > message.size) throw DnsFormatException("DNS question type/class is truncated")
        val qtype = u16(message, offset)
        val qclass = u16(message, offset + 2)
        if (qclass != CLASS_IN) throw DnsFormatException("Only IN-class DNS questions are supported")
        offset += 4

        when (additionalCount) {
            0 -> if (offset != message.size) {
                throw DnsFormatException("Trailing records or bytes are not supported by this policy core")
            }
            1 -> parseOptRecord(message, offset)
        }

        return DnsQuestionView(
            id = u16(message, 0),
            name = labels.joinToString("."),
            type = qtype,
            recursionDesired = (flags and FLAG_RD) != 0
        )
    }

    /**
     * Validates the single EDNS(0) OPT pseudo-record without interpreting option payloads.
     * Unknown option codes are intentionally opaque; their declared lengths must still be valid.
     */
    private fun parseOptRecord(message: ByteArray, start: Int) {
        if (start >= message.size) throw DnsFormatException("EDNS OPT record is truncated")
        if ((message[start].toInt() and 0xff) != 0) {
            throw DnsFormatException("EDNS OPT owner name must be the root")
        }

        val fixedStart = start + 1
        if (fixedStart + OPT_FIXED_SIZE > message.size) {
            throw DnsFormatException("EDNS OPT fixed fields are truncated")
        }
        if (u16(message, fixedStart) != TYPE_OPT) {
            throw DnsFormatException("The additional record must be an EDNS OPT record")
        }

        // CLASS is the sender's advertised UDP payload size. The policy engine does not
        // choose a transport size, so it validates the record structure but does not use it.
        val version = message[fixedStart + 5].toInt() and 0xff
        if (version != EDNS_VERSION_0) {
            throw DnsFormatException("Unsupported EDNS version: $version")
        }

        val dataLength = u16(message, fixedStart + 8)
        val dataStart = fixedStart + OPT_FIXED_SIZE
        val dataEnd = dataStart + dataLength
        if (dataEnd != message.size) {
            throw DnsFormatException("EDNS OPT RDATA length does not match the message")
        }

        var optionOffset = dataStart
        while (optionOffset < dataEnd) {
            if (optionOffset + OPT_OPTION_HEADER_SIZE > dataEnd) {
                throw DnsFormatException("EDNS option header is truncated")
            }
            val optionLength = u16(message, optionOffset + 2)
            optionOffset += OPT_OPTION_HEADER_SIZE
            if (optionOffset + optionLength > dataEnd) {
                throw DnsFormatException("EDNS option data is truncated")
            }
            optionOffset += optionLength
        }
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private class DnsFormatException(message: String) : Exception(message)

    companion object {
        private const val DNS_HEADER_SIZE = 12
        private const val OPT_FIXED_SIZE = 10
        private const val OPT_OPTION_HEADER_SIZE = 4
        private const val FLAG_QR = 0x8000
        private const val FLAG_RD = 0x0100
        private const val FLAG_RESERVED_Z = 0x0040
        private const val OPCODE_MASK = 0x7800
        private const val CLASS_IN = 1
        private const val TYPE_OPT = 41
        private const val EDNS_VERSION_0 = 0
    }
}

sealed interface DnsDecision {
    data class Allow(val question: DnsQuestionView) : DnsDecision
    data class Block(val question: DnsQuestionView, val matchedRule: String) : DnsDecision
    data class Malformed(val reason: String) : DnsDecision
}

data class DnsQuestionView(
    val id: Int,
    val name: String,
    val type: Int,
    val recursionDesired: Boolean
)
