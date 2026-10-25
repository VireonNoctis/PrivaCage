package org.privacage.dns

import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.math.ceil
import kotlin.test.Test
import org.junit.jupiter.api.Tag

/**
 * Repeatable relative microbenchmark. Results are measurements, not pass/fail thresholds.
 * The runner compares the same workload on a baseline commit and the candidate commit.
 */
@Tag("performance")
class DnsPerformanceBenchmarkTest {

    private data class Measurement(
        val benchmark: String,
        val operationsPerSample: Int,
        val samples: Int,
        val medianNsPerOperation: Long,
        val p95NsPerOperation: Long,
        val operationsPerSecond: Double,
        val ruleCount: Int,
        val sink: Long
    ) {
        fun toJson(): String = buildString {
            append("{")
            append("\"benchmark\":").append(jsonString(benchmark)).append(',')
            append("\"operations_per_sample\":").append(operationsPerSample).append(',')
            append("\"samples\":").append(samples).append(',')
            append("\"median_ns_per_operation\":").append(medianNsPerOperation).append(',')
            append("\"p95_ns_per_operation\":").append(p95NsPerOperation).append(',')
            append("\"operations_per_second\":").append(operationsPerSecond).append(',')
            append("\"rule_count\":").append(ruleCount).append(',')
            append("\"result_sink\":").append(sink)
            append("}")
        }
    }

    @Test
    fun measuresDnsRuleBuildLookupAndBlockedPacketThroughput() {
        val rules = (0 until 10_000)
            .mapTo(linkedSetOf()) { index -> "tracker-$index.example.test" }
            .apply {
                add("example.test")
                add("sdk.example.test")
            }
        val target = "img.tracker-9999.example.test"
        val query = dnsQuery(target)
        val packet = ipv4UdpPacket(query)
        val engine = DnsPolicyEngine(rules)
        val processor = DnsPacketProcessor(engine)

        check(engine.matchingRuleForDomain(target) == "tracker-9999.example.test")
        check(engine.evaluate(query) is DnsDecision.Block)
        check(processor.processIpv4Packet(packet) is DnsPacketProcessingResult.Blocked)

        val measurements = listOf(
            measure(
                name = "dns_policy_trie_build_10k_rules",
                warmupIterations = 2,
                operationsPerSample = 1,
                samples = 7,
                ruleCount = rules.size
            ) {
                val built = DnsPolicyEngine(rules)
                if (built.matchingRuleForDomain(target) == "tracker-9999.example.test") 1L else 0L
            },
            measure(
                name = "dns_policy_evaluate_10k_rules",
                warmupIterations = 20_000,
                operationsPerSample = 10_000,
                samples = 7,
                ruleCount = rules.size
            ) {
                if (engine.evaluate(query) is DnsDecision.Block) 1L else 0L
            },
            measure(
                name = "dns_ipv4_udp_blocked_packet_10k_rules",
                warmupIterations = 10_000,
                operationsPerSample = 5_000,
                samples = 7,
                ruleCount = rules.size
            ) {
                val result = processor.processIpv4Packet(packet)
                if (result is DnsPacketProcessingResult.Blocked) {
                    result.responsePacket.size.toLong()
                } else {
                    0L
                }
            }
        )

        val outputPath = System.getProperty("performance.output")
            ?: error("performance.output must be set by the Gradle performanceTest task")
        val output = File(outputPath)
        output.parentFile?.mkdirs()
        output.writeText(
            buildString {
                append("{\"schema_version\":1,")
                append("\"benchmark_runner\":").append(jsonString("JVM/JUnit5")).append(',')
                append("\"os\":").append(jsonString(System.getProperty("os.name"))).append(',')
                append("\"java_version\":").append(jsonString(System.getProperty("java.version"))).append(',')
                append("\"available_processors\":").append(Runtime.getRuntime().availableProcessors()).append(',')
                append("\"benchmarks\":[")
                append(measurements.joinToString(",") { it.toJson() })
                append("]}\n")
            }
        )
        measurements.forEach { println("PRIVACAGE_PERF_DNS_JSON:${it.toJson()}") }
        println("PrivaCage DNS benchmark report: ${output.absolutePath}")
    }

    private fun measure(
        name: String,
        warmupIterations: Int,
        operationsPerSample: Int,
        samples: Int,
        ruleCount: Int,
        operation: () -> Long
    ): Measurement {
        var sink = 0L
        repeat(warmupIterations) { sink += operation() }

        val sampleNs = LongArray(samples) {
            val start = System.nanoTime()
            repeat(operationsPerSample) { sink += operation() }
            ((System.nanoTime() - start) / operationsPerSample).coerceAtLeast(1L)
        }.sortedArray()

        val median = sampleNs[sampleNs.size / 2]
        val p95Index = ceil(sampleNs.size * 0.95).toInt().coerceAtMost(sampleNs.size) - 1
        return Measurement(
            benchmark = name,
            operationsPerSample = operationsPerSample,
            samples = samples,
            medianNsPerOperation = median,
            p95NsPerOperation = sampleNs[p95Index],
            operationsPerSecond = 1_000_000_000.0 / median.toDouble(),
            ruleCount = ruleCount,
            sink = sink
        )
    }

    private fun dnsQuery(domain: String): ByteArray {
        val qname = ByteArrayOutputStream()
        for (label in domain.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            qname.write(bytes.size)
            qname.write(bytes)
        }
        qname.write(0)
        return byteArrayOf(
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ) + qname.toByteArray() + byteArrayOf(0, 1, 0, 1)
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
        val udpChecksum = udpChecksum(packet, 20, udpLength)
        putU16(packet, 26, if (udpChecksum == 0) 0xffff else udpChecksum)
        putU16(packet, 10, checksum(packet, 0, 20))
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

    private fun checksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += u16(packet, index).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
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

    private fun jsonString(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
