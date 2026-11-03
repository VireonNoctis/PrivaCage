package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException

class LocalDnsConfigurationStoreTest {
    private val configuration = LocalDnsConfiguration(
        resolverIpv4 = "1.1.1.1",
        blockedDomains = setOf("ads.example.org", "metrics.example.org"),
        dnsOverTlsEnabled = true,
        dnsOverTlsHostname = "one.one.one.one"
    )

    @Test
    fun configurationRoundTripsWithDeterministicDomainOrdering() {
        val encoded = LocalDnsConfigurationStore.encode(configuration)
        val decoded = LocalDnsConfigurationStore.decode(encoded)
        assertEquals(configuration, decoded)
        assertEquals(
            LocalDnsConfigurationStore.encode(configuration),
            LocalDnsConfigurationStore.encode(configuration.copy(blockedDomains = configuration.blockedDomains.reversed().toSet()))
        )
    }

    @Test
    fun rejectsUnsupportedSchemaFieldsAndWrongTypes() {
        val encoded = LocalDnsConfigurationStore.encode(configuration)
        assertThrows(IOException::class.java) {
            LocalDnsConfigurationStore.decode(
                org.json.JSONObject(encoded).put("unreviewed", true).toString()
            )
        }
        assertThrows(IOException::class.java) {
            LocalDnsConfigurationStore.decode(
                org.json.JSONObject(encoded).put("dns_over_tls_enabled", "true").toString()
            )
        }
        assertThrows(IOException::class.java) {
            LocalDnsConfigurationStore.decode(
                encoded.replace("\"schema_version\":1", "\"schema_version\":1.0")
            )
        }
    }

    @Test
    fun preservesValidUnusedTlsHostnameForDisabledLegacyProfiles() {
        val legacy = configuration.copy(dnsOverTlsEnabled = false)
        assertEquals(legacy, LocalDnsConfigurationStore.decode(LocalDnsConfigurationStore.encode(legacy)))
    }

    @Test
    fun rejectsInvalidResolverRulesAndTlsHostname() {
        val encoded = LocalDnsConfigurationStore.encode(configuration)
        assertThrows(IllegalArgumentException::class.java) {
            LocalDnsConfigurationStore.encode(configuration.copy(resolverIpv4 = "resolver.example.org"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            LocalDnsConfigurationStore.encode(configuration.copy(blockedDomains = emptySet()))
        }
        assertThrows(IOException::class.java) {
            LocalDnsConfigurationStore.decode(
                org.json.JSONObject(encoded).put("dns_over_tls_hostname", "not a host name").toString()
            )
        }
    }
}
