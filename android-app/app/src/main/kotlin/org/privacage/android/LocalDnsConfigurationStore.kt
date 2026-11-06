package org.privacage.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.privacage.dns.DnsPolicyEngine
import org.privacage.dns.DnsOverTlsForwarder
import java.io.IOException
import java.nio.charset.StandardCharsets

internal data class LocalDnsConfiguration(
    val resolverIpv4: String,
    val blockedDomains: Set<String>,
    val dnsOverTlsEnabled: Boolean,
    val dnsOverTlsHostname: String
)

internal object LocalDnsConfigurationStore {
    private const val ENCRYPTED_KEY = "dns_configuration_encrypted_v1"
    private const val KEY_ALIAS = "org.privacage.android.dns-config.aes-gcm.v1"
    private const val AAD_LABEL = "dns-configuration"
    private const val MAX_BYTES = 128 * 1024
    private const val SCHEMA_VERSION = 1

    private val LEGACY_KEYS = setOf(
        PrivacyDnsVpnService.KEY_RESOLVER_IP,
        PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS,
        PrivacyDnsVpnService.KEY_DOT_ENABLED,
        PrivacyDnsVpnService.KEY_DOT_HOSTNAME
    )

    fun read(context: Context): LocalDnsConfiguration? {
        val preferences = context.getSharedPreferences(
            PrivacyDnsVpnService.PREFERENCES_NAME,
            Context.MODE_PRIVATE
        )
        val serialized = AndroidSensitivePreferenceVault.read(
            context = context,
            preferencesName = PrivacyDnsVpnService.PREFERENCES_NAME,
            encryptedKey = ENCRYPTED_KEY,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            defaultValue = null,
            maximumPlaintextBytes = MAX_BYTES,
            legacyKeys = LEGACY_KEYS,
            legacyValue = {
                val resolver = preferences.getString(PrivacyDnsVpnService.KEY_RESOLVER_IP, null)
                    ?: throw IOException("The legacy DNS resolver setting is missing.")
                val domains = preferences.getStringSet(PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS, null)
                    ?: throw IOException("The legacy DNS domain-rule setting is missing.")
                val tlsEnabled = preferences.getBoolean(PrivacyDnsVpnService.KEY_DOT_ENABLED, false)
                val tlsHostname = preferences.getString(PrivacyDnsVpnService.KEY_DOT_HOSTNAME, "").orEmpty()
                encode(
                    LocalDnsConfiguration(
                        resolverIpv4 = resolver,
                        blockedDomains = domains.toSet(),
                        dnsOverTlsEnabled = tlsEnabled,
                        dnsOverTlsHostname = tlsHostname
                    )
                )
            },
            validateValue = { decode(it) }
        )
        return serialized?.let(::decode)
    }

    fun save(context: Context, configuration: LocalDnsConfiguration) {
        val serialized = encode(configuration)
        AndroidSensitivePreferenceVault.write(
            context = context,
            preferencesName = PrivacyDnsVpnService.PREFERENCES_NAME,
            encryptedKey = ENCRYPTED_KEY,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            plaintext = serialized,
            maximumPlaintextBytes = MAX_BYTES,
            legacyKeys = LEGACY_KEYS,
            validateValue = { decode(it) }
        )
    }

    internal fun encode(configuration: LocalDnsConfiguration): String {
        validate(configuration)
        val domains = JSONArray()
        configuration.blockedDomains.sorted().forEach(domains::put)
        return JSONObject()
            .put("schema_version", SCHEMA_VERSION)
            .put("resolver_ipv4", configuration.resolverIpv4)
            .put("blocked_domains", domains)
            .put("dns_over_tls_enabled", configuration.dnsOverTlsEnabled)
            .put("dns_over_tls_hostname", configuration.dnsOverTlsHostname)
            .toString()
    }

    internal fun decode(serialized: String): LocalDnsConfiguration {
        if (serialized.toByteArray(StandardCharsets.UTF_8).size > MAX_BYTES) {
            throw IOException("The encrypted DNS configuration exceeds the supported size.")
        }
        try {
            StrictJsonKeyScanner.validate(serialized, "Encrypted DNS configuration")
        } catch (exception: IOException) {
            throw IOException("Encrypted DNS configuration is malformed or ambiguous.", exception)
        }
        val root = try {
            JSONObject(serialized)
        } catch (exception: Exception) {
            throw IOException("Encrypted DNS configuration is not valid JSON.", exception)
        }
        if (root.keys().asSequence().toSet() != setOf(
                "schema_version", "resolver_ipv4", "blocked_domains",
                "dns_over_tls_enabled", "dns_over_tls_hostname"
            ) ||
            root.opt("schema_version") !is Int || root.optInt("schema_version") != SCHEMA_VERSION
        ) {
            throw IOException("Encrypted DNS configuration has unsupported fields or version.")
        }
        val resolver = root.opt("resolver_ipv4") as? String
            ?: throw IOException("Encrypted DNS resolver address must be a string.")
        val array = root.optJSONArray("blocked_domains")
            ?: throw IOException("Encrypted DNS domain rules must be an array.")
        if (array.length() !in 1..10_000) {
            throw IOException("Encrypted DNS configuration must contain between 1 and 10,000 rules.")
        }
        val domains = linkedSetOf<String>()
        for (index in 0 until array.length()) {
            val domain = array.opt(index) as? String
                ?: throw IOException("Encrypted DNS configuration contains a non-string domain rule.")
            if (!domains.add(domain)) {
                throw IOException("Encrypted DNS configuration contains duplicate domain rules.")
            }
        }
        val tlsEnabled = root.opt("dns_over_tls_enabled") as? Boolean
            ?: throw IOException("Encrypted DNS-over-TLS setting must be a boolean.")
        val tlsHostname = root.opt("dns_over_tls_hostname") as? String
            ?: throw IOException("Encrypted DNS-over-TLS hostname must be a string.")
        val result = LocalDnsConfiguration(resolver, domains, tlsEnabled, tlsHostname)
        try {
            validate(result)
        } catch (exception: IllegalArgumentException) {
            throw IOException("Encrypted DNS configuration failed validation.", exception)
        }
        return result
    }

    private fun validate(configuration: LocalDnsConfiguration) {
        require(isIpv4Address(configuration.resolverIpv4)) {
            "The DNS resolver must be a numeric IPv4 address."
        }
        require(configuration.blockedDomains.isNotEmpty() && configuration.blockedDomains.size <= 10_000) {
            "DNS configuration must contain between 1 and 10,000 domain rules."
        }
        require(configuration.blockedDomains.all { it.isNotBlank() && it == it.trim() }) {
            "DNS domain rules must be non-empty and trimmed."
        }
        DnsPolicyEngine(configuration.blockedDomains)
        if (configuration.dnsOverTlsEnabled || configuration.dnsOverTlsHostname.isNotEmpty()) {
            DnsOverTlsForwarder.validateHostname(configuration.dnsOverTlsHostname)
        }
    }

    private fun isIpv4Address(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() &&
                part.length <= 3 &&
                part.all { it in '0'..'9' } &&
                part.toIntOrNull()?.let { it in 0..255 } == true
        }
    }
}
