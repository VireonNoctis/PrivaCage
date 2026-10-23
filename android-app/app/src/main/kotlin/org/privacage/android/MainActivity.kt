package org.privacage.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import org.privacage.crypto.EncryptedBackupEnvelope
import org.privacage.dns.DnsPolicyEngine
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets

class MainActivity : Activity() {
    private lateinit var resolverInput: EditText
    private lateinit var domainsInput: EditText
    private lateinit var domainTestInput: EditText
    private lateinit var statsText: TextView
    private lateinit var statusText: TextView
    private var pendingEncryptedBackup: ByteArray? = null
    private var pendingImportBackup: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        var trackerCatalog: List<TrackerSignature>? = null
        var trackerCatalogError: String? = null
        try {
            trackerCatalog = TrackerSignatureCatalog.load(this)
        } catch (exception: Exception) {
            // Surface the failure to the user while preserving manual-rule functionality.
            trackerCatalogError = exception.message ?: exception.javaClass.simpleName
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
        }
        root.addView(TextView(this).apply { text = "PrivaCage"; textSize = 28f })
        root.addView(TextView(this).apply {
            text = "Local DNS filtering. No account or required cloud service."
            setPadding(0, dp(8), 0, dp(20))
        })
        root.addView(TextView(this).apply { text = "Upstream DNS resolver (numeric IPv4)" })
        resolverInput = EditText(this).apply {
            hint = "Enter a resolver IP you trust"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL
            setSingleLine(true)
            setText(prefs.getString(PrivacyDnsVpnService.KEY_RESOLVER_IP, ""))
        }
        root.addView(resolverInput, matchWidth())
        root.addView(TextView(this).apply {
            text = "Bundled tracker intelligence (optional)"
            setPadding(0, dp(18), 0, dp(4))
        })
        val activeTrackerCount = trackerCatalog.orEmpty().count { it.status == "active" }
        val reviewTrackerCount = trackerCatalog.orEmpty().count { it.status == "review" }
        val retiredTrackerCount = trackerCatalog.orEmpty().count { it.status == "retired" }
        root.addView(TextView(this).apply {
            text = if (trackerCatalog == null) {
                "Catalog unavailable: $trackerCatalogError. Manual domain rules still work."
            } else {
                "Bundled records: ${trackerCatalog!!.size}; active: $activeTrackerCount; review: $reviewTrackerCount; retired: $retiredTrackerCount. Nothing is blocked until you import domains and save."
            }
            textSize = 13f
        })
        val trackerDetails = TextView(this).apply {
            text = trackerCatalog.orEmpty().joinToString("\n\n") { record ->
                buildString {
                    append(record.name)
                    append(" [")
                    append(record.status.uppercase())
                    append(", ")
                    append(record.confidence)
                    append(" confidence]\n")
                    append("Category: ")
                    append(record.category)
                    append("\nDomains: ")
                    append(record.domains.ifEmpty { listOf("none") }.joinToString(", "))
                    append("\nSDK patterns: ")
                    append(record.sdkPatterns.ifEmpty { listOf("none") }.joinToString(", "))
                    append("\nLast verified: ")
                    append(record.lastVerified)
                    append("\nEvidence:\n")
                    append(record.evidence.joinToString("\n") { source -> "${source.url}\n${source.description}" })
                }
            }
            textSize = 12f
            visibility = android.view.View.GONE
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(Button(this).apply {
            text = "Show tracker records and evidence"
            setOnClickListener {
                if (trackerCatalog == null) {
                    statusText.text = "Tracker catalog unavailable: $trackerCatalogError. Rebuild with a valid bundled signatures.json."
                } else {
                    val expanded = trackerDetails.visibility != android.view.View.VISIBLE
                    trackerDetails.visibility = if (expanded) android.view.View.VISIBLE else android.view.View.GONE
                    text = if (expanded) "Hide tracker records and evidence" else "Show tracker records and evidence"
                }
            }
        }, matchWidth())
        root.addView(trackerDetails, matchWidth())
        root.addView(Button(this).apply {
            text = "Import active tracker domains"
            setOnClickListener {
                val catalog = trackerCatalog
                if (catalog == null) {
                    statusText.text = "Tracker catalog unavailable: $trackerCatalogError. No domains were imported."
                } else {
                    val activeDomains = catalog.filter { it.status == "active" }.flatMap { it.domains }.toSet()
                    if (activeDomains.isEmpty()) {
                        statusText.text = "The catalog has no active domain indicators to import. Review-only entries were left untouched."
                    } else {
                        val currentDomains = domainsInput.text.toString().lineSequence()
                            .map(String::trim).filter(String::isNotEmpty).toSet()
                        val newlyAdded = activeDomains - currentDomains
                        domainsInput.setText((currentDomains + activeDomains).sorted().joinToString("\n"))
                        statusText.text = if (newlyAdded.isEmpty()) {
                            "All active tracker domains are already in the rule editor. Save configuration to retain changes."
                        } else {
                            "Added ${newlyAdded.size} active domain indicator(s) to the rule editor. These changes are not saved until you tap Save configuration."
                        }
                    }
                }
            }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Blocked domains (one hostname per line)"
            setPadding(0, dp(16), 0, 0)
        })
        domainsInput = EditText(this).apply {
            hint = "tracker.example\nad-network.example"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            gravity = Gravity.TOP
            minLines = 4
            maxLines = 10
            setText(prefs.getStringSet(PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS, emptySet())
                .orEmpty().sorted().joinToString("\n"))
        }
        root.addView(domainsInput, matchWidth())
        root.addView(TextView(this).apply {
            text = "Preview a rule match (offline; no DNS request is sent)"
            setPadding(0, dp(12), 0, 0)
        })
        domainTestInput = EditText(this).apply {
            hint = "example.org"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        root.addView(domainTestInput, matchWidth())
        root.addView(Button(this).apply {
            text = "Test domain against current editor rules"
            setOnClickListener { previewDomainRule() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Export encrypted settings backup"
            setOnClickListener { promptExportPassphrase() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Import encrypted settings backup"
            setOnClickListener {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/octet-stream"
                }
                startActivityForResult(intent, REQUEST_IMPORT_FILE)
            }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Blocking is based on hostnames, not per-app proof of tracking. Review-status records are never imported. TCP DNS from apps, IPv6 DNS, DoH, DoT, and DoQ remain outside this version's scope."
            textSize = 13f
            setPadding(0, dp(12), 0, dp(12))
        })
        root.addView(Button(this).apply {
            text = "Save configuration"
            setOnClickListener { if (saveConfiguration()) statusText.text = "Configuration saved locally." }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Enable DNS filtering"
            setOnClickListener {
                if (!saveConfiguration()) return@setOnClickListener
                val consent = VpnService.prepare(this@MainActivity)
                if (consent == null) startVpnService() else {
                    @Suppress("DEPRECATION")
                    startActivityForResult(consent, REQUEST_VPN_PERMISSION)
                }
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Stop DNS filtering"
            setOnClickListener {
                stopService(Intent(this@MainActivity, PrivacyDnsVpnService::class.java))
                statusText.text = "Stop requested. Confirm disconnection using Android's VPN indicator."
            }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Privacy-preserving DNS counters"
            setPadding(0, dp(16), 0, 0)
        })
        statsText = TextView(this).apply {
            textSize = 13f
            setPadding(0, dp(4), 0, dp(4))
        }
        root.addView(statsText, matchWidth())
        root.addView(Button(this).apply {
            text = "Refresh DNS counters"
            setOnClickListener { refreshDnsStats() }
        }, matchWidth())
        statusText = TextView(this).apply {
            text = "Not connected (service state is not inferred by this screen)."
            setPadding(0, dp(12), 0, 0)
        }
        root.addView(statusText, matchWidth())
        refreshDnsStats()
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onResume() {
        super.onResume()
        if (::statsText.isInitialized) refreshDnsStats()
    }

    @Deprecated("Uses platform-compatible activity result callbacks")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_VPN_PERMISSION -> {
                if (resultCode == RESULT_OK) startVpnService()
                else statusText.text = "VPN permission was not granted; filtering did not start."
            }
            REQUEST_EXPORT_FILE -> writeEncryptedBackup(resultCode, data?.data)
            REQUEST_IMPORT_FILE -> readEncryptedBackup(resultCode, data?.data)
        }
    }

    override fun onDestroy() {
        pendingEncryptedBackup?.fill(0)
        pendingEncryptedBackup = null
        pendingImportBackup?.fill(0)
        pendingImportBackup = null
        super.onDestroy()
    }

    private fun previewDomainRule() {
        val candidate = domainTestInput.text.toString().trim()
        if (candidate.isEmpty()) {
            statusText.text = "Enter a hostname to preview. No network request will be sent."
            return
        }

        val rules = domainsInput.text.toString().lineSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toSet()
        if (rules.isEmpty()) {
            statusText.text = "There are no rules in the editor to test."
            return
        }

        try {
            val engine = DnsPolicyEngine(rules)
            val matchedRule = engine.matchingRuleForDomain(candidate)
            statusText.text = if (matchedRule == null) {
                "No current editor rule matches '$candidate'. This is only a local rule preview; no DNS request was sent."
            } else {
                "Would be blocked by '$matchedRule'. This is only a local rule preview; no DNS request was sent."
            }
        } catch (exception: IllegalArgumentException) {
            statusText.text = exception.message ?: "Enter a valid fully qualified hostname."
        }
    }

    private fun refreshDnsStats() {
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        statsText.text = buildString {
            append("Current/last VPN session totals (domain names are not recorded):\n")
            append("Blocked replies prepared: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_BLOCKED, 0L))
            append("\nUpstream replies prepared: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_FORWARDED, 0L))
            append("\nUnsupported or malformed packets: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_UNSUPPORTED, 0L))
            append("\nUpstream failures/timeouts: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_UPSTREAM_FAILURES, 0L))
            append("\nCounters reflect DNS-core outcomes, not proof that Android delivered every reply.")
        }
    }

    private fun promptExportPassphrase() {
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        val first = EditText(this).apply {
            hint = "Backup passphrase (12+ characters)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        val confirmation = EditText(this).apply {
            hint = "Confirm passphrase"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        fields.addView(first, matchWidth())
        fields.addView(confirmation, matchWidth())
        AlertDialog.Builder(this)
            .setTitle("Encrypt settings backup")
            .setMessage("The file is encrypted before it is written. Keep the passphrase separate from the file; PrivaCage cannot recover it.")
            .setView(fields)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Encrypt and save") { _, _ ->
                val password = first.text.toString().toCharArray()
                val confirm = confirmation.text.toString().toCharArray()
                try {
                    beginEncryptedExport(password, confirm)
                } finally {
                    password.fill('\u0000')
                    confirm.fill('\u0000')
                    first.text.clear()
                    confirmation.text.clear()
                }
            }
            .show()
    }

    private fun beginEncryptedExport(password: CharArray, confirmation: CharArray) {
        if (password.size < EncryptedBackupEnvelope.MIN_PASSPHRASE_LENGTH) {
            statusText.text = "Use a passphrase with at least ${EncryptedBackupEnvelope.MIN_PASSPHRASE_LENGTH} characters."
            return
        }
        if (!password.contentEquals(confirmation)) {
            statusText.text = "The passphrases do not match. No backup was created."
            return
        }
        val plaintext = currentProfilePayload() ?: return
        try {
            pendingEncryptedBackup?.fill(0)
            pendingEncryptedBackup = EncryptedBackupEnvelope.encrypt(plaintext, password)
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_TITLE, "privacage-settings.pcage")
            }
            startActivityForResult(intent, REQUEST_EXPORT_FILE)
            statusText.text = "Choose a destination for the encrypted settings file."
        } catch (exception: Exception) {
            pendingEncryptedBackup?.fill(0)
            pendingEncryptedBackup = null
            statusText.text = "Encrypted export could not be prepared. Check the passphrase and available device memory."
        } finally {
            plaintext.fill(0)
        }
    }

    private fun currentProfilePayload(): ByteArray? {
        val resolver = resolverInput.text.toString().trim()
        if (!isIpv4Address(resolver)) {
            statusText.text = "Enter a numeric IPv4 resolver before exporting."
            return null
        }
        val domains = domainsInput.text.toString().lineSequence()
            .map(String::trim).filter(String::isNotEmpty)
            .map { it.trimEnd('.').lowercase() }.toSet()
        if (domains.isEmpty()) {
            statusText.text = "Add at least one blocked domain before exporting."
            return null
        }
        try {
            DnsPolicyEngine(domains)
        } catch (exception: IllegalArgumentException) {
            statusText.text = exception.message ?: "One or more domain rules are invalid."
            return null
        }
        val json = JSONObject()
            .put("format_version", PROFILE_FORMAT_VERSION)
            .put("resolver_ipv4", resolver)
            .put("blocked_domains", JSONArray(domains.sorted()))
        val bytes = json.toString().toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > EncryptedBackupEnvelope.MAX_PLAINTEXT_BYTES) {
            bytes.fill(0)
            statusText.text = "The settings profile is too large to export."
            return null
        }
        return bytes
    }

    private fun writeEncryptedBackup(resultCode: Int, uri: Uri?) {
        val encrypted = pendingEncryptedBackup
        pendingEncryptedBackup = null
        if (resultCode != RESULT_OK || uri == null) {
            encrypted?.fill(0)
            statusText.text = "Encrypted export was cancelled; no file was saved."
            return
        }
        try {
            val content = encrypted ?: throw IOException("Encrypted backup bytes are missing")
            val output = contentResolver.openOutputStream(uri)
                ?: throw IOException("The chosen destination could not be opened")
            output.use { stream ->
                stream.write(content)
                stream.flush()
            }
            statusText.text = "Encrypted settings backup saved. The file contains no passphrase; keep the passphrase separately."
        } catch (exception: Exception) {
            statusText.text = "Could not write the encrypted backup. Choose a writable destination and try again."
        } finally {
            encrypted?.fill(0)
        }
    }

    private fun readEncryptedBackup(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            statusText.text = "Encrypted import was cancelled; settings were not changed."
            return
        }
        try {
            val input = contentResolver.openInputStream(uri)
                ?: throw IOException("The selected file could not be opened")
            val envelope = input.use { readLimited(it, EncryptedBackupEnvelope.MAX_ENVELOPE_BYTES) }
            pendingImportBackup?.fill(0)
            pendingImportBackup = envelope
            promptImportPassphrase()
        } catch (exception: Exception) {
            pendingImportBackup?.fill(0)
            pendingImportBackup = null
            statusText.text = "Could not read this encrypted backup. The file may be too large or inaccessible."
        }
    }

    private fun promptImportPassphrase() {
        val passwordInput = EditText(this).apply {
            hint = "Backup passphrase"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Decrypt settings backup")
            .setMessage("A wrong passphrase or modified file cannot be recovered. The current settings will not change until you confirm the import.")
            .setView(passwordInput)
            .setNegativeButton("Cancel") { _, _ ->
                pendingImportBackup?.fill(0)
                pendingImportBackup = null
                statusText.text = "Encrypted import cancelled; settings were not changed."
            }
            .setPositiveButton("Decrypt") { _, _ ->
                val password = passwordInput.text.toString().toCharArray()
                try {
                    decryptAndConfirmImport(password)
                } finally {
                    password.fill('\u0000')
                    passwordInput.text.clear()
                }
            }
            .setOnCancelListener {
                pendingImportBackup?.fill(0)
                pendingImportBackup = null
            }
            .show()
    }

    private fun decryptAndConfirmImport(password: CharArray) {
        val encrypted = pendingImportBackup
        pendingImportBackup = null
        var plaintext: ByteArray? = null
        try {
            val envelope = encrypted ?: throw IOException("Encrypted backup bytes are missing")
            plaintext = EncryptedBackupEnvelope.decrypt(envelope, password)
            val imported = parseProfilePayload(plaintext)
            AlertDialog.Builder(this)
                .setTitle("Replace local DNS settings?")
                .setMessage("Resolver: ${imported.resolverIpv4}\nBlocked domains: ${imported.blockedDomains.size}\n\nThis replaces the saved resolver and domain rules. If filtering is active, restart it to apply the imported settings.")
                .setNegativeButton("Cancel") { _, _ ->
                    statusText.text = "Import cancelled; existing settings were kept."
                }
                .setPositiveButton("Replace settings") { _, _ ->
                    getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE).edit()
                        .putString(PrivacyDnsVpnService.KEY_RESOLVER_IP, imported.resolverIpv4)
                        .putStringSet(PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS, imported.blockedDomains.toSet())
                        .apply()
                    resolverInput.setText(imported.resolverIpv4)
                    domainsInput.setText(imported.blockedDomains.sorted().joinToString("\n"))
                    statusText.text = "Encrypted profile imported. Restart active DNS filtering to apply the new configuration."
                }
                .show()
        } catch (exception: Exception) {
            statusText.text = "Backup could not be decrypted or validated. The passphrase may be wrong, the file may be damaged, or its format may be unsupported."
        } finally {
            plaintext?.fill(0)
            encrypted?.fill(0)
        }
    }

    private fun parseProfilePayload(plaintext: ByteArray): ImportedProfile {
        if (plaintext.isEmpty() || plaintext.size > EncryptedBackupEnvelope.MAX_PLAINTEXT_BYTES) {
            throw IOException("Profile payload length is invalid")
        }
        val json = try {
            JSONObject(String(plaintext, StandardCharsets.UTF_8))
        } catch (exception: Exception) {
            throw IOException("Profile payload is not valid JSON", exception)
        }
        val actualKeys = mutableSetOf<String>()
        val iterator = json.keys()
        while (iterator.hasNext()) actualKeys += iterator.next()
        if (actualKeys != setOf("format_version", "resolver_ipv4", "blocked_domains")) {
            throw IOException("Profile fields do not match the supported format")
        }
        val version = json.opt("format_version")
        if (version !is Number || version.toInt() != PROFILE_FORMAT_VERSION || version.toDouble() != PROFILE_FORMAT_VERSION.toDouble()) {
            throw IOException("Unsupported profile format version")
        }
        val resolver = json.opt("resolver_ipv4") as? String
            ?: throw IOException("Profile resolver is invalid")
        if (!isIpv4Address(resolver)) throw IOException("Profile resolver must be a numeric IPv4 address")
        val domainArray = json.opt("blocked_domains") as? JSONArray
            ?: throw IOException("Profile blocked_domains must be an array")
        if (domainArray.length() == 0) throw IOException("Profile must contain at least one blocked domain")
        val domains = mutableListOf<String>()
        for (index in 0 until domainArray.length()) {
            val domain = domainArray.opt(index) as? String
                ?: throw IOException("Profile contains a non-string domain")
            if (domain.isBlank() || domain != domain.trim() || domain != domain.lowercase() || domain.endsWith(".")) {
                throw IOException("Profile contains a non-normalized domain")
            }
            domains += domain
        }
        if (domains.size != domains.toSet().size) throw IOException("Profile contains duplicate domains")
        try {
            DnsPolicyEngine(domains.toSet())
        } catch (exception: IllegalArgumentException) {
            throw IOException("Profile contains an invalid domain rule", exception)
        }
        return ImportedProfile(resolver, domains)
    }

    private fun readLimited(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8_192)
        try {
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size() > maxBytes - count) {
                    throw IOException("Selected file exceeds the supported size")
                }
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        } finally {
            buffer.fill(0)
        }
    }

    private data class ImportedProfile(val resolverIpv4: String, val blockedDomains: List<String>)

    private fun saveConfiguration(): Boolean {
        val resolver = resolverInput.text.toString().trim()
        if (!isIpv4Address(resolver)) {
            statusText.text = "Enter a numeric IPv4 resolver address; hostnames are not accepted."
            return false
        }
        val domains = domainsInput.text.toString().lineSequence()
            .map(String::trim).filter(String::isNotEmpty).toSet()
        if (domains.isEmpty()) {
            statusText.text = "Add at least one domain. An empty rule set would block nothing."
            return false
        }
        try {
            DnsPolicyEngine(domains)
        } catch (exception: IllegalArgumentException) {
            statusText.text = exception.message ?: "One or more blocked-domain rules are invalid."
            return false
        }
        getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE).edit()
            .putString(PrivacyDnsVpnService.KEY_RESOLVER_IP, resolver)
            .putStringSet(PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS, domains)
            .apply()
        return true
    }

    private fun startVpnService() {
        val intent = Intent(this, PrivacyDnsVpnService::class.java).setAction(PrivacyDnsVpnService.ACTION_START)
        startForegroundService(intent)
        statusText.text = "Start requested. Check the persistent notification and Android VPN indicator for actual state."
    }

    private fun isIpv4Address(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) &&
                (part.toIntOrNull()?.let { it in 0..255 } ?: false)
        }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    )

    companion object {
        private const val REQUEST_VPN_PERMISSION = 4107
        private const val REQUEST_EXPORT_FILE = 4108
        private const val REQUEST_IMPORT_FILE = 4109
        private const val PROFILE_FORMAT_VERSION = 1
    }
}
