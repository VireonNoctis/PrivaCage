package org.privacage.android

import android.app.Activity
import android.content.Intent
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
import org.privacage.dns.DnsPolicyEngine

class MainActivity : Activity() {
    private lateinit var resolverInput: EditText
    private lateinit var domainsInput: EditText
    private lateinit var statusText: TextView

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
        statusText = TextView(this).apply {
            text = "Not connected (service state is not inferred by this screen)."
            setPadding(0, dp(12), 0, 0)
        }
        root.addView(statusText, matchWidth())
        setContentView(ScrollView(this).apply { addView(root) })
    }

    @Deprecated("Uses the platform-compatible VPN consent result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_VPN_PERMISSION) return
        if (resultCode == RESULT_OK) startVpnService()
        else statusText.text = "VPN permission was not granted; filtering did not start."
    }

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

    companion object { private const val REQUEST_VPN_PERMISSION = 4107 }
}
