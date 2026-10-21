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
            text = "No verified tracker list is bundled. Only domains you enter are blocked. TCP DNS, IPv6 DNS, DoH, DoT, and DoQ are outside this version's scope."
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
