package org.privacage.android

import android.app.Activity
import android.app.AlertDialog
import android.app.DatePickerDialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.Context
import android.content.IntentFilter
import android.content.ClipboardManager
import android.content.Intent
import android.provider.Settings
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import org.privacage.audit.AuditExportRequest
import org.privacage.audit.AuditExportResult
import org.privacage.audit.LocalAuditExporter
import org.privacage.crypto.EncryptedBackupEnvelope
import org.privacage.dns.DnsPolicyEngine
import org.privacage.dns.DnsOverTlsForwarder
import org.privacage.android.sync.AndroidEncryptedSyncManager
import org.privacage.android.sync.OwnerRotationResult
import org.privacage.android.sync.SyncRelayClient
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.time.LocalDate
import java.security.MessageDigest

class MainActivity : Activity() {
    private lateinit var resolverInput: EditText
    private lateinit var resolverHostnameInput: EditText
    private lateinit var dnsOverTlsInput: CheckBox
    private lateinit var domainsInput: EditText
    private lateinit var domainTestInput: EditText
    private lateinit var statsText: TextView
    private lateinit var apkAuditText: TextView
    private lateinit var statusText: TextView
    private lateinit var vpnStateText: TextView
    private lateinit var dnsDiagnosticText: TextView
    private var vpnStateReceiverRegistered = false
    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == PrivacyDnsVpnService.ACTION_STATE_CHANGED) refreshVpnState()
            if (intent.action == PrivacyDnsVpnService.ACTION_DIAGNOSTIC_RESULT) refreshDnsRouteDiagnostic()
        }
    }
    private lateinit var devicePrivacyText: TextView
    private lateinit var appPermissionAuditText: TextView
    private var apkTrackerCatalog: List<TrackerSignature> = emptyList()
    @Volatile private var trackerCatalogLoadComplete = false
    @Volatile private var trackerCatalogLoadFailure: String? = null
    private var lastImportedTrackerDomains: Set<String> = emptySet()
    private var pendingEncryptedBackup: ByteArray? = null
    private var pendingImportBackup: ByteArray? = null
    private var pendingAuditExport: ByteArray? = null
    private var pendingAuditExportFileName: String? = null
    private var pendingAuditExportIsSignedCheckpoint = false
    private var auditExportStartDate = LocalDate.now().minusDays(6)
    private var auditExportEndDate = LocalDate.now()
    private lateinit var auditExportStartButton: Button
    private lateinit var auditExportEndButton: Button
    private lateinit var auditExportBlockedCheck: CheckBox
    private lateinit var auditExportForwardedCheck: CheckBox
    private lateinit var auditExportHostnamesCheck: CheckBox
    private lateinit var auditExportSocketOwnerCheck: CheckBox
    private var pendingMetadataInput: File? = null
    private var pendingApkDiffBaseline: ApkManifestAuditReport? = null
    private var pendingScrubbedMedia: File? = null
    private var pendingScrubbedMediaExtension: String? = null
    private var pendingScrubbedMediaMime: String? = null
    private val metadataScrubber by lazy { NativeMetadataScrubber() }
    private var pendingSyncRecoveryExport: ByteArray? = null
    private var pendingSyncRecoveryImport: ByteArray? = null
    private lateinit var syncStatusText: TextView
    private lateinit var syncPeerCardInput: EditText
    private lateinit var syncRelayUrlInput: EditText
    private lateinit var syncSpaceIdInput: EditText
    private lateinit var syncCapabilityInput: EditText
    private val encryptedSyncManager by lazy { AndroidEncryptedSyncManager(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        var trackerCatalog: List<TrackerSignature>? = null
        var trackerCatalogError: String? = null
        var trackerCatalogLoading = true
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
        }
        root.addView(TextView(this).apply { text = "PrivaCage"; textSize = 28f })
        root.addView(TextView(this).apply {
            text = "Local-first privacy controls. Android still owns OS-level permissions and system telemetry."
            setPadding(0, dp(8), 0, dp(12))
        })
        root.addView(TextView(this).apply { text = "ANDROID PRIVACY CONTROLS"; textSize = 16f; setPadding(0, dp(8), 0, dp(4)) })
        root.addView(TextView(this).apply {
            text = "These shortcuts open Android's own settings so you can review access and revoke permissions there. PrivaCage cannot override the OS or secretly revoke permissions for other apps."
            textSize = 13f
        })
        root.addView(Button(this).apply { text = "Open Privacy Dashboard"; setOnClickListener { openSystemSettings(Settings.ACTION_PRIVACY_SETTINGS, "Privacy Dashboard") } }, matchWidth())
        root.addView(Button(this).apply { text = "Open app management"; setOnClickListener { openSystemSettings(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS, "App management") } }, matchWidth())
        root.addView(Button(this).apply { text = "Location access settings"; setOnClickListener { openSystemSettings(Settings.ACTION_LOCATION_SOURCE_SETTINGS, "Location settings") } }, matchWidth())
        root.addView(Button(this).apply { text = "Wi-Fi and network settings"; setOnClickListener { openSystemSettings(Settings.ACTION_WIFI_SETTINGS, "Wi-Fi settings") } }, matchWidth())
        root.addView(Button(this).apply {
            text = "Open Private DNS settings"
            setOnClickListener { openSystemSettings("android.settings.PRIVATE_DNS_SETTINGS", "Private DNS settings") }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "DEVICE PRIVACY SNAPSHOT (LOCAL ONLY)"
            textSize = 16f
            setPadding(0, dp(18), 0, dp(4))
        })
        root.addView(TextView(this).apply {
            text = "Reads only exposed device settings: location-services state, Wi-Fi radio state, Android Private DNS mode, and whether the active default network uses a VPN. It does not read your Wi-Fi name, scan nearby networks, or send this snapshot anywhere."
            textSize = 13f
        })
        devicePrivacyText = TextView(this).apply {
            text = "Snapshot not refreshed yet."
            textSize = 13f
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(devicePrivacyText, matchWidth())
        root.addView(Button(this).apply {
            text = "Refresh device privacy snapshot"
            setOnClickListener { refreshDevicePrivacySnapshot() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Audit visible apps' sensitive permissions"
            setOnClickListener {
                appPermissionAuditText.text = "Scanning launcher-visible apps. Results stay on this device..."
                Thread({
                    val report = AppPermissionAudit.scan(this@MainActivity)
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) appPermissionAuditText.text = report
                    }
                }, "PrivaCage-permission-audit").start()
            }
        }, matchWidth())
        appPermissionAuditText = TextView(this).apply {
            text = "No app permission audit has been run."
            textSize = 12f
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(appPermissionAuditText, matchWidth())

        root.addView(TextView(this).apply {
            text = "PRIVACY HARDENING"
            textSize = 16f
            setPadding(0, dp(18), 0, dp(4))
        })
        root.addView(TextView(this).apply {
            text = "These controls open official Android, Google, and Samsung settings or guidance. PrivaCage does not silently change account settings or claim that a page visit disables collection."
            textSize = 13f
        })
        root.addView(Button(this).apply {
            text = "Review Android ad privacy settings"
            setOnClickListener {
                openSystemSettings("android.settings.AD_PRIVACY_SETTINGS", "Ad privacy settings")
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Review Google Account data controls"
            setOnClickListener {
                openExternalUrl("https://myaccount.google.com/data-and-privacy", "Google Account data controls")
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Review Samsung Customization Service"
            setOnClickListener {
                openExternalUrl(
                    "https://terms.account.samsung.com/contents/legal/gb/en/customizedservicecontent.html",
                    "Samsung Customization Service privacy information"
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Open Android VPN settings (advanced)"
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("VPN lockdown is not ready for PrivaCage")
                    .setMessage(
                        "PrivaCage currently routes only its configured DNS endpoint, not all device traffic. " +
                            "Do not select PrivaCage as an always-on lockdown VPN yet: Android may block ordinary app traffic. " +
                            "This opens VPN settings so you can inspect your device's existing VPN configuration."
                    )
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Open VPN settings") { _, _ ->
                        openSystemSettings(Settings.ACTION_VPN_SETTINGS, "VPN settings")
                    }
                    .show()
            }
        }, matchWidth())
        root.addView(TextView(this).apply { text = "DNS PRIVACY"; textSize = 16f; setPadding(0, dp(18), 0, dp(4)) })
        root.addView(Button(this).apply {
            text = "Inspect / scrub image metadata (JPEG, PNG, WebP)"
            setOnClickListener { chooseMetadataFile() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Inspect APK manifest offline"
            setOnClickListener { chooseApkForAudit() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Compare two APK versions locally"
            setOnClickListener { chooseApkForDiffBaseline() }
        }, matchWidth())
        apkAuditText = TextView(this).apply {
            visibility = android.view.View.GONE
            textSize = 12f
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(apkAuditText, matchWidth())
        root.addView(TextView(this).apply { text = "Upstream DNS resolver (numeric IPv4)" })
        resolverInput = EditText(this).apply {
            hint = "Enter a resolver IP you trust"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL
            setSingleLine(true)
            setText(prefs.getString(PrivacyDnsVpnService.KEY_RESOLVER_IP, ""))
        }
        root.addView(resolverInput, matchWidth())
        dnsOverTlsInput = CheckBox(this).apply {
            text = "Use DNS-over-TLS (encrypted upstream DNS; fails closed)"
            isChecked = prefs.getBoolean(PrivacyDnsVpnService.KEY_DOT_ENABLED, false)
        }
        root.addView(dnsOverTlsInput, matchWidth())
        root.addView(TextView(this).apply { text = "TLS certificate hostname (required when DNS-over-TLS is enabled)" })
        resolverHostnameInput = EditText(this).apply {
            hint = "e.g. dns.google or cloudflare-dns.com"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            setText(prefs.getString(PrivacyDnsVpnService.KEY_DOT_HOSTNAME, ""))
        }
        root.addView(resolverHostnameInput, matchWidth())
        root.addView(TextView(this).apply {
            text = "DNS-over-TLS encrypts DNS between this device and the selected resolver; that resolver can still see queries. It does not stop Android, apps, or the Wi-Fi operator from collecting other data, and it does not block DoH/DoQ or all IPv6 traffic."
            textSize = 12f; setPadding(0, dp(4), 0, dp(8))
        })
        root.addView(TextView(this).apply {
            text = "Bundled tracker intelligence (optional)"
            setPadding(0, dp(18), 0, dp(4))
        })
        val trackerCatalogStatus = TextView(this).apply {
            text = "Loading bundled tracker intelligence in the background…"
            textSize = 13f
        }
        root.addView(trackerCatalogStatus)
        val trackerDetails = TextView(this).apply {
            textSize = 12f
            visibility = android.view.View.GONE
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(Button(this).apply {
            text = "Show tracker records and evidence"
            setOnClickListener {
                if (trackerCatalogLoading) {
                    statusText.text = "Tracker catalog is still loading in the background. Manual DNS rules remain available."
                } else if (trackerCatalog == null) {
                    statusText.text = "Tracker catalog unavailable: $trackerCatalogError. Manual domain rules still work."
                } else {
                    if (trackerDetails.text.isNullOrBlank()) {
                        trackerDetails.text = formatTrackerCatalogDetails(trackerCatalog.orEmpty())
                    }
                    val expanded = trackerDetails.visibility != android.view.View.VISIBLE
                    trackerDetails.visibility = if (expanded) android.view.View.VISIBLE else android.view.View.GONE
                    text = if (expanded) "Hide tracker records and evidence" else "Show tracker records and evidence"
                }
            }
        }, matchWidth())
        root.addView(trackerDetails, matchWidth())
        root.addView(Button(this).apply {
            text = "Review and import active tracker domains"
            setOnClickListener {
                val catalog = trackerCatalog
                if (trackerCatalogLoading) {
                    statusText.text = "Tracker catalog is still loading. No domains were imported."
                } else if (catalog == null) {
                    statusText.text = "Tracker catalog unavailable: $trackerCatalogError. No domains were imported."
                } else {
                    val activeDomains = catalog.filter { it.status == "active" }.flatMap { it.domains }.toSet()
                    if (activeDomains.isEmpty()) {
                        statusText.text = "The catalog has no active domain indicators to import. Review-only entries were left untouched."
                    } else {
                        val preview = activeDomains.sorted().take(18).joinToString("\n")
                        val omitted = (activeDomains.size - 18).coerceAtLeast(0)
                        val message = buildString {
                            append("This adds ").append(activeDomains.size).append(" active hostname rule(s) to the editor; it does not save or enable them.\n\n")
                            append("Blocking may break sign-in, analytics, ads, deep links, crash reporting, or other app features. A domain match does not identify the initiating app or prove personal data was sent.\n\n")
                            append(preview)
                            if (omitted > 0) append("\n… and ").append(omitted).append(" more")
                            append("\n\nReview the resulting rules and save only if you accept the possible breakage.")
                        }
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("Review tracker block rules")
                            .setMessage(message)
                            .setNegativeButton("Cancel", null)
                            .setPositiveButton("Add to editor") { _, _ ->
                                val currentDomains = domainsInput.text.toString().lineSequence()
                                    .map(String::trim).filter(String::isNotEmpty).toSet()
                                val newlyAdded = activeDomains - currentDomains
                                lastImportedTrackerDomains = newlyAdded
                                domainsInput.setText((currentDomains + activeDomains).sorted().joinToString("\n"))
                                statusText.text = if (newlyAdded.isEmpty()) {
                                    "All active tracker domains are already in the rule editor. No settings were saved."
                                } else {
                                    "Added ${newlyAdded.size} active domain indicator(s) to the editor only. Review rules and tap Save configuration to retain changes."
                                }
                            }
                            .show()
                    }
                }
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Undo last tracker import"
            setOnClickListener {
                if (lastImportedTrackerDomains.isEmpty()) {
                    statusText.text = "There are no newly added tracker domains to undo in this screen session."
                } else {
                    val currentDomains = domainsInput.text.toString().lineSequence()
                        .map(String::trim).filter(String::isNotEmpty).toSet()
                    val removed = currentDomains intersect lastImportedTrackerDomains
                    domainsInput.setText((currentDomains - lastImportedTrackerDomains).sorted().joinToString("\n"))
                    lastImportedTrackerDomains = emptySet()
                    statusText.text = "Removed ${removed.size} domain(s) added by the last tracker import from the editor. Save configuration only if the remaining rules are correct."
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
                showVpnPreflight()
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Stop DNS filtering"
            setOnClickListener {
                stopService(Intent(this@MainActivity, PrivacyDnsVpnService::class.java))
                statusText.text = "Stop requested. Waiting for the service lifecycle update."
            }
        }, matchWidth())
        vpnStateText = TextView(this).apply {
            text = "DNS filtering service state has not been refreshed."
            textSize = 13f
            setPadding(0, dp(8), 0, dp(4))
        }
        root.addView(vpnStateText, matchWidth())
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

        root.addView(TextView(this).apply {
            text = "DNS ROUTE DIAGNOSTICS"
            textSize = 16f
            setPadding(0, dp(18), 0, dp(4))
        })
        root.addView(TextView(this).apply {
            text = "Runs one user-triggered DNS A query for example.com through the configured protected upstream resolver. It does not save the query name to local DNS event history. Android's visible non-VPN network snapshot can identify validated or captive-portal states, but it does not prove which route every app uses."
            textSize = 12f
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Run DNS route diagnostic"
            setOnClickListener { runDnsRouteDiagnostic() }
        }, matchWidth())
        dnsDiagnosticText = TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(8), 0, dp(8))
            text = "No DNS route diagnostic has been run."
        }
        root.addView(dnsDiagnosticText, matchWidth())

        root.addView(CheckBox(this).apply {
            text = "Enable local DNS event history (saves queried hostnames on this device)"
            isChecked = prefs.getBoolean(LocalDnsEventHistory.KEY_ENABLED, false)
            setOnCheckedChangeListener { _, checked ->
                prefs.edit().putBoolean(LocalDnsEventHistory.KEY_ENABLED, checked).apply()
                if (!checked) {
                    statusText.text = "DNS event recording disabled. Existing local history remains until you clear it."
                } else {
                    statusText.text = "Local DNS event recording enabled. History is stored on this device and is not uploaded."
                }
            }
        }, matchWidth())
        val dnsEventHistoryText = TextView(this).apply {
            textSize = 12f
            setPadding(0, dp(8), 0, dp(8))
            text = "DNS event history is disabled. Enable it above to record hostnames."
        }
        root.addView(dnsEventHistoryText, matchWidth())
        root.addView(Button(this).apply {
            text = "Refresh local DNS event history"
            setOnClickListener {
                dnsEventHistoryText.text = if (prefs.getBoolean(LocalDnsEventHistory.KEY_ENABLED, false)) {
                    LocalDnsEventHistory.read(this@MainActivity).joinToString("\n\n").ifBlank { "No DNS events recorded yet." }
                } else {
                    "DNS event history is disabled. Existing entries are not displayed while recording is off."
                }
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Clear local DNS event history"
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Clear DNS history?")
                    .setMessage("This permanently clears the locally stored DNS event list. Aggregate counters are separate.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Clear history") { _, _ ->
                        LocalDnsEventHistory.clear(this@MainActivity)
                        dnsEventHistoryText.text = "Local DNS event history cleared."
                    }
                    .show()
            }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "PRIVACY AUDIT EXPORT"
            textSize = 16f
            setPadding(0, dp(20), 0, dp(4))
        })
        root.addView(TextView(this).apply {
            text = "Build a local JSON export from the saved DNS history only (at most 100 records). Select a date range and decisions, then review the redaction preview before saving. New recording is not enabled by this feature."
            textSize = 12f
        }, matchWidth())
        auditExportStartButton = Button(this).apply {
            text = "Start date (inclusive, local time): $auditExportStartDate"
            setOnClickListener { chooseAuditExportDate(startDate = true) }
        }
        root.addView(auditExportStartButton, matchWidth())
        auditExportEndButton = Button(this).apply {
            text = "End date (inclusive, local time): $auditExportEndDate"
            setOnClickListener { chooseAuditExportDate(startDate = false) }
        }
        root.addView(auditExportEndButton, matchWidth())
        auditExportBlockedCheck = CheckBox(this).apply {
            text = "Include blocked DNS decisions"
            isChecked = true
        }
        root.addView(auditExportBlockedCheck, matchWidth())
        auditExportForwardedCheck = CheckBox(this).apply {
            text = "Include forwarded DNS decisions"
            isChecked = true
        }
        root.addView(auditExportForwardedCheck, matchWidth())
        auditExportHostnamesCheck = CheckBox(this).apply {
            text = "Include raw queried hostnames (privacy-sensitive)"
            isChecked = false
        }
        root.addView(auditExportHostnamesCheck, matchWidth())
        auditExportSocketOwnerCheck = CheckBox(this).apply {
            text = "Include socket-owner labels (best-effort; may identify apps)"
            isChecked = false
        }
        root.addView(auditExportSocketOwnerCheck, matchWidth())
        root.addView(Button(this).apply {
            text = "Preview redacted audit export"
            setOnClickListener { previewLocalAuditExport() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Create signed audit checkpoint"
            setOnClickListener { previewSignedAuditCheckpoint() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Verify signed audit checkpoint"
            setOnClickListener { chooseAuditCheckpointForVerification() }
        }, matchWidth())

        root.addView(TextView(this).apply {
            text = "ENCRYPTED DEVICE SYNC"
            textSize = 16f
            setPadding(0, dp(20), 0, dp(4))
        })
        root.addView(TextView(this).apply {
            text = "Send only the selected DNS settings profile to a device you have explicitly verified. Private identity material and relay capabilities are encrypted at rest with Android Keystore. Relay metadata remains visible to the relay operator. This is an early Android integration; it does not sync every app setting."
            textSize = 13f
        })
        syncStatusText = TextView(this).apply {
            text = "No sync operation has been run."
            textSize = 12f
            setPadding(0, dp(8), 0, dp(8))
        }
        root.addView(syncStatusText, matchWidth())
        root.addView(Button(this).apply {
            text = "Create or validate local sync identity"
            setOnClickListener {
                runSyncTask(
                    progress = "Creating or validating the device identity...",
                    task = { encryptedSyncManager.createIdentity().toString() },
                    onSuccess = { cardJson ->
                        syncStatusText.text = "Device identity is protected locally. Review and copy the public card below."
                        showLocalDeviceCard(cardJson)
                    }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Show / copy my public device card"
            setOnClickListener {
                runSyncTask(
                    progress = "Loading the local device card...",
                    task = { encryptedSyncManager.localCardJson() },
                    onSuccess = { cardJson -> showLocalDeviceCard(cardJson) }
                )
            }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Peer public device card (paste from the other device)"
            setPadding(0, dp(12), 0, 0)
        })
        syncPeerCardInput = EditText(this).apply {
            hint = "Paste the complete public device card JSON"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            gravity = Gravity.TOP
            minLines = 3
            maxLines = 6
        }
        root.addView(syncPeerCardInput, matchWidth())
        root.addView(Button(this).apply {
            text = "Verify peer card and review fingerprint"
            setOnClickListener {
                val pastedCard = syncPeerCardInput.text.toString().trim()
                runSyncTask(
                    progress = "Validating the peer card cryptographically...",
                    task = { encryptedSyncManager.verifyPeerCard(pastedCard).toString() },
                    onSuccess = { verifiedCardJson ->
                        syncPeerCardInput.setText(verifiedCardJson)
                        showPeerTrustConfirmation(verifiedCardJson)
                    }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Manage / revoke trusted devices"
            setOnClickListener { showTrustedDeviceManager() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Create / update owner-signed device roster"
            setOnClickListener {
                runSyncTask(
                    progress = "Signing the roster with this device's protected identity...",
                    task = { encryptedSyncManager.createSignedDeviceRoster() },
                    onSuccess = { showSignedDeviceRoster(it) }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Rotate roster owner key"
            setOnClickListener { showOwnerKeyRotationPrompt() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Import owner-key rotation package"
            setOnClickListener { showOwnerKeyRotationImport() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Copy saved owner-key rotation package"
            setOnClickListener {
                runSyncTask(
                    progress = "Validating the saved owner transition and replacement roster...",
                    task = { encryptedSyncManager.lastOwnerKeyRotationPackage() },
                    onSuccess = { packageJson ->
                        getSystemService(ClipboardManager::class.java).setPrimaryClip(
                            ClipData.newPlainText("PrivaCage owner-key rotation", packageJson)
                        )
                        syncStatusText.text = "Last public owner-key rotation package copied. It remains stored in the protected local record. Distribute it through a trusted channel."
                    }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Confirm owner-key handoff complete"
            setOnClickListener { showOwnerKeyHandoffConfirmation() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Import owner-signed device roster"
            setOnClickListener { showSignedDeviceRosterImport() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Synchronize signed roster now"
            setOnClickListener {
                runSyncTask(
                    progress = "Fetching and verifying signed roster history...",
                    task = { encryptedSyncManager.syncSignedRosterFromRelay() }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "View roster-change history"
            setOnClickListener { showRosterChangeHistory() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Stage this device's key rotation"
            setOnClickListener { showLocalKeyRotation() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Import peer key-rotation request"
            setOnClickListener { showPeerKeyRotationImport() }
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Relay URL (HTTPS only)"
            setPadding(0, dp(12), 0, 0)
        })
        syncRelayUrlInput = EditText(this).apply {
            hint = "https://your-relay.example"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
        }
        root.addView(syncRelayUrlInput, matchWidth())
        root.addView(TextView(this).apply { text = "Relay space ID" })
        syncSpaceIdInput = EditText(this).apply {
            hint = "device-space-0001"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        root.addView(syncSpaceIdInput, matchWidth())
        root.addView(TextView(this).apply { text = "Relay capability (secret; saved encrypted)" })
        syncCapabilityInput = EditText(this).apply {
            hint = "64 lowercase hexadecimal characters"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        root.addView(syncCapabilityInput, matchWidth())
        root.addView(Button(this).apply {
            text = "Save HTTPS relay configuration"
            setOnClickListener {
                val url = syncRelayUrlInput.text.toString().trim()
                val space = syncSpaceIdInput.text.toString().trim()
                val capability = syncCapabilityInput.text.toString().trim()
                runSyncTask(
                    progress = "Validating and encrypting relay configuration...",
                    task = {
                        encryptedSyncManager.saveRelayConfiguration(url, space, capability)
                        "Relay configuration saved in the protected local record. Remote relays must use valid HTTPS."
                    }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Send current settings to trusted device"
            setOnClickListener {
                val profile = currentProfilePayload() ?: return@setOnClickListener
                val profileJson = String(profile, StandardCharsets.UTF_8)
                profile.fill(0)
                val recipientCard = syncPeerCardInput.text.toString().trim()
                runSyncTask(
                    progress = "Encrypting the settings profile and sending it to the relay...",
                    task = { encryptedSyncManager.sendProfile(profileJson, recipientCard) }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Check relay for received settings"
            setOnClickListener {
                runSyncTask(
                    progress = "Checking the encrypted inbox...",
                    task = {
                        val rosterStatus = encryptedSyncManager.syncSignedRosterFromRelay()
                        val received = encryptedSyncManager.receiveProfile { payload ->
                            val bytes = payload.toByteArray(StandardCharsets.UTF_8)
                            try {
                                parseProfilePayload(bytes)
                            } finally {
                                bytes.fill(0)
                            }
                        }
                        JSONObject()
                            .put("roster_sync_status", rosterStatus)
                            .put("status", received.status)
                            .put("message", received.message)
                            .put("profile_json", received.profileJson ?: JSONObject.NULL)
                            .put("sender_fingerprint", received.senderFingerprint ?: JSONObject.NULL)
                            .toString()
                    },
                    onSuccess = { resultJson ->
                        val result = JSONObject(resultJson)
                        syncStatusText.text = result.optString("roster_sync_status", "") + "\n" +
                            result.optString("message", "Sync receive operation finished.")
                        when (result.optString("status")) {
                            "pending" -> showReceivedProfile(
                                result.getString("profile_json"),
                                result.optString("sender_fingerprint", "")
                            )
                            "untrusted" -> syncStatusText.text = result.optString("message") +
                                "\nSender fingerprint: " + result.optString("sender_fingerprint") +
                                "\nObtain that device's public card through a separate trusted channel, verify the fingerprint, and trust it before retrying."
                        }
                    }
                )
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Export encrypted device recovery bundle"
            setOnClickListener { promptExportSyncRecoveryBundle() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Import device recovery bundle"
            setOnClickListener { chooseSyncRecoveryBundle() }
        }, matchWidth())

        statusText = TextView(this).apply {
            text = "Local actions and service messages appear here."
            setPadding(0, dp(12), 0, 0)
        }
        root.addView(statusText, matchWidth())
        refreshDnsStats()
        setContentView(ScrollView(this).apply { addView(root) })
        Thread({
            val loadedCatalog: List<TrackerSignature>?
            val loadError: String?
            try {
                loadedCatalog = TrackerSignatureCatalog.load(this@MainActivity)
                loadError = null
            } catch (exception: Exception) {
                loadedCatalog = null
                loadError = exception.message ?: exception.javaClass.simpleName
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                trackerCatalogLoading = false
                trackerCatalog = loadedCatalog
                trackerCatalogError = loadError
                trackerCatalogLoadFailure = loadError
                trackerCatalogLoadComplete = true
                apkTrackerCatalog = loadedCatalog.orEmpty()
                if (loadedCatalog == null) {
                    trackerCatalogStatus.text = "Catalog unavailable: $loadError. Manual domain rules still work."
                } else {
                    val active = loadedCatalog.count { it.status == "active" }
                    val review = loadedCatalog.count { it.status == "review" }
                    val retired = loadedCatalog.count { it.status == "retired" }
                    trackerCatalogStatus.text =
                        "Bundled records: ${loadedCatalog.size}; active: $active; review: $review; retired: $retired. Nothing is blocked until you import domains and save."
                }
            }
        }, "PrivaCage-tracker-catalog").start()
        syncStatusText.text = "Loading protected sync configuration locally… No network request is made."
        Thread({
            val savedSyncConfig: JSONObject?
            val loadError: String?
            try {
                savedSyncConfig = encryptedSyncManager.storedConfigurationForUi()
                loadError = null
            } catch (exception: Exception) {
                savedSyncConfig = null
                loadError = exception.message ?: "storage error"
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (loadError != null) {
                    syncStatusText.text =
                        "Could not load protected sync configuration: $loadError. No stored sync record was overwritten."
                } else if (savedSyncConfig == null) {
                    syncStatusText.text = "No local sync identity exists yet. Nothing has been uploaded."
                } else {
                    syncRelayUrlInput.setText(savedSyncConfig.optString("relay_url", ""))
                    syncSpaceIdInput.setText(savedSyncConfig.optString("space_id", ""))
                    syncCapabilityInput.setText(savedSyncConfig.optString("capability_token", ""))
                    syncStatusText.text = "Protected sync record loaded. Trusted devices: " +
                        savedSyncConfig.optInt("trusted_count", 0) + "; revoked fingerprints: " +
                        savedSyncConfig.optInt("revoked_count", 0) + ". No network request was made."
                }
            }
        }, "PrivaCage-sync-config").start()
        refreshDevicePrivacySnapshot()
    }

    private fun requireTrackerCatalogForApkAudit(): Boolean {
        if (!trackerCatalogLoadComplete) {
            statusText.text = "Tracker intelligence is still loading. Retry this APK audit in a moment so matching is not silently skipped."
            return false
        }
        trackerCatalogLoadFailure?.let { error ->
            statusText.text = "Tracker intelligence is unavailable: $error. APK tracker matching cannot be performed."
            return false
        }
        return true
    }

    private fun formatTrackerCatalogDetails(records: List<TrackerSignature>): String = buildString {
        append("CATALOG SUMMARY\n")
        append("Records: ").append(records.size)
        append(" | Active: ").append(records.count { it.status == "active" })
        append(" | Review-only: ").append(records.count { it.status == "review" })
        append(" | Retired: ").append(records.count { it.status == "retired" })
        append("\nA hostname match identifies a known endpoint indicator; it does not prove which app sent data, what a payload contained, or that collection completed. Review-only records are not included in bulk import.\n\n")
        append(records.joinToString("\n\n") { record ->
            buildString {
                append(record.name)
                append(" [")
                append(record.status.uppercase())
                append(", ")
                append(record.confidence)
                append(" confidence]\n")
                append("Category: ").append(record.category)
                append("\nDomains: ").append(record.domains.ifEmpty { listOf("none") }.joinToString(", "))
                append("\nSDK patterns: ").append(record.sdkPatterns.ifEmpty { listOf("none") }.joinToString(", "))
                append("\nLast verified: ").append(record.lastVerified)
                append("\nEvidence:\n")
                append(record.evidence.joinToString("\n") { source -> "${source.url}\n${source.description}" })
            }
        })
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(PrivacyDnsVpnService.ACTION_STATE_CHANGED).apply {
            addAction(PrivacyDnsVpnService.ACTION_DIAGNOSTIC_RESULT)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(vpnStateReceiver, filter)
        }
        vpnStateReceiverRegistered = true
        refreshVpnState()
    }

    override fun onStop() {
        if (vpnStateReceiverRegistered) {
            unregisterReceiver(vpnStateReceiver)
            vpnStateReceiverRegistered = false
        }
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        if (::statsText.isInitialized) refreshDnsStats()
        if (::devicePrivacyText.isInitialized) refreshDevicePrivacySnapshot()
        if (::vpnStateText.isInitialized) refreshVpnState()
        if (::dnsDiagnosticText.isInitialized) refreshDnsRouteDiagnostic()
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
            REQUEST_AUDIT_EXPORT -> writeLocalAuditExport(resultCode, data?.data)
            REQUEST_AUDIT_CHECKPOINT_VERIFY -> verifyAuditCheckpoint(resultCode, data?.data)
            REQUEST_IMPORT_FILE -> readEncryptedBackup(resultCode, data?.data)
            REQUEST_APK_AUDIT -> auditSelectedApk(resultCode, data?.data)
            REQUEST_APK_DIFF_BASELINE -> auditApkDiffBaseline(resultCode, data?.data)
            REQUEST_APK_DIFF_CANDIDATE -> auditApkDiffCandidate(resultCode, data?.data)
            REQUEST_METADATA_SCRUB_INPUT -> inspectSelectedMedia(resultCode, data?.data)
            REQUEST_METADATA_SCRUB_OUTPUT -> saveScrubbedMedia(resultCode, data?.data)
            REQUEST_SYNC_RECOVERY_EXPORT -> writeSyncRecoveryBundle(resultCode, data?.data)
            REQUEST_SYNC_RECOVERY_IMPORT -> readSyncRecoveryBundle(resultCode, data?.data)
        }
    }

    override fun onDestroy() {
        pendingEncryptedBackup?.fill(0)
        pendingEncryptedBackup = null
        pendingImportBackup?.fill(0)
        pendingImportBackup = null
        pendingAuditExport?.fill(0)
        pendingAuditExport = null
        pendingAuditExportFileName = null
        pendingAuditExportIsSignedCheckpoint = false
        pendingMetadataInput?.delete()
        pendingMetadataInput = null
        pendingScrubbedMedia?.delete()
        pendingScrubbedMedia = null
        pendingSyncRecoveryExport?.fill(0)
        pendingSyncRecoveryExport = null
        pendingSyncRecoveryImport?.fill(0)
        pendingSyncRecoveryImport = null
        super.onDestroy()
    }


    private fun <T : Any> runSyncTask(
        progress: String,
        task: () -> T,
        onSuccess: (T) -> Unit = { value -> syncStatusText.text = value.toString() }
    ) {
        syncStatusText.text = progress
        Thread({
            var result: T? = null
            var failure: Exception? = null
            try {
                result = task()
            } catch (exception: Exception) {
                failure = exception
            }
            val completed = result
            val error = failure
            runOnUiThread {
                if (isFinishing || isDestroyed) {
                    if (completed is ByteArray) completed.fill(0)
                    return@runOnUiThread
                }
                if (error != null) {
                    syncStatusText.text = "Sync operation failed: " + (error.message ?: error.javaClass.simpleName)
                } else if (completed != null) {
                    onSuccess(completed)
                }
            }
        }, "PrivaCage-encrypted-sync").start()
    }

    private fun showLocalDeviceCard(cardJson: String) {
        val card = try {
            JSONObject(cardJson)
        } catch (exception: Exception) {
            syncStatusText.text = "The device card could not be displayed because its JSON is invalid."
            return
        }
        val fingerprint = card.optString("fingerprint_sha256", "unavailable")
        AlertDialog.Builder(this)
            .setTitle("Public device card")
            .setMessage(
                "SHA-256 fingerprint:\n" + fingerprint +
                    "\n\nShare this public card with the other device. Before trusting another card, compare its complete fingerprint through a separate trusted channel. The card contains public keys, not your private identity material.\n\n" +
                    card.toString(2)
            )
            .setPositiveButton("Copy public card") { _, _ ->
                val clipboard = getSystemService(ClipboardManager::class.java)
                clipboard.setPrimaryClip(ClipData.newPlainText("PrivaCage public device card", card.toString()))
                syncStatusText.text = "Public device card copied. It contains public keys only; share it through a channel you trust."
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showPeerTrustConfirmation(cardJson: String) {
        val card = JSONObject(cardJson)
        val fingerprint = card.optString("fingerprint_sha256", "unavailable")
        val fingerprintInput = EditText(this).apply {
            hint = "Re-enter the full 64-character SHA-256 fingerprint"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
            addView(TextView(this@MainActivity).apply {
                text = "Device: " + card.optString("device_id") +
                    "\nKey epoch: " + card.optLong("key_epoch", 0L) +
                    "\n\nFull SHA-256 fingerprint:\n" + fingerprint +
                    "\n\nCompare every character with the device owner through a separate trusted channel, for example in person. A card received only from the relay is not sufficient."
                textSize = 14f
            }, matchWidth())
            addView(fingerprintInput, matchWidth())
        }
        AlertDialog.Builder(this)
            .setTitle("Verify this device fingerprint")
            .setMessage("Enter the fingerprint you independently compared. The device is not trusted unless the full fingerprint matches.")
            .setView(fields)
            .setPositiveButton("Confirm fingerprint and trust device") { _, _ ->
                val confirmedFingerprint = fingerprintInput.text.toString().trim().lowercase()
                if (confirmedFingerprint != fingerprint.lowercase()) {
                    syncStatusText.text = "Fingerprint mismatch. The device was not trusted. Compare the full fingerprint through a separate trusted channel."
                } else {
                    runSyncTask(
                        progress = "Saving the explicitly verified device card...",
                        task = { encryptedSyncManager.trustPeerCard(card.toString(), confirmedFingerprint) },
                        onSuccess = { savedFingerprint ->
                            syncStatusText.text = "Trusted device saved: " + savedFingerprint
                        }
                    )
                }
            }
            .setNegativeButton("Not now", null)
            .show()
    }

    private fun showTrustedDeviceManager() {
        runSyncTask(
            progress = "Loading explicitly trusted devices...",
            task = { encryptedSyncManager.listTrustedPeers().toString() },
            onSuccess = { peersJson ->
                val peers = JSONArray(peersJson)
                if (peers.length() == 0) {
                    syncStatusText.text = "No trusted devices remain. Revoked fingerprints stay locally denylisted until the full fingerprint is independently confirmed again."
                    return@runSyncTask
                }
                val labels = Array(peers.length()) { index ->
                    val peer = peers.getJSONObject(index)
                    val fingerprint = peer.optString("fingerprint_sha256")
                    peer.optString("device_id") +
                        " · epoch " + peer.optLong("key_epoch", 0L) +
                        "\nSHA-256: " + fingerprint
                }
                AlertDialog.Builder(this)
                    .setTitle("Trusted devices")
                    .setItems(labels) { _, index ->
                        val peer = peers.getJSONObject(index)
                        val fingerprint = peer.getString("fingerprint_sha256")
                        val deviceId = peer.optString("device_id")
                        AlertDialog.Builder(this)
                            .setTitle("Revoke this device?")
                            .setMessage(
                                "Device: " + deviceId +
                                    "\n\nThis removes its trust on this device, deny-lists its fingerprint, and discards any pending profile from it. Future packets from this fingerprint will be skipped.\n\nThis does not erase data already copied to that device and does not revoke the shared relay capability. If that capability may be compromised, rotate it using the relay administrator credentials; that invalidates access for every device until the remaining devices are reconfigured."
                            )
                            .setNegativeButton("Cancel", null)
                            .setNeutralButton("Revoke trust + relay access") { _, _ ->
                                showRelayAdminRevocationPrompt(fingerprint, deviceId)
                            }
                            .setPositiveButton("Revoke trust locally") { _, _ ->
                                runSyncTask(
                                    progress = "Revoking local trust and dropping pending data...",
                                    task = { encryptedSyncManager.revokeTrustedPeerAndPublishRoster(fingerprint) },
                                    onSuccess = { status -> syncStatusText.text = status }
                                )
                            }
                            .show()
                    }
                    .setPositiveButton("Close", null)
                    .show()
            }
        )
    }


    private fun showRelayAdminRevocationPrompt(fingerprint: String, deviceId: String) {
        val adminTokenInput = EditText(this).apply {
            hint = "Relay administrator token"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Revoke lost device at relay?")
            .setMessage(
                "Target device: $deviceId\n\nEnter the relay administrator token to revoke this fingerprint's per-device relay credential. The app requests the token for this operation only and does not save it. The relay's per-device member mode must already be active; if it is not, remote revocation fails closed because the legacy shared capability would remain usable. Local trust revocation is still attempted even if remote revocation fails."
            )
            .setView(adminTokenInput)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Revoke device") { _, _ ->
                val adminToken = adminTokenInput.text.toString()
                adminTokenInput.text.clear()
                if (!SyncRelayClient.isValidAdminToken(adminToken)) {
                    syncStatusText.text = "No relay request was sent. The administrator token must be 32–4096 printable ASCII characters without whitespace. You can still use 'Revoke trust locally'."
                    return@setPositiveButton
                }
                runSyncTask(
                    progress = "Revoking relay credential first, then updating local trust...",
                    task = { encryptedSyncManager.revokeLostDevice(fingerprint, adminToken) },
                    onSuccess = { status -> syncStatusText.text = status }
                )
            }
            .show()
    }

    private fun showSignedDeviceRoster(rosterJson: String) {
        val roster = try {
            JSONObject(rosterJson)
        } catch (_: Exception) {
            syncStatusText.text = "Signed roster was created but could not be displayed."
            return
        }
        val unsigned = roster.optJSONObject("unsigned")
        val ownerFingerprint = unsigned?.optJSONObject("owner_card")?.optString("fingerprint_sha256") ?: "unavailable"
        val revision = unsigned?.optLong("revision", 0L) ?: 0L
        AlertDialog.Builder(this)
            .setTitle("Owner-signed device roster · revision " + revision)
            .setMessage(
                "Owner fingerprint:\n" + ownerFingerprint +
                    "\n\nShare the complete signed JSON with each trusted device. Before first import on a device, compare the full owner fingerprint through a separate trusted channel. A signature does not make an unverified owner key trustworthy.\n\n" +
                    rosterJson
            )
            .setPositiveButton("Copy signed roster") { _, _ ->
                val clipboard = getSystemService(ClipboardManager::class.java)
                clipboard.setPrimaryClip(ClipData.newPlainText("PrivaCage signed device roster", rosterJson))
                syncStatusText.text = "Signed roster revision " + revision +
                    " copied. Import it on every trusted device; revocation takes effect there only after importing a newer revision."
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showOwnerKeyRotationPrompt() {
        AlertDialog.Builder(this)
            .setTitle("Rotate roster owner key?")
            .setMessage(
                "This operation replaces this installation's owner identity with a new key epoch and signs a transition with both the current and replacement keys. It binds the exact relay space and current roster revision, then creates the next owner-signed roster. The replacement private identity stays in this device's encrypted local record and is never included in the package.\n\nShare the public package with every trusted device. Each device must independently confirm the new full fingerprint through a separate trusted channel before it changes its pinned owner. This does not rotate relay credentials or revoke the old key at the relay."
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Generate owner transition") { _, _ ->
                runSyncTask(
                    progress = "Creating the next owner identity, dual-signed transition and replacement roster...",
                    task = { encryptedSyncManager.rotateRosterOwnerKey() },
                    onSuccess = { result -> showOwnerKeyRotationPackage(result) }
                )
            }
            .show()
    }

    private fun showOwnerKeyRotationPackage(result: OwnerRotationResult) {
        val packageJson = result.packageJson
        val message = buildString {
            append("Previous owner fingerprint:\n").append(result.previousFingerprint).append("\n\n")
            append("Replacement owner fingerprint:\n").append(result.nextFingerprint).append("\n\n")
            append("New roster revision: ").append(result.rosterRevision).append('\n')
            append(result.publicationMessage).append("\n\n")
            append("The public package contains both signatures and the new signed roster. It contains no private key or recovery bundle. A copy is retained in this installation's protected local record so it can be copied again after the dialog closes. Every device must verify this transition and independently confirm the replacement fingerprint before pinning it.\n\n")
            append(packageJson)
        }
        AlertDialog.Builder(this)
            .setTitle("Owner-key rotation package")
            .setMessage(message)
            .setPositiveButton("Copy public package") { _, _ ->
                getSystemService(ClipboardManager::class.java).setPrimaryClip(
                    ClipData.newPlainText("PrivaCage owner-key rotation", packageJson)
                )
                syncStatusText.text = result.publicationMessage + " Public owner-key rotation package copied; distribute it over a trusted channel."
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showOwnerKeyHandoffConfirmation() {
        val fingerprintInput = EditText(this).apply {
            hint = "Re-enter this installation's full owner SHA-256 fingerprint"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Confirm owner-key handoff?")
            .setMessage(
                "Only confirm after every intended trusted device has received the saved owner-key rotation package, independently verified the new full fingerprint, and accepted the exact next signed roster. This is an explicit local acknowledgement; the app cannot remotely prove every peer completed the handoff. Until you confirm, another owner-key rotation is blocked. The last public package remains saved for re-copying after confirmation."
            )
            .setView(fingerprintInput)
            .setNegativeButton("Not yet", null)
            .setPositiveButton("Confirm all intended devices updated") { _, _ ->
                val fingerprint = fingerprintInput.text.toString().trim().lowercase()
                runSyncTask(
                    progress = "Verifying the local owner fingerprint and closing the handoff gate...",
                    task = { encryptedSyncManager.confirmOwnerKeyRotationHandoff(fingerprint) }
                )
            }
            .show()
    }

    private fun showOwnerKeyRotationImport() {
        val packageInput = EditText(this).apply {
            hint = "Paste the complete owner-key rotation package JSON"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            gravity = Gravity.TOP
            minLines = 6
            maxLines = 14
        }
        val fingerprintInput = EditText(this).apply {
            hint = "Independently confirmed new owner SHA-256 fingerprint"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
            addView(TextView(this@MainActivity).apply {
                text = "The transition must be signed by both the currently pinned owner key and the replacement key, and the signed roster must be exactly the next revision in the same relay space. Compare the complete new fingerprint through a separate trusted channel; do not accept a key based only on a package received from the relay."
                textSize = 14f
            }, matchWidth())
            addView(fingerprintInput, matchWidth())
            addView(packageInput, matchWidth())
        }
        AlertDialog.Builder(this)
            .setTitle("Verify owner-key rotation")
            .setView(fields)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Verify and update owner pin") { _, _ ->
                val packageJson = packageInput.text.toString().trim()
                val confirmedFingerprint = fingerprintInput.text.toString().trim().lowercase()
                runSyncTask(
                    progress = "Checking the previous owner pin, both signatures, revision linkage, fingerprint and new roster...",
                    task = {
                        encryptedSyncManager.importOwnerKeyRotationPackage(packageJson, confirmedFingerprint)
                    }
                )
            }
            .show()
    }

    private fun showSignedDeviceRosterImport() {
        val rosterInput = EditText(this).apply {
            hint = "Paste the complete signed roster JSON"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            gravity = Gravity.TOP
            minLines = 5
            maxLines = 10
        }
        val ownerFingerprintInput = EditText(this).apply {
            hint = "Independently confirmed 64-character owner fingerprint"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
            addView(TextView(this@MainActivity).apply {
                text = "Compare the owner fingerprint with the owner through a separate trusted channel. Import replaces this device's peer roster, and older revisions are rejected."
                textSize = 14f
            }, matchWidth())
            addView(ownerFingerprintInput, matchWidth())
            addView(rosterInput, matchWidth())
        }
        AlertDialog.Builder(this)
            .setTitle("Import signed device roster")
            .setView(fields)
            .setPositiveButton("Verify and import") { _, _ ->
                val rosterJson = rosterInput.text.toString().trim()
                val ownerFingerprint = ownerFingerprintInput.text.toString().trim().lowercase()
                runSyncTask(
                    progress = "Verifying owner signature, fingerprint pin, membership and revision...",
                    task = { encryptedSyncManager.importSignedDeviceRoster(rosterJson, ownerFingerprint) }
                )
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showRosterChangeHistory() {
        runSyncTask(
            progress = "Loading encrypted local roster-change history...",
            task = { encryptedSyncManager.rosterChangeHistory().toString() },
            onSuccess = { historyJson ->
                val history = JSONArray(historyJson)
                if (history.length() == 0) {
                    syncStatusText.text = "No roster lifecycle events have been recorded on this installation yet."
                    return@runSyncTask
                }
                val lines = (history.length() - 1 downTo 0).map { index ->
                    val event = history.getJSONObject(index)
                    val fingerprint = event.optString("device_fingerprint", "")
                        .takeUnless { it == "null" || it.isBlank() } ?: "—"
                    "#" + event.optLong("timestamp_unix", 0L) +
                        " · " + event.optString("type") +
                        " · rev " + event.optLong("roster_revision", 0L) +
                        "\n" + fingerprint +
                        "\n" + event.optString("detail")
                }
                AlertDialog.Builder(this)
                    .setTitle("Roster-change history · newest first")
                    .setMessage(lines.joinToString("\n\n"))
                    .setPositiveButton("Close", null)
                    .show()
            }
        )
    }

    private fun showLocalKeyRotation() {
        AlertDialog.Builder(this)
            .setTitle("Stage peer key rotation?")
            .setMessage(
                "This creates a new device identity and a transition signed by the current key, but keeps the current identity active. The roster owner must import the public rotation package and publish a newer signed roster authorizing the replacement. This workflow does not rotate the roster-owner key. The encrypted replacement private identity stays in this device's protected record and is never included in the copied package."
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Stage rotation") { _, _ ->
                runSyncTask(
                    progress = "Generating a replacement key and signed transition...",
                    task = { encryptedSyncManager.stageLocalKeyRotation() },
                    onSuccess = { showStagedKeyRotation(it) }
                )
            }
            .show()
    }

    private fun showStagedKeyRotation(packageJson: String) {
        AlertDialog.Builder(this)
            .setTitle("Key rotation staged")
            .setMessage(
                "Copy this public rotation package to the roster owner. It contains the previous public card, replacement public card, and transition signed by the previous key; it contains no private key or recovery bundle. The old identity remains active until a valid owner-signed roster authorizes the replacement.\n\n" +
                    packageJson
            )
            .setPositiveButton("Copy rotation package") { _, _ ->
                getSystemService(ClipboardManager::class.java).setPrimaryClip(
                    ClipData.newPlainText("PrivaCage peer key rotation", packageJson)
                )
                syncStatusText.text = "Public rotation package copied. Send it to the pinned roster owner through a trusted channel."
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showPeerKeyRotationImport() {
        val rotationInput = EditText(this).apply {
            hint = "Paste the complete public key-rotation package JSON"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            gravity = Gravity.TOP
            minLines = 5
            maxLines = 12
        }
        AlertDialog.Builder(this)
            .setTitle("Verify peer key rotation")
            .setMessage(
                "The current roster owner verifies the transition using the exact currently trusted predecessor card. Importing adds the replacement card while retaining the predecessor temporarily. The owner then publishes a signed roster; after the replacement activates, revoke the old peer and separately manage its relay credential."
            )
            .setView(rotationInput)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Verify and accept") { _, _ ->
                val packageJson = rotationInput.text.toString().trim()
                runSyncTask(
                    progress = "Verifying previous-key signature, epoch and trusted predecessor...",
                    task = { encryptedSyncManager.acceptPeerKeyRotation(packageJson) }
                )
            }
            .show()
    }

    private fun showReceivedProfile(profileJson: String, senderFingerprint: String) {
        val profileBytes = profileJson.toByteArray(StandardCharsets.UTF_8)
        val imported = try {
            parseProfilePayload(profileBytes)
        } catch (exception: Exception) {
            syncStatusText.text = "Received profile did not pass local validation. It was not applied."
            return
        } finally {
            profileBytes.fill(0)
        }
        val dnsTlsSummary = if (imported.dnsOverTlsEnabled) {
            "enabled (" + imported.dnsOverTlsHostname + ")"
        } else {
            "disabled"
        }
        val message = "Trusted sender fingerprint:\n" + senderFingerprint +
            "\n\nResolver: " + imported.resolverIpv4 +
            "\nBlocked domain rules: " + imported.blockedDomains.size +
            "\nDNS-over-TLS: " + dnsTlsSummary +
            "\n\nApplying replaces the saved resolver and domain rules. It does not start or restart DNS filtering. Review the settings before continuing."
        AlertDialog.Builder(this)
            .setTitle("Review received settings")
            .setMessage(message)
            .setPositiveButton("Apply these settings") { _, _ ->
                getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE).edit()
                    .putString(PrivacyDnsVpnService.KEY_RESOLVER_IP, imported.resolverIpv4)
                    .putStringSet(PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS, imported.blockedDomains.toSet())
                    .putBoolean(PrivacyDnsVpnService.KEY_DOT_ENABLED, imported.dnsOverTlsEnabled)
                    .putString(PrivacyDnsVpnService.KEY_DOT_HOSTNAME, imported.dnsOverTlsHostname)
                    .apply()
                resolverInput.setText(imported.resolverIpv4)
                domainsInput.setText(imported.blockedDomains.sorted().joinToString("\n"))
                dnsOverTlsInput.isChecked = imported.dnsOverTlsEnabled
                resolverHostnameInput.setText(imported.dnsOverTlsHostname)
                statusText.text = "Received DNS profile applied to local settings. Restart active DNS filtering to apply it."
                runSyncTask(
                    progress = "Finalizing local receive history...",
                    task = {
                        encryptedSyncManager.clearPendingProfile()
                        "Received profile applied. The encrypted pending copy was cleared."
                    }
                )
            }
            .setNegativeButton("Keep pending", null)
            .show()
    }

    private fun promptExportSyncRecoveryBundle() {
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        val passphraseInput = EditText(this).apply {
            hint = "Recovery passphrase (12+ characters)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        val confirmInput = EditText(this).apply {
            hint = "Confirm recovery passphrase"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        fields.addView(passphraseInput, matchWidth())
        fields.addView(confirmInput, matchWidth())
        AlertDialog.Builder(this)
            .setTitle("Create device recovery bundle")
            .setMessage(
                "This bundle can restore the device's private sync identity. Use a strong unique passphrase and keep both the file and passphrase offline and separate. Never upload the recovery bundle to the sync relay."
            )
            .setView(fields)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Encrypt recovery bundle") { _, _ ->
                val passphrase = passphraseInput.text.toString()
                val confirmation = confirmInput.text.toString()
                passphraseInput.text.clear()
                confirmInput.text.clear()
                if (passphrase.length < AndroidEncryptedSyncManager.RECOVERY_PASSPHRASE_MIN_LENGTH) {
                    syncStatusText.text = "Recovery passphrase must be at least " +
                        AndroidEncryptedSyncManager.RECOVERY_PASSPHRASE_MIN_LENGTH + " characters."
                } else if (passphrase != confirmation) {
                    syncStatusText.text = "Recovery passphrases did not match. No file was created."
                } else {
                    runSyncTask(
                        progress = "Encrypting the portable device recovery bundle...",
                        task = { encryptedSyncManager.exportRecoveryBundle(passphrase) },
                        onSuccess = { bundle ->
                            pendingSyncRecoveryExport?.fill(0)
                            pendingSyncRecoveryExport = bundle
                            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                                addCategory(Intent.CATEGORY_OPENABLE)
                                type = "application/octet-stream"
                                putExtra(Intent.EXTRA_TITLE, "privacage-device-recovery.pcage-sync")
                            }
                            startActivityForResult(intent, REQUEST_SYNC_RECOVERY_EXPORT)
                            syncStatusText.text = "Choose a local/offline destination for the encrypted recovery file."
                        }
                    )
                }
            }
            .show()
    }

    private fun writeSyncRecoveryBundle(resultCode: Int, uri: Uri?) {
        val bundle = pendingSyncRecoveryExport
        pendingSyncRecoveryExport = null
        if (resultCode != RESULT_OK || uri == null) {
            bundle?.fill(0)
            syncStatusText.text = "Recovery export cancelled; no file was saved."
            return
        }
        try {
            val bytes = bundle ?: throw IOException("Encrypted recovery bytes are missing.")
            val output = contentResolver.openOutputStream(uri)
                ?: throw IOException("The chosen recovery destination could not be opened.")
            output.use {
                it.write(bytes)
                it.flush()
            }
            syncStatusText.text = "Encrypted recovery bundle saved. Keep its passphrase separate; never upload this file to the relay."
        } catch (exception: Exception) {
            syncStatusText.text = "Could not save recovery bundle: " + (exception.message ?: "file write failed")
        } finally {
            bundle?.fill(0)
        }
    }

    private fun chooseSyncRecoveryBundle() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
        }
        startActivityForResult(intent, REQUEST_SYNC_RECOVERY_IMPORT)
    }

    private fun readSyncRecoveryBundle(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            syncStatusText.text = "Recovery import cancelled; current identity was not changed."
            return
        }
        try {
            val input = contentResolver.openInputStream(uri)
                ?: throw IOException("The selected recovery file could not be opened.")
            val bundle = input.use { readLimited(it, 1_100_000) }
            if (bundle.isEmpty()) {
                bundle.fill(0)
                throw IOException("The selected recovery file is empty.")
            }
            pendingSyncRecoveryImport?.fill(0)
            pendingSyncRecoveryImport = bundle
            promptImportSyncRecoveryPassphrase()
        } catch (exception: Exception) {
            pendingSyncRecoveryImport?.fill(0)
            pendingSyncRecoveryImport = null
            syncStatusText.text = "Could not read recovery file: " + (exception.message ?: "invalid file")
        }
    }

    private fun promptImportSyncRecoveryPassphrase() {
        val passphraseInput = EditText(this).apply {
            hint = "Recovery passphrase"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Restore device identity")
            .setMessage("The recovery file is authenticated before any local identity is replaced. Import resets this device's relay settings and trusted-device list.")
            .setView(passphraseInput)
            .setNegativeButton("Cancel") { _, _ ->
                pendingSyncRecoveryImport?.fill(0)
                pendingSyncRecoveryImport = null
                syncStatusText.text = "Recovery import cancelled; current identity was not changed."
            }
            .setPositiveButton("Decrypt and review identity") { _, _ ->
                val passphrase = passphraseInput.text.toString()
                passphraseInput.text.clear()
                val fileBytes = pendingSyncRecoveryImport
                pendingSyncRecoveryImport = null
                if (fileBytes == null) {
                    syncStatusText.text = "Recovery import failed: no recovery file is available."
                } else {
                    runSyncTask(
                        progress = "Authenticating the recovery bundle...",
                        task = {
                            try {
                                encryptedSyncManager.prepareRecoveryImport(fileBytes, passphrase)
                            } finally {
                                fileBytes.fill(0)
                            }
                        },
                        onSuccess = { importedRecord -> showRecoveryReplacementConfirmation(importedRecord) }
                    )
                }
            }
            .setOnCancelListener {
                pendingSyncRecoveryImport?.fill(0)
                pendingSyncRecoveryImport = null
            }
            .show()
    }

    private fun showRecoveryReplacementConfirmation(importedRecord: JSONObject) {
        val newCard = JSONObject(importedRecord.getString("card_json"))
        val fingerprint = newCard.optString("fingerprint_sha256", "unavailable")
        AlertDialog.Builder(this)
            .setTitle("Restore sync identity from recovery?")
            .setMessage(
                "The recovery file was authenticated. Restored identity fingerprint:\n" + fingerprint +
                    "\n\nThis restores the same long-term cryptographic identity from the recovery bundle; it does not create a new device identity or revoke the original installation. Confirming replaces this device's stored sync record and clears its relay configuration, trusted-device list, revoked-fingerprint list, inbox cursor and pending receive. If the original device may be lost or compromised, separately revoke its trust on other devices and rotate the shared relay capability with the relay administrator. Rotation affects every device using that capability."
            )
            .setNegativeButton("Keep existing identity", null)
            .setPositiveButton("Replace and protect locally") { _, _ ->
                runSyncTask(
                    progress = "Installing the recovered identity...",
                    task = {
                        encryptedSyncManager.commitRecoveryImport(importedRecord)
                        importedRecord.getString("card_json")
                    },
                    onSuccess = { cardJson ->
                        syncRelayUrlInput.text.clear()
                        syncSpaceIdInput.text.clear()
                        syncCapabilityInput.text.clear()
                        syncPeerCardInput.text.clear()
                        syncStatusText.text = "Recovered identity installed. Configure the relay and explicitly re-trust peers."
                        showLocalDeviceCard(cardJson)
                    }
                )
            }
            .show()
    }

    private fun refreshDevicePrivacySnapshot() {
        devicePrivacyText.text = DevicePrivacySnapshot.capture(this).render()
    }

    private fun chooseMetadataFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "image/*"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/jpeg", "image/png", "image/webp"))
        }
        startActivityForResult(intent, REQUEST_METADATA_SCRUB_INPUT)
    }

    private fun inspectSelectedMedia(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            statusText.text = "Image metadata inspection cancelled."
            return
        }
        pendingMetadataInput?.delete()
        pendingMetadataInput = null
        pendingScrubbedMedia?.delete()
        pendingScrubbedMedia = null
        statusText.text = "Inspecting the selected image locally. No network request is made."
        Thread({
            var staged: File? = null
            try {
                staged = stageSelectedMedia(uri)
                val inspection = metadataScrubber.inspect(staged)
                val inspectedFile = staged
                staged = null
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        pendingMetadataInput = inspectedFile
                        showMetadataInspection(inspectedFile, inspection)
                    } else {
                        inspectedFile.delete()
                    }
                }
            } catch (exception: Exception) {
                val message = exception.message ?: "The selected file could not be inspected safely."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        statusText.text = "Image metadata inspection failed: " + message
                    }
                }
            } finally {
                staged?.delete()
            }
        }, "PrivaCage-metadata-inspect").start()
    }

    private fun showMetadataInspection(input: File, report: NativeMetadataReport) {
        val limitations = report.warnings.joinToString(separator = "\n- ", prefix = "\n\nLimits:\n- ")
        val message = buildString {
            append("Format: ").append(report.format.uppercase()).append("\n")
            append("Input size: ").append(report.inputBytes).append(" bytes\n\n")
            append(report.removedSummary())
            if (report.metadataSegmentsRemoved == 0L) {
                append("\n\nNo metadata entries recognized by this parser were found.")
            } else {
                append("\n\nThese recognized entries can be removed without recompressing image pixels.")
            }
            append("\n\nThe original file will remain unchanged.")
            append(limitations)
        }
        AlertDialog.Builder(this)
            .setTitle("Image metadata inspection")
            .setMessage(message)
            .setNegativeButton("Cancel") { _, _ ->
                if (pendingMetadataInput == input) pendingMetadataInput = null
                input.delete()
                statusText.text = "Inspection cancelled. The selected original was not changed."
            }
            .setPositiveButton("Create cleaned copy") { _, _ ->
                if (pendingMetadataInput == input) pendingMetadataInput = null
                createScrubbedMedia(input, report.format)
            }
            .setOnCancelListener {
                if (pendingMetadataInput == input) pendingMetadataInput = null
                input.delete()
                statusText.text = "Inspection dismissed. Temporary input copy deleted."
            }
            .show()
    }

    private fun createScrubbedMedia(input: File, format: String) {
        val extension = metadataExtension(format)
        val mimeType = metadataMimeType(format)
        statusText.text = "Removing recognized metadata in the Rust core and re-checking the output..."
        Thread({
            var cleaned: File? = null
            try {
                cleaned = File.createTempFile("privacage-cleaned-", ".$extension", cacheDir)
                val result = metadataScrubber.scrub(input, cleaned)
                val verification = metadataScrubber.inspect(cleaned)
                if (verification.format != format || verification.metadataSegmentsRemoved != 0L ||
                    verification.outputBytes != cleaned.length()
                ) {
                    throw IOException("The cleaned image did not pass the second metadata inspection.")
                }
                val completedFile = cleaned
                cleaned = null
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        pendingScrubbedMedia = completedFile
                        pendingScrubbedMediaExtension = extension
                        pendingScrubbedMediaMime = mimeType
                        showScrubbedMediaReport(result, verification)
                    } else {
                        completedFile.delete()
                    }
                }
            } catch (exception: Exception) {
                val message = exception.message ?: "The image could not be safely scrubbed."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        statusText.text = "Metadata removal failed: " + message + ". The original was not modified."
                    }
                }
            } finally {
                input.delete()
                cleaned?.delete()
            }
        }, "PrivaCage-metadata-scrub").start()
    }

    private fun showScrubbedMediaReport(
        removed: NativeMetadataReport,
        verification: NativeMetadataReport
    ) {
        val extension = pendingScrubbedMediaExtension ?: metadataExtension(removed.format)
        val mimeType = pendingScrubbedMediaMime ?: metadataMimeType(removed.format)
        val message = buildString {
            append("Format: ").append(removed.format.uppercase()).append("\n")
            append("Input: ").append(removed.inputBytes).append(" bytes\n")
            append("Cleaned copy: ").append(removed.outputBytes).append(" bytes\n\n")
            append(removed.removedSummary())
            append("\n\nVerification: a second Rust parser pass found zero remaining recognized metadata entries.")
            if (verification.metadataSegmentsRemoved != 0L) {
                append("\nVerification failed; this copy must not be saved.")
            }
            removed.warnings.forEach { append("\n\nLIMITATION: ").append(it) }
            append("\n\nThis removes recognized container metadata only. It does not hide identifying details visible in the image pixels.")
        }
        statusText.text = "Image processed locally. Review the metadata report before saving."
        AlertDialog.Builder(this)
            .setTitle("Cleaned image report")
            .setMessage(message)
            .setNegativeButton("Discard cleaned copy") { _, _ ->
                pendingScrubbedMedia?.delete()
                pendingScrubbedMedia = null
                pendingScrubbedMediaExtension = null
                pendingScrubbedMediaMime = null
                statusText.text = "Cleaned copy discarded. The original file was not changed."
            }
            .setPositiveButton("Save cleaned copy") { _, _ ->
                val saveIntent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = mimeType
                    putExtra(Intent.EXTRA_TITLE, "privacage-cleaned.$extension")
                }
                startActivityForResult(saveIntent, REQUEST_METADATA_SCRUB_OUTPUT)
            }
            .setOnCancelListener {
                pendingScrubbedMedia?.delete()
                pendingScrubbedMedia = null
                pendingScrubbedMediaExtension = null
                pendingScrubbedMediaMime = null
                statusText.text = "Report dismissed. The temporary cleaned copy was deleted."
            }
            .show()
    }

    private fun metadataExtension(format: String): String = when (format) {
        "jpeg" -> "jpg"
        "png" -> "png"
        "webp" -> "webp"
        else -> throw IOException("Unsupported image format returned by the metadata core.")
    }

    private fun metadataMimeType(format: String): String = when (format) {
        "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "webp" -> "image/webp"
        else -> throw IOException("Unsupported image format returned by the metadata core.")
    }

    private fun stageSelectedMedia(uri: Uri): File {
        val staged = File.createTempFile("privacage-metadata-input-", ".bin", cacheDir)
        val buffer = ByteArray(8_192)
        var totalBytes = 0L
        try {
            val source = contentResolver.openInputStream(uri)
                ?: throw IOException("The selected image could not be opened.")
            source.use { input ->
                FileOutputStream(staged).use { output ->
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        if (totalBytes > NativeMetadataScrubber.DEFAULT_MAX_BYTES - count) {
                            throw IOException("Selected file exceeds the 100 MiB local processing limit.")
                        }
                        output.write(buffer, 0, count)
                        totalBytes += count
                    }
                    output.flush()
                }
            }
            if (totalBytes == 0L) throw IOException("The selected file is empty.")
            return staged
        } catch (exception: Exception) {
            staged.delete()
            throw exception
        } finally {
            buffer.fill(0)
        }
    }

    private fun saveScrubbedMedia(resultCode: Int, uri: Uri?) {
        val cleaned = pendingScrubbedMedia
        pendingScrubbedMedia = null
        pendingScrubbedMediaExtension = null
        pendingScrubbedMediaMime = null
        if (resultCode != RESULT_OK || uri == null) {
            cleaned?.delete()
            statusText.text = "Cleaned image was not saved; temporary output deleted."
            return
        }
        if (cleaned == null || !cleaned.isFile) {
            statusText.text = "Cleaned image is no longer available; inspect and scrub the file again."
            return
        }
        statusText.text = "Saving the verified cleaned image locally."
        Thread({
            val buffer = ByteArray(8_192)
            try {
                val destination = contentResolver.openOutputStream(uri, "w")
                    ?: throw IOException("The chosen destination could not be opened.")
                destination.use { output ->
                    cleaned.inputStream().use { input ->
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (count > 0) output.write(buffer, 0, count)
                        }
                    }
                    output.flush()
                }
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        statusText.text = "Verified cleaned image saved. The selected original was never modified."
                    }
                }
            } catch (exception: Exception) {
                val message = exception.message ?: "The cleaned image could not be saved."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) statusText.text = "Saving cleaned image failed: " + message
                }
            } finally {
                buffer.fill(0)
                cleaned.delete()
            }
        }, "PrivaCage-metadata-save").start()
    }

    private fun apkPickerIntent(): Intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
        addCategory(Intent.CATEGORY_OPENABLE)
        type = "*/*"
        putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/vnd.android.package-archive"))
    }

    private fun chooseApkForAudit() {
        startActivityForResult(apkPickerIntent(), REQUEST_APK_AUDIT)
    }

    private fun chooseApkForDiffBaseline() {
        pendingApkDiffBaseline = null
        startActivityForResult(apkPickerIntent(), REQUEST_APK_DIFF_BASELINE)
    }

    private fun chooseApkForDiffCandidate() {
        if (pendingApkDiffBaseline == null) {
            statusText.text = "The baseline report is no longer available. Start the comparison again."
            return
        }
        startActivityForResult(apkPickerIntent(), REQUEST_APK_DIFF_CANDIDATE)
    }

    private fun auditApkDiffBaseline(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            pendingApkDiffBaseline = null
            statusText.text = "APK comparison cancelled; no file was installed or uploaded."
            return
        }

        if (!requireTrackerCatalogForApkAudit()) return

        pendingApkDiffBaseline = null
        statusText.text = "Scanning the baseline APK locally. It will not be installed or uploaded."
        Thread({
            var stagedApk: File? = null
            try {
                stagedApk = stageSelectedApk(uri)
                val report = ApkManifestAuditor(packageManager).inspect(stagedApk, apkTrackerCatalog)
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        pendingApkDiffBaseline = report
                        AlertDialog.Builder(this)
                            .setTitle("Baseline APK scanned")
                            .setMessage(
                                "Package: " + report.packageName +
                                    "\nVersion: " + (report.versionName ?: "unknown") +
                                    " (code " + report.versionCode + ")" +
                                    "\nAPK SHA-256: " + report.sha256 +
                                    "\n\nSelect the candidate version of this same package. Both APKs are inspected locally."
                            )
                            .setNegativeButton("Cancel comparison") { _, _ ->
                                pendingApkDiffBaseline = null
                                statusText.text = "APK comparison cancelled; baseline report discarded."
                            }
                            .setPositiveButton("Choose candidate APK") { _, _ ->
                                chooseApkForDiffCandidate()
                            }
                            .setOnCancelListener {
                                pendingApkDiffBaseline = null
                                statusText.text = "APK comparison cancelled; baseline report discarded."
                            }
                            .show()
                    }
                }
            } catch (exception: Exception) {
                val failure = exception.message ?: "The baseline APK could not be inspected."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        pendingApkDiffBaseline = null
                        statusText.text = "APK comparison failed: " + failure + " No file was installed or uploaded."
                    }
                }
            } finally {
                stagedApk?.delete()
            }
        }, "PrivaCage-APK-diff-baseline").start()
    }

    private fun auditApkDiffCandidate(resultCode: Int, uri: Uri?) {
        val baseline = pendingApkDiffBaseline
        if (resultCode != RESULT_OK || uri == null) {
            pendingApkDiffBaseline = null
            statusText.text = "APK comparison cancelled; the baseline report was discarded."
            return
        }
        if (baseline == null) {
            statusText.text = "The baseline report is no longer available. Start the comparison again."
            return
        }
        if (!requireTrackerCatalogForApkAudit()) {
            pendingApkDiffBaseline = null
            return
        }

        pendingApkDiffBaseline = null
        statusText.text = "Scanning the candidate APK and comparing static privacy indicators locally..."
        Thread({
            var stagedApk: File? = null
            try {
                stagedApk = stageSelectedApk(uri)
                val candidate = ApkManifestAuditor(packageManager).inspect(stagedApk, apkTrackerCatalog)
                val diff = ApkPrivacyDiff.compare(baseline, candidate, trackerCatalogSha256())
                val summary = formatApkPrivacyDiffReport(diff)
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        apkAuditText.text = summary
                        apkAuditText.visibility = android.view.View.VISIBLE
                        statusText.text = "APK comparison finished locally. Both temporary APK copies were deleted."
                    }
                }
            } catch (exception: Exception) {
                val failure = exception.message ?: "The candidate APK could not be compared."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        statusText.text = "APK comparison failed: " + failure + " Both APKs remained uninstalled and were not uploaded."
                    }
                }
            } finally {
                stagedApk?.delete()
            }
        }, "PrivaCage-APK-diff-candidate").start()
    }

    private fun trackerCatalogSha256(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8_192)
        try {
            assets.open("signatures.json").use { input ->
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    digest.update(buffer, 0, count)
                }
            }
        } finally {
            buffer.fill(0)
        }

        val hexDigits = "0123456789abcdef"
        return buildString(64) {
            digest.digest().forEach { byte ->
                val value = byte.toInt() and 0xff
                append(hexDigits[value ushr 4])
                append(hexDigits[value and 0x0f])
            }
        }
    }

    private fun auditSelectedApk(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            statusText.text = "APK inspection cancelled; no file was installed or uploaded."
            return
        }

        if (!requireTrackerCatalogForApkAudit()) return

        statusText.text = "Inspecting the selected APK locally. It will not be installed or executed."
        Thread({
            var stagedApk: File? = null
            try {
                stagedApk = stageSelectedApk(uri)
                val report = ApkManifestAuditor(packageManager).inspect(stagedApk, apkTrackerCatalog)
                val summary = formatApkAuditReport(report)
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        apkAuditText.text = summary
                        apkAuditText.visibility = android.view.View.VISIBLE
                        statusText.text = "APK manifest inspection finished locally. The temporary copy was deleted."
                    }
                }
            } catch (exception: Exception) {
                val failure = exception.message ?: "The selected APK could not be inspected."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        statusText.text = "APK inspection failed: $failure No file was installed or uploaded."
                    }
                }
            } finally {
                stagedApk?.delete()
            }
        }, "PrivaCage-APK-audit").start()
    }

    private fun stageSelectedApk(uri: Uri): File {
        val staged = File.createTempFile("privacage-apk-audit-", ".apk", cacheDir)
        val buffer = ByteArray(8_192)
        var totalBytes = 0L
        try {
            val source = contentResolver.openInputStream(uri)
                ?: throw IOException("The selected document could not be opened.")
            source.use { input ->
                FileOutputStream(staged).use { output ->
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        if (totalBytes > ApkManifestAuditor.MAX_APK_BYTES.toLong() - count) {
                            throw IOException("APK exceeds the 100 MiB local inspection limit.")
                        }
                        output.write(buffer, 0, count)
                        totalBytes += count
                    }
                    output.flush()
                }
            }
            if (totalBytes == 0L) throw IOException("The selected file is empty.")
            return staged
        } catch (exception: Exception) {
            staged.delete()
            throw exception
        } finally {
            buffer.fill(0)
        }
    }

    private fun formatApkAuditReport(report: ApkManifestAuditReport): String = buildString {
        append("OFFLINE STATIC MANIFEST REVIEW\n")
        append("Package: ").append(report.packageName).append('\n')
        append("Version: ").append(report.versionName ?: "unknown")
            .append(" (code ").append(report.versionCode).append(")\n")
        append("Target SDK: ").append(report.targetSdkVersion ?: "unknown").append('\n')
        append("File size: ").append(report.fileSizeBytes).append(" bytes\n")
        append("APK SHA-256: ").append(report.sha256).append('\n')
        append("Current signing certificate SHA-256 fingerprints:")
        if (report.signingCertificateSha256.isEmpty()) {
            append(" unavailable (unsigned APK or Android did not expose signer metadata)")
        } else {
            report.signingCertificateSha256.forEach { append("\n  ").append(it) }
        }
        append("\n\nAPK signature verification: ").append(report.signatureVerification.status.name)
        append("\nThis checks cryptographic signature integrity, not whether the publisher or app is trustworthy.")
        report.signatureVerification.errors.forEach { append("\n  ERROR: ").append(it) }
        report.signatureVerification.warnings.forEach { append("\n  WARNING: ").append(it) }
        append("\n\n")

        append("Declared permissions (").append(report.permissions.size).append("):")
        if (report.permissions.isEmpty()) append("\nNo requested manifest permissions were declared.")
        else {
            report.permissions.take(MAX_AUDIT_ITEMS_TO_DISPLAY).forEach { finding ->
                append("\n[").append(finding.review.category.displayName).append("] ")
                    .append(finding.permissionName)
                append("\n  ").append(finding.review.explanation)
            }
            if (report.permissions.size > MAX_AUDIT_ITEMS_TO_DISPLAY) {
                append("\n… ").append(report.permissions.size - MAX_AUDIT_ITEMS_TO_DISPLAY)
                    .append(" additional permissions omitted from this view.")
            }
        }

        append("\n\nExported components (").append(report.exportedComponents.size).append("):")
        if (report.exportedComponents.isEmpty()) append("\nNo components marked exported were reported by Android's package parser.")
        else {
            report.exportedComponents.take(MAX_AUDIT_ITEMS_TO_DISPLAY).forEach { component ->
                append("\n[").append(component.kind).append("] ").append(component.className)
                    .append(" — enabled=").append(component.enabled)
                    .append(", required permission=").append(component.requiredPermission ?: "none")
            }
            if (report.exportedComponents.size > MAX_AUDIT_ITEMS_TO_DISPLAY) {
                append("\n… ").append(report.exportedComponents.size - MAX_AUDIT_ITEMS_TO_DISPLAY)
                    .append(" additional exported components omitted from this view.")
            }
        }

        append("\n\nPossible embedded catalog indicators found in DEX strings (")
            .append(report.trackerScan.findings.size).append("):")
        append("\nCatalog markers considered: ").append(report.trackerScan.indicatorsConsidered)
        append("\nDEX files scanned: ").append(report.trackerScan.dexFilesScanned)
        append("\nDEX bytes scanned: ").append(report.trackerScan.dexBytesScanned)
        if (report.trackerScan.findings.isEmpty()) {
            append("\nNo catalog indicator strings were found in scanned DEX data. This does not prove their absence.")
        } else {
            report.trackerScan.findings.take(MAX_AUDIT_ITEMS_TO_DISPLAY).forEach { finding ->
                append("\n[").append(finding.status.uppercase()).append(", ")
                    .append(finding.confidence).append(" confidence] ")
                    .append(finding.recordName).append(" — ").append(finding.indicatorType)
                    .append(": ").append(finding.indicator)
                append("\n  DEX entry: ").append(finding.dexEntries.joinToString(", "))
                if (finding.evidenceUrls.isNotEmpty()) {
                    append("\n  Evidence: ").append(finding.evidenceUrls.take(2).joinToString(", "))
                }
            }
            if (report.trackerScan.findings.size > MAX_AUDIT_ITEMS_TO_DISPLAY) {
                append("\n… ").append(report.trackerScan.findings.size - MAX_AUDIT_ITEMS_TO_DISPLAY)
                    .append(" additional indicator findings omitted from this view.")
            }
        }
        if (report.trackerScan.warnings.isNotEmpty()) {
            append("\n\nScan coverage warnings:")
            report.trackerScan.warnings.forEach { append("\n• ").append(it) }
        }

        append("\n\nLIMITS: These are declarations and embedded strings, not proof of permission grants,")
        append(" runtime execution, network connections, transmitted data, or malicious intent.")
        append(" Obfuscation, native code, encryption, and dynamic loading can evade static string scans.")
        append(" Exported components may be intentional; review their purpose and guards.")
    }

    private fun formatApkPrivacyDiffReport(diff: ApkPrivacyDiffReport): String = buildString {
        val baseline = diff.baseline
        val candidate = diff.candidate
        append("LOCAL STATIC APK PRIVACY DIFF\n")
        append("Package: ").append(baseline.packageName).append('\n')
        append("Baseline version: ").append(baseline.versionName ?: "unknown")
            .append(" (code ").append(baseline.versionCode).append(")\n")
        append("Candidate version: ").append(candidate.versionName ?: "unknown")
            .append(" (code ").append(candidate.versionCode).append(")\n")
        if (candidate.versionCode < baseline.versionCode) {
            append("WARNING: the candidate version code is lower than the baseline. Verify which file is the intended update.\n")
        }
        append("Baseline APK SHA-256: ").append(baseline.sha256).append('\n')
        append("Candidate APK SHA-256: ").append(candidate.sha256).append('\n')
        append("Bundled tracker catalog SHA-256: ").append(diff.trackerCatalogSha256).append('\n')
        append("Target SDK: ").append(baseline.targetSdkVersion ?: "unknown")
            .append(" -> ").append(candidate.targetSdkVersion ?: "unknown").append('\n')
        append("APK signature verification: baseline ").append(baseline.signatureVerification.status.name)
            .append(", candidate ").append(candidate.signatureVerification.status.name).append('\n')
        append("Signing certificate fingerprints: ")
            .append(if (baseline.signingCertificateSha256 == candidate.signingCertificateSha256) "unchanged" else "CHANGED")
        if (baseline.signingCertificateSha256 != candidate.signingCertificateSha256) {
            append("\nWARNING: signing fingerprints differ. Rotation can be legitimate, but independently verify the publisher before installing an APK.")
        }
        appendDiffSection(this, "Declared permissions added", diff.addedPermissions.map {
            "[" + it.review.category.displayName + "] " + it.permissionName
        })
        appendDiffSection(this, "Declared permissions removed", diff.removedPermissions.map {
            "[" + it.review.category.displayName + "] " + it.permissionName
        })
        appendDiffSection(this, "Exported components added", diff.addedExportedComponents.map {
            it.kind + ": " + it.className + " (enabled=" + it.enabled +
                ", required permission=" + (it.requiredPermission ?: "none") + ")"
        })
        appendDiffSection(this, "Exported components removed", diff.removedExportedComponents.map {
            it.kind + ": " + it.className + " (enabled=" + it.enabled +
                ", required permission=" + (it.requiredPermission ?: "none") + ")"
        })
        appendDiffSection(this, "Exported components changed", diff.changedExportedComponents.map { change ->
            change.before.kind + ": " + change.before.className +
                " — enabled " + change.before.enabled + " -> " + change.after.enabled +
                "; required permission " + (change.before.requiredPermission ?: "none") +
                " -> " + (change.after.requiredPermission ?: "none")
        })
        appendDiffSection(this, "Embedded catalog indicators added", diff.addedTrackerIndicators.map {
            it.recordName + " [" + it.status + "] — " + it.indicatorType + ": " + it.indicator +
                " (DEX: " + it.dexEntries.joinToString(", ") + ")"
        })
        appendDiffSection(this, "Embedded catalog indicators no longer found", diff.removedTrackerIndicators.map {
            it.recordName + " [" + it.status + "] — " + it.indicatorType + ": " + it.indicator +
                " (was in DEX: " + it.dexEntries.joinToString(", ") + ")"
        })
        appendDiffSection(this, "Embedded catalog indicators changed", diff.changedTrackerIndicators.map { change ->
            change.before.recordName + " — " + change.before.indicatorType + ": " + change.before.indicator +
                "; status " + change.before.status + " -> " + change.after.status +
                "; DEX entries " + change.before.dexEntries.joinToString(", ") +
                " -> " + change.after.dexEntries.joinToString(", ")
        })
        val signatureIssues = buildList {
            baseline.signatureVerification.errors.take(5).forEach { add("baseline error: " + it) }
            candidate.signatureVerification.errors.take(5).forEach { add("candidate error: " + it) }
            baseline.signatureVerification.warnings.take(5).forEach { add("baseline warning: " + it) }
            candidate.signatureVerification.warnings.take(5).forEach { add("candidate warning: " + it) }
        }
        appendDiffSection(this, "APK signature verifier details", signatureIssues)
        val coverageWarnings = buildList {
            baseline.trackerScan.warnings.forEach { add("baseline: " + it) }
            candidate.trackerScan.warnings.forEach { add("candidate: " + it) }
        }
        appendDiffSection(this, "Static scan coverage warnings", coverageWarnings)
        append("\n\nLIMITS: This comparison reports changes in manifest declarations and literal catalog strings found in bounded DEX scans. It does not prove SDK execution, network activity, data collection, safety, or malicious intent. No APK was installed or uploaded. Obfuscation, native code, encrypted strings, dynamic loading, split APKs, and bounded scan coverage can hide changes.")
    }

    private fun appendDiffSection(output: StringBuilder, title: String, items: List<String>) {
        output.append("\n\n").append(title).append(" (").append(items.size).append("):")
        if (items.isEmpty()) {
            output.append("\nNone.")
            return
        }
        items.take(MAX_AUDIT_ITEMS_TO_DISPLAY).forEach { output.append("\n• ").append(it) }
        if (items.size > MAX_AUDIT_ITEMS_TO_DISPLAY) {
            output.append("\n… ").append(items.size - MAX_AUDIT_ITEMS_TO_DISPLAY)
                .append(" additional items omitted from this view.")
        }
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

    private fun chooseAuditExportDate(startDate: Boolean) {
        val current = if (startDate) auditExportStartDate else auditExportEndDate
        DatePickerDialog(
            this,
            { _, year, month, day ->
                val selected = LocalDate.of(year, month + 1, day)
                if (startDate) {
                    auditExportStartDate = selected
                    auditExportStartButton.text = "Start date (inclusive, local time): $selected"
                } else {
                    auditExportEndDate = selected
                    auditExportEndButton.text = "End date (inclusive, local time): $selected"
                }
            },
            current.year,
            current.monthValue - 1,
            current.dayOfMonth
        ).show()
    }

    private fun prepareLocalAuditExport(): AuditExportResult? {
        val categories = buildSet {
            if (auditExportBlockedCheck.isChecked) add("BLOCKED")
            if (auditExportForwardedCheck.isChecked) add("FORWARDED")
        }
        return try {
            LocalAuditExporter.prepare(
                events = LocalDnsEventHistory.readForExport(this),
                request = AuditExportRequest(
                    startDate = auditExportStartDate,
                    endDate = auditExportEndDate,
                    categories = categories,
                    includeHostnames = auditExportHostnamesCheck.isChecked,
                    includeSocketOwnerLabels = auditExportSocketOwnerCheck.isChecked
                )
            )
        } catch (exception: Exception) {
            statusText.text = "Could not prepare audit export: " + (exception.message ?: exception.javaClass.simpleName)
            null
        }
    }

    private fun previewLocalAuditExport() {
        val prepared = prepareLocalAuditExport() ?: return
        pendingAuditExport?.fill(0)
        pendingAuditExport = prepared.json.toByteArray(StandardCharsets.UTF_8)
        pendingAuditExportFileName = "privacage-audit-" + LocalDate.now() + ".json"
        pendingAuditExportIsSignedCheckpoint = false
        showAuditExportPreview("Review audit export", prepared.previewText)
    }

    private fun previewSignedAuditCheckpoint() {
        val prepared = prepareLocalAuditExport() ?: return
        try {
            val checkpoint = LocalAuditCheckpointSigner.sign(
                context = this,
                payloadJson = prepared.json,
                chainHeadSha256 = prepared.chainHeadSha256,
                eventCount = prepared.eventCount
            )
            pendingAuditExport?.fill(0)
            pendingAuditExport = checkpoint.json.toByteArray(StandardCharsets.UTF_8)
            pendingAuditExportFileName = "privacage-audit-checkpoint-" + LocalDate.now() + ".json"
            pendingAuditExportIsSignedCheckpoint = true
            val message = prepared.previewText +
                "\n\nSIGNED CHECKPOINT\n" +
                "Signature: ECDSA with SHA-256\n" +
                "Signer public-key SHA-256: " + checkpoint.publicKeySha256 + "\n" +
                "Payload SHA-256: " + checkpoint.payloadSha256 + "\n" +
                "Chain head SHA-256: " + prepared.chainHeadSha256 + "\n\n" +
                "The private key is kept in Android Keystore and is not included in the file. Hardware-backed storage is not guaranteed. This file is not encrypted, the creation time is from the device clock, and the embedded public key does not identify a person. Keep a copy of the fingerprint through a separate trusted channel if you need to recognize this signer later."
            showAuditExportPreview("Review signed audit checkpoint", message)
        } catch (exception: Exception) {
            pendingAuditExport?.fill(0)
            pendingAuditExport = null
            pendingAuditExportFileName = null
            pendingAuditExportIsSignedCheckpoint = false
            statusText.text = "Could not sign audit checkpoint: " + (exception.message ?: exception.javaClass.simpleName)
        }
    }

    private fun showAuditExportPreview(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setNegativeButton("Cancel and discard") { _, _ ->
                pendingAuditExport?.fill(0)
                pendingAuditExport = null
                pendingAuditExportFileName = null
                pendingAuditExportIsSignedCheckpoint = false
                statusText.text = "Audit export discarded; no file was saved."
            }
            .setPositiveButton("Choose save location") { _, _ ->
                chooseAuditExportDestination()
            }
            .setOnCancelListener {
                pendingAuditExport?.fill(0)
                pendingAuditExport = null
                pendingAuditExportFileName = null
                pendingAuditExportIsSignedCheckpoint = false
                statusText.text = "Audit export discarded; no file was saved."
            }
            .show()
    }

    private fun chooseAuditExportDestination() {
        if (pendingAuditExport == null) {
            statusText.text = "The audit export is no longer available. Preview it again."
            return
        }
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, pendingAuditExportFileName ?: ("privacage-audit-" + LocalDate.now() + ".json"))
        }
        try {
            startActivityForResult(intent, REQUEST_AUDIT_EXPORT)
        } catch (exception: Exception) {
            pendingAuditExport?.fill(0)
            pendingAuditExport = null
            statusText.text = "Could not open Android's save picker. The export was discarded."
        }
    }

    private fun writeLocalAuditExport(resultCode: Int, uri: Uri?) {
        val bytes = pendingAuditExport
        val signedCheckpoint = pendingAuditExportIsSignedCheckpoint
        pendingAuditExport = null
        pendingAuditExportFileName = null
        pendingAuditExportIsSignedCheckpoint = false
        if (resultCode != RESULT_OK || uri == null) {
            bytes?.fill(0)
            statusText.text = "Audit export cancelled; no file was saved."
            return
        }
        try {
            val content = bytes ?: throw IOException("The prepared audit export is missing.")
            val output = contentResolver.openOutputStream(uri)
                ?: throw IOException("The chosen destination could not be opened.")
            output.use { stream ->
                stream.write(content)
                stream.flush()
            }
            statusText.text = if (signedCheckpoint) {
                "Signed audit checkpoint saved. It is not encrypted; retain the signer fingerprint separately if you need to trust this key later."
            } else {
                "Audit export saved. The JSON is unencrypted; check the destination and any cloud-sync behavior."
            }
        } catch (exception: Exception) {
            statusText.text = "Could not write the audit export. Choose a writable destination and preview again."
        } finally {
            bytes?.fill(0)
        }
    }

    private fun chooseAuditCheckpointForVerification() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
        }
        try {
            startActivityForResult(intent, REQUEST_AUDIT_CHECKPOINT_VERIFY)
        } catch (exception: Exception) {
            statusText.text = "Could not open the checkpoint picker."
        }
    }

    private fun verifyAuditCheckpoint(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            statusText.text = "Checkpoint verification cancelled."
            return
        }
        statusText.text = "Verifying checkpoint signature, payload digest and event chain locally..."
        Thread({
            var bytes: ByteArray? = null
            var message: String
            try {
                val input = contentResolver.openInputStream(uri)
                    ?: throw IOException("The selected checkpoint could not be opened.")
                bytes = input.use { readLimited(it, MAX_AUDIT_CHECKPOINT_BYTES) }
                message = LocalAuditCheckpointSigner.verify(
                    this,
                    String(bytes ?: throw IOException("Checkpoint bytes are missing."), StandardCharsets.UTF_8)
                ).render()
            } catch (exception: Exception) {
                message = "Checkpoint verification failed: " + (exception.message ?: exception.javaClass.simpleName)
            } finally {
                bytes?.fill(0)
            }
            runOnUiThread {
                if (!isFinishing && !isDestroyed) statusText.text = message
            }
        }, "PrivaCage-audit-checkpoint-verify").start()
    }

    private fun refreshDnsStats() {
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        statsText.text = buildString {
            append("Current/last VPN session aggregate totals (separate from optional local event history):\n")
            append("Blocked replies prepared: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_BLOCKED, 0L))
            append("\nUpstream replies prepared: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_FORWARDED, 0L))
            append("\nUnsupported or malformed packets: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_UNSUPPORTED, 0L))
            append("\nUpstream failures/timeouts: ")
            append(prefs.getLong(PrivacyDnsVpnService.KEY_STATS_UPSTREAM_FAILURES, 0L))
            append("\nActive-session counts update in batches and flush again when the tunnel stops.")
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
        val useDot = dnsOverTlsInput.isChecked
        val tlsHostname = if (useDot) try {
            DnsOverTlsForwarder.validateHostname(resolverHostnameInput.text.toString())
        } catch (exception: IllegalArgumentException) {
            statusText.text = exception.message ?: "Enter a valid DNS-over-TLS certificate hostname."; return null
        } else ""
        val json = JSONObject()
            .put("format_version", PROFILE_FORMAT_VERSION)
            .put("resolver_ipv4", resolver)
            .put("blocked_domains", JSONArray(domains.sorted()))
            .put("dns_over_tls_enabled", useDot)
            .put("dns_over_tls_hostname", tlsHostname)
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
                        .putBoolean(PrivacyDnsVpnService.KEY_DOT_ENABLED, imported.dnsOverTlsEnabled)
                        .putString(PrivacyDnsVpnService.KEY_DOT_HOSTNAME, imported.dnsOverTlsHostname)
                        .apply()
                    resolverInput.setText(imported.resolverIpv4)
                    domainsInput.setText(imported.blockedDomains.sorted().joinToString("\n"))
                    dnsOverTlsInput.isChecked = imported.dnsOverTlsEnabled
                    resolverHostnameInput.setText(imported.dnsOverTlsHostname)
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
        val version = json.opt("format_version")
        if (version !is Number || version.toInt() !in 1..PROFILE_FORMAT_VERSION || version.toDouble() != version.toInt().toDouble()) throw IOException("Unsupported profile format version")
        val expectedKeys = if (version.toInt() == 1) setOf("format_version", "resolver_ipv4", "blocked_domains") else setOf("format_version", "resolver_ipv4", "blocked_domains", "dns_over_tls_enabled", "dns_over_tls_hostname")
        if (actualKeys != expectedKeys) throw IOException("Profile fields do not match the supported format")
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
        val useDot = if (version.toInt() == 1) false else (json.opt("dns_over_tls_enabled") as? Boolean ?: throw IOException("Profile DNS-over-TLS flag is invalid"))
        var tlsHostname = if (version.toInt() == 1) "" else (json.opt("dns_over_tls_hostname") as? String ?: throw IOException("Profile DNS-over-TLS hostname is invalid"))
        if (tlsHostname.isNotEmpty() || useDot) tlsHostname = try { DnsOverTlsForwarder.validateHostname(tlsHostname) } catch (exception: IllegalArgumentException) { throw IOException("Profile DNS-over-TLS hostname is invalid", exception) }
        return ImportedProfile(resolver, domains, useDot, tlsHostname)
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

    private data class ImportedProfile(val resolverIpv4: String, val blockedDomains: List<String>, val dnsOverTlsEnabled: Boolean, val dnsOverTlsHostname: String)

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
        val useDot = dnsOverTlsInput.isChecked
        val tlsHostname = if (useDot) try {
            DnsOverTlsForwarder.validateHostname(resolverHostnameInput.text.toString())
        } catch (exception: IllegalArgumentException) {
            statusText.text = exception.message ?: "Enter a valid DNS-over-TLS certificate hostname."; return false
        } else ""
        getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE).edit()
            .putString(PrivacyDnsVpnService.KEY_RESOLVER_IP, resolver)
            .putStringSet(PrivacyDnsVpnService.KEY_BLOCKED_DOMAINS, domains)
            .putBoolean(PrivacyDnsVpnService.KEY_DOT_ENABLED, useDot)
            .putString(PrivacyDnsVpnService.KEY_DOT_HOSTNAME, tlsHostname)
            .apply()
        return true
    }

    private fun openExternalUrl(url: String, label: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            statusText.text = "Opened official $label. Review and change settings on that service's own page."
        } catch (exception: Exception) {
            statusText.text = "Could not open $label. Open it manually from the official provider's settings or website."
        }
    }

    private fun openSystemSettings(action: String, label: String) {
        try { startActivity(Intent(action)); statusText.text = "Opened Android $label. Changes are controlled by Android Settings." }
        catch (exception: Exception) { statusText.text = "This Android build does not expose the $label shortcut. Open it manually in Settings." }
    }

    private fun showVpnPreflight() {
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        val upstreamDescription = if (prefs.getBoolean(PrivacyDnsVpnService.KEY_DOT_ENABLED, false)) {
            "DNS-over-TLS is enabled. PrivaCage verifies the configured certificate hostname and drops queries if TLS fails; the selected resolver can still see the DNS names."
        } else {
            "Plain upstream DNS is selected. Queries from PrivaCage to the resolver are not encrypted."
        }
        val message = buildString {
            append("Starting PrivaCage may disconnect the VPN you currently use. Android allows only one active VPN service per user/profile.\n\n")
            append("Coverage is deliberately narrow: only IPv4 UDP DNS packets addressed to PrivaCage's virtual DNS endpoint are routed here. This is not a full-device VPN. DNS-over-TCP from apps, IPv6 DNS, DNS-over-HTTPS, DNS-over-QUIC, HTTPS contents, and OS/OEM telemetry are outside this implementation. Other DNS paths may bypass these rules.\n\n")
            append(upstreamDescription)
            append("\n\nContinue to Android's VPN permission step?")
        }
        AlertDialog.Builder(this)
            .setTitle("Before enabling DNS filtering")
            .setMessage(message)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Continue") { _, _ -> requestVpnPermissionAndStart() }
            .show()
    }

    private fun requestVpnPermissionAndStart() {
        val consent = VpnService.prepare(this)
        if (consent == null) {
            startVpnService()
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN_PERMISSION)
        }
    }

    private fun refreshVpnState() {
        if (!::vpnStateText.isInitialized) return
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        val snapshot = VpnSessionStatus.resolve(
            state = prefs.getString(VpnSessionStatus.KEY_STATE, null),
            message = prefs.getString(VpnSessionStatus.KEY_MESSAGE, null),
            processId = prefs.getString(VpnSessionStatus.KEY_PROCESS_ID, null),
            currentProcessId = PrivacyDnsVpnService.PROCESS_SESSION_ID
        )
        vpnStateText.text = buildString {
            append("PrivaCage DNS service: ").append(snapshot.state.uppercase()).append("\n")
            append(snapshot.message)
            if (snapshot.stale) {
                append("\n\nA prior app process recorded this state, so it is treated as stopped.")
            }
            append("\n\nCoverage note: this status reflects PrivaCage's own service lifecycle only. It does not prove every DNS route or every app is filtered.")
        }
    }

    private fun runDnsRouteDiagnostic() {
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        val session = VpnSessionStatus.resolve(
            state = prefs.getString(VpnSessionStatus.KEY_STATE, null),
            message = prefs.getString(VpnSessionStatus.KEY_MESSAGE, null),
            processId = prefs.getString(VpnSessionStatus.KEY_PROCESS_ID, null),
            currentProcessId = PrivacyDnsVpnService.PROCESS_SESSION_ID
        )
        if (session.state != VpnSessionStatus.STATE_ACTIVE) {
            dnsDiagnosticText.text = "Cannot test the configured resolver path until PrivaCage DNS filtering is active. Enable filtering, confirm the service reports ACTIVE, then run the diagnostic."
            return
        }
        if (prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_STATUS, "") == "running") {
            dnsDiagnosticText.text = "A DNS route diagnostic is already running."
            return
        }
        dnsDiagnosticText.text = "Running one DNS A query for example.com through the configured upstream. Sampling Android-visible network and captive-portal state before and after the query..."
        try {
            startService(
                Intent(this, PrivacyDnsVpnService::class.java)
                    .setAction(PrivacyDnsVpnService.ACTION_RUN_DIAGNOSTIC)
            )
            statusText.text = "DNS route diagnostic started. The query name is not added to local DNS event history."
        } catch (exception: Exception) {
            dnsDiagnosticText.text = "Could not request the DNS route diagnostic (${exception.javaClass.simpleName}). No result is available."
        }
    }

    private fun refreshDnsRouteDiagnostic() {
        if (!::dnsDiagnosticText.isInitialized) return
        val prefs = getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, MODE_PRIVATE)
        val state = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_STATUS, "").orEmpty()
        if (state.isBlank()) {
            dnsDiagnosticText.text = "No DNS route diagnostic has been run. Tap Run DNS route diagnostic while the PrivaCage service is ACTIVE. The fixed probe is example.com (A); raw DNS packets are not saved."
            return
        }
        val startReport = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_NETWORK_START, "").orEmpty()
        val endReport = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_NETWORK_END, "").orEmpty()
        val message = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_MESSAGE, "No diagnostic message was recorded.").orEmpty()
        dnsDiagnosticText.text = buildString {
            append("Status: ")
            append(
                when (state) {
                    "running" -> "RUNNING"
                    "success" -> "RESOLVED"
                    "response_only" -> "RESPONDER REACHED; LOOKUP NOT RESOLVED"
                    else -> "FAILED"
                }
            )
            append("\n").append(message)
            val started = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_STARTED_AT, "").orEmpty()
            val completed = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_COMPLETED_AT, "").orEmpty()
            if (started.isNotBlank()) append("\nStarted: ").append(started)
            if (completed.isNotBlank()) append("\nCompleted: ").append(completed)
            if (state != "running" && prefs.getBoolean(PrivacyDnsVpnService.KEY_DIAGNOSTIC_RESPONSE_RECEIVED, false)) {
                append("\nLatency: ").append(prefs.getLong(PrivacyDnsVpnService.KEY_DIAGNOSTIC_LATENCY_MILLIS, 0L)).append(" ms")
                val code = prefs.getInt(PrivacyDnsVpnService.KEY_DIAGNOSTIC_RESPONSE_CODE, -1)
                if (code >= 0) append("\nDNS response code: ").append(code)
                val answers = prefs.getInt(PrivacyDnsVpnService.KEY_DIAGNOSTIC_ANSWER_COUNT, -1)
                if (answers >= 0) append("\nAnswer records: ").append(answers)
            }
            if (startReport.isNotBlank()) append("\n\nNetwork snapshot at probe start:\n").append(startReport)
            if (endReport.isNotBlank()) append("\n\nNetwork snapshot at probe completion:\n").append(endReport)
            if (prefs.getBoolean(PrivacyDnsVpnService.KEY_DIAGNOSTIC_NETWORK_CHANGED, false)) {
                append("\n\nWarning: Android-visible non-VPN network state changed during the probe. Repeat the test after the connection settles.")
            } else if (state != "running" && endReport.isNotBlank()) {
                val current = DnsNetworkSnapshot.capture(this@MainActivity)
                val previousSignature = prefs.getString(PrivacyDnsVpnService.KEY_DIAGNOSTIC_NETWORK_END_SIGNATURE, "").orEmpty()
                if (previousSignature.isNotBlank() && current.fingerprint != previousSignature) {
                    append("\n\nThe current network snapshot differs from the last probe. Rerun the diagnostic for the current connection.")
                }
            }
            append("\n\nScope: this tests one fixed A query and the configured upstream only. Network snapshots do not prove every app's route, and IPv6 DNS, DNS-over-TCP from apps, DoH and DoQ remain outside the current filter.")
            append("\nNo query history is added by this diagnostic.")
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PrivacyDnsVpnService::class.java).setAction(PrivacyDnsVpnService.ACTION_START)
        startForegroundService(intent)
        statusText.text = "Start requested. Waiting for the service to establish the virtual DNS interface."
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
        private const val REQUEST_APK_AUDIT = 4110
        private const val REQUEST_APK_DIFF_BASELINE = 4115
        private const val REQUEST_APK_DIFF_CANDIDATE = 4116
        private const val REQUEST_AUDIT_EXPORT = 4117
        private const val REQUEST_AUDIT_CHECKPOINT_VERIFY = 4118
        private const val MAX_AUDIT_CHECKPOINT_BYTES = 512 * 1024
        private const val REQUEST_METADATA_SCRUB_INPUT = 4111
        private const val REQUEST_METADATA_SCRUB_OUTPUT = 4112
        private const val REQUEST_SYNC_RECOVERY_EXPORT = 4113
        private const val REQUEST_SYNC_RECOVERY_IMPORT = 4114
        private const val MAX_AUDIT_ITEMS_TO_DISPLAY = 80
        private const val PROFILE_FORMAT_VERSION = 2
    }
}
