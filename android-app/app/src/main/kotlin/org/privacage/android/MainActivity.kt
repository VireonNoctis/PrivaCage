package org.privacage.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.provider.Settings
import android.net.Uri
import android.net.VpnService
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
import org.privacage.crypto.EncryptedBackupEnvelope
import org.privacage.dns.DnsPolicyEngine
import org.privacage.dns.DnsOverTlsForwarder
import org.privacage.metadata.JpegMetadataScrubber
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets

class MainActivity : Activity() {
    private lateinit var resolverInput: EditText
    private lateinit var resolverHostnameInput: EditText
    private lateinit var dnsOverTlsInput: CheckBox
    private lateinit var domainsInput: EditText
    private lateinit var domainTestInput: EditText
    private lateinit var statsText: TextView
    private lateinit var apkAuditText: TextView
    private lateinit var statusText: TextView
    private lateinit var devicePrivacyText: TextView
    private lateinit var appPermissionAuditText: TextView
    private var apkTrackerCatalog: List<TrackerSignature> = emptyList()
    private var pendingEncryptedBackup: ByteArray? = null
    private var pendingImportBackup: ByteArray? = null
    private var pendingScrubbedJpeg: File? = null

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
        apkTrackerCatalog = trackerCatalog.orEmpty()
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
            text = "Remove photo metadata (JPEG)"
            setOnClickListener { chooseJpegForScrubbing() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Inspect APK manifest offline"
            setOnClickListener { chooseApkForAudit() }
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
        refreshDevicePrivacySnapshot()
    }

    override fun onResume() {
        super.onResume()
        if (::statsText.isInitialized) refreshDnsStats()
        if (::devicePrivacyText.isInitialized) refreshDevicePrivacySnapshot()
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
            REQUEST_APK_AUDIT -> auditSelectedApk(resultCode, data?.data)
            REQUEST_JPEG_SCRUB_INPUT -> scrubSelectedJpeg(resultCode, data?.data)
            REQUEST_JPEG_SCRUB_OUTPUT -> saveScrubbedJpeg(resultCode, data?.data)
        }
    }

    override fun onDestroy() {
        pendingEncryptedBackup?.fill(0)
        pendingEncryptedBackup = null
        pendingImportBackup?.fill(0)
        pendingImportBackup = null
        pendingScrubbedJpeg?.delete()
        pendingScrubbedJpeg = null
        super.onDestroy()
    }

    private fun refreshDevicePrivacySnapshot() {
        devicePrivacyText.text = DevicePrivacySnapshot.capture(this).render()
    }

    private fun chooseJpegForScrubbing() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "image/jpeg"
        }
        startActivityForResult(intent, REQUEST_JPEG_SCRUB_INPUT)
    }

    private fun scrubSelectedJpeg(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            statusText.text = "Photo metadata removal cancelled."
            return
        }
        pendingScrubbedJpeg?.delete()
        pendingScrubbedJpeg = null
        statusText.text = "Removing common JPEG metadata locally. The image is not uploaded."
        Thread({
            var staged: File? = null
            var cleaned: File? = null
            try {
                staged = stageSelectedJpeg(uri)
                cleaned = File.createTempFile("privacage-cleaned-", ".jpg", cacheDir)
                val result = JpegMetadataScrubber.scrub(staged, cleaned)
                staged.delete()
                staged = null
                val completedFile = cleaned
                cleaned = null
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        pendingScrubbedJpeg = completedFile
                        statusText.text = "Removed " + result.metadataSegmentsRemoved +
                            " metadata segments (" + result.metadataBytesRemoved +
                            " bytes). Save the cleaned JPEG to a location you choose."
                        val saveIntent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "image/jpeg"
                            putExtra(Intent.EXTRA_TITLE, "privacage-cleaned.jpg")
                        }
                        startActivityForResult(saveIntent, REQUEST_JPEG_SCRUB_OUTPUT)
                    } else {
                        completedFile?.delete()
                    }
                }
            } catch (exception: Exception) {
                val message = exception.message ?: "The JPEG could not be safely scrubbed."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) statusText.text = "Photo metadata removal failed: " + message
                }
            } finally {
                staged?.delete()
                cleaned?.delete()
            }
        }, "PrivaCage-JPEG-scrub").start()
    }

    private fun stageSelectedJpeg(uri: Uri): File {
        val staged = File.createTempFile("privacage-jpeg-input-", ".jpg", cacheDir)
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
                        if (totalBytes > 100L * 1024 * 1024 - count) {
                            throw IOException("JPEG exceeds the 100 MiB local processing limit.")
                        }
                        output.write(buffer, 0, count)
                        totalBytes += count
                    }
                    output.flush()
                }
            }
            if (totalBytes == 0L) throw IOException("The selected image is empty.")
            return staged
        } catch (exception: Exception) {
            staged.delete()
            throw exception
        } finally {
            buffer.fill(0)
        }
    }

    private fun saveScrubbedJpeg(resultCode: Int, uri: Uri?) {
        val cleaned = pendingScrubbedJpeg
        pendingScrubbedJpeg = null
        if (resultCode != RESULT_OK || uri == null) {
            cleaned?.delete()
            statusText.text = "Cleaned JPEG was not saved; the temporary copy was deleted."
            return
        }
        if (cleaned == null || !cleaned.isFile) {
            statusText.text = "Cleaned JPEG is no longer available; run metadata removal again."
            return
        }
        statusText.text = "Saving the cleaned JPEG locally."
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
                        statusText.text = "Cleaned JPEG saved. Pixel data was not recompressed; APP1, APP13, and comment segments were removed."
                    }
                }
            } catch (exception: Exception) {
                val message = exception.message ?: "The cleaned JPEG could not be saved."
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) statusText.text = "Saving cleaned JPEG failed: " + message
                }
            } finally {
                buffer.fill(0)
                cleaned.delete()
            }
        }, "PrivaCage-JPEG-save").start()
    }

    private fun chooseApkForAudit() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/vnd.android.package-archive"))
        }
        startActivityForResult(intent, REQUEST_APK_AUDIT)
    }

    private fun auditSelectedApk(resultCode: Int, uri: Uri?) {
        if (resultCode != RESULT_OK || uri == null) {
            statusText.text = "APK inspection cancelled; no file was installed or uploaded."
            return
        }

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
        append("SHA-256: ").append(report.sha256).append("\n\n")

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
        private const val REQUEST_APK_AUDIT = 4110
        private const val REQUEST_JPEG_SCRUB_INPUT = 4111
        private const val REQUEST_JPEG_SCRUB_OUTPUT = 4112
        private const val MAX_AUDIT_ITEMS_TO_DISPLAY = 80
        private const val PROFILE_FORMAT_VERSION = 2
    }
}
