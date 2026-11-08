package org.privacage.android

import android.app.Activity
import android.app.KeyguardManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView

class CellularSecurityOnboardingActivity : Activity() {
    private lateinit var statusText: TextView
    private var checklist: CellularSecurityChecklist? = null
    private var suppressRadioChanges = false
    private lateinit var lockSignalText: TextView
    private lateinit var patchSignalText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(36))
        }

        root.addView(heading("CELLULAR SECURITY SETUP"))
        root.addView(body(
            "This is a guided, local checklist. Android controls the radio settings. PrivaCage cannot switch off 2G, " +
                "read the modem cipher, or confirm that a false base station is present."
        ))
        root.addView(body(
            "IMPORTANT · Every checklist status is your own report. “Confirmed” means you personally checked the " +
                "setting in Android or Google Play. It is not an independent OS measurement. “Unavailable” means " +
                "you could not find or use that control; it does not mean protection is enabled."
        ))

        statusText = body("Loading the encrypted local checklist…")
        statusText.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        root.addView(statusText, matchWidth())

        checklist = try {
            CellularSecurityChecklistStore.read(this)
        } catch (exception: Exception) {
            statusText.text = "The encrypted checklist could not be authenticated or read (" +
                exception.javaClass.simpleName + "). Existing stored data was preserved. Editing is disabled."
            null
        }

        if (checklist != null) {
            statusText.text =
                "LOCAL ONLY · Choices are saved in an encrypted, device-local record as you make them. Nothing is uploaded."
        }

        root.addView(heading("DIRECT ANDROID SIGNALS"))
        lockSignalText = body("Screen-lock credential: " + readSecureLockState())
        root.addView(lockSignalText, matchWidth())
        root.addView(body(
            "Android reports whether a secure PIN, pattern or password is configured. This does not measure " +
                "credential strength, biometric quality, coercion risk or resistance to every physical attack."
        ))
        root.addView(settingsButton(Settings.ACTION_SECURITY_SETTINGS, "Open screen-lock and security settings"))

        val patchLevel = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() } ?: "not exposed"
        patchSignalText = body("Reported Android security patch: " + patchLevel)
        root.addView(patchSignalText, matchWidth())
        root.addView(body(
            "This is the date Android exposes for the applied security patch. PrivaCage does not decide whether " +
                "it is the newest update available for this exact device. Check the manufacturer's update screen " +
                "and compare the device-specific release with the current Android Security Bulletin."
        ))
        root.addView(Button(this).apply {
            text = "Check Android system updates"
            setOnClickListener { openSystemUpdateSettings() }
            PrivaCageDesign.styleControl(this@CellularSecurityOnboardingActivity, this)
        }, matchWidth())
        root.addView(urlButton("Open Android Security Bulletins", "https://source.android.com/docs/security/bulletin"))

        root.addView(heading("USER-CONFIRMED HARDENING"))
        val current = checklist ?: CellularSecurityChecklist()
        val canSave = checklist != null

        addChecklistItem(
            root = root,
            title = "2G NETWORK PROTECTION · EVERY SIM",
            explanation = "Open mobile-network settings and inspect every active physical SIM and eSIM. Confirm that " +
                "the 2G network protection control is enabled for each SIM where Android and the modem support it. " +
                "If a SIM has no such control, choose “Unavailable” rather than assuming it is protected.",
            status = current.everySim2gProtection,
            enabled = canSave,
            openSettings = { openSettings(Settings.ACTION_WIRELESS_SETTINGS, "Mobile network settings") },
            update = { value, status -> value.copy(everySim2gProtection = status) },
            currentStatus = { it.everySim2gProtection }
        )

        addChecklistItem(
            root = root,
            title = "UNENCRYPTED-NETWORK ALERTS",
            explanation = "On supported Android 16 devices, open Mobile network security in Safety Center and " +
                "confirm notifications for unencrypted connections and device-identifier disclosures are enabled. " +
                "The feature is modem-dependent and Android's notification switch is off by default.",
            status = current.unencryptedNetworkAlerts,
            enabled = canSave,
            openSettings = { openSettings(Settings.ACTION_SECURITY_SETTINGS, "Android security settings") },
            update = { value, status -> value.copy(unencryptedNetworkAlerts = status) },
            currentStatus = { it.unencryptedNetworkAlerts }
        )

        addChecklistItem(
            root = root,
            title = "SYSTEM AND SECURITY UPDATES",
            explanation = "Review the update screen and the device manufacturer's support/update page. Mark “Confirmed” " +
                "only after you have checked for updates and reviewed the patch level. The patch date above is a raw " +
                "OS signal, not a guarantee that every vendor or modem component is current.",
            status = current.securityUpdates,
            enabled = canSave,
            openSettings = { openSystemUpdateSettings() },
            update = { value, status -> value.copy(securityUpdates = status) },
            currentStatus = { it.securityUpdates }
        )

        addChecklistItem(
            root = root,
            title = "USB DEBUGGING AND DEVELOPER OPTIONS",
            explanation = "Review Developer options. Keep USB debugging off when you are not actively using it, " +
                "and remove authorizations for computers you no longer trust. A normal third-party app cannot " +
                "reliably read the global ADB-enabled state; PrivaCage does not report this as automatically checked.",
            status = current.usbDebugging,
            enabled = canSave,
            openSettings = { openSettings(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS, "Developer options") },
            update = { value, status -> value.copy(usbDebugging = status) },
            currentStatus = { it.usbDebugging }
        )

        addChecklistItem(
            root = root,
            title = "GOOGLE PLAY PROTECT",
            explanation = "Where Google Play is installed, open Play Protect and check that “Scan apps with Play " +
                "Protect” is on. This is a Google service, not an offline PrivaCage scan. Google documents that it " +
                "may receive device network connections, potentially harmful URLs, OS/app details and scan submissions. " +
                "Review its data choices; “Improve harmful app detection” is a separate setting.",
            status = current.playProtect,
            enabled = canSave,
            openSettings = { openPlayProtect() },
            update = { value, status -> value.copy(playProtect = status) },
            currentStatus = { it.playProtect }
        )

        addChecklistItem(
            root = root,
            title = "DEVICE THEFT PROTECTION",
            explanation = "Open Google → All services → Theft protection. Review Theft Detection Lock, Offline Device Lock, " +
                "Failed Authentication Lock, Identity Check and Remote Lock where each is available on this device. " +
                "Identity Check is model-dependent and requires biometrics and trusted places. Remote Lock requires " +
                "a screen lock, active SIM, verified number, Find Hub and connectivity. Mark unavailable for controls " +
                "that this device does not offer; these are Google/system settings, not PrivaCage detections.",
            status = current.theftProtection,
            enabled = canSave,
            openSettings = { openSettings(Settings.ACTION_SECURITY_SETTINGS, "Android security and Google settings") },
            update = { value, status -> value.copy(theftProtection = status) },
            currentStatus = { it.theftProtection }
        )
        root.addView(urlButton(
            "Open official Android Theft Protection guidance",
            "https://support.google.com/android/answer/15146908?hl=en-GB"
        ))

        addChecklistItem(
            root = root,
            title = "ADVANCED PROTECTION AND USB PROTECTION",
            explanation = "On supported Android 16 devices, review Advanced Protection → Device protection. " +
                "It applies a broader security configuration and can restrict some features. Intrusion Logging is " +
                "an optional part of setup; review its data and export implications before enabling it. USB Protection " +
                "is documented for Pixel 6 and later: with the screen locked, it blocks new USB data connections and " +
                "is enabled through Device protection. Other manufacturers may not expose the same feature.",
            status = current.advancedProtectionUsb,
            enabled = canSave,
            openSettings = { openSettings(Settings.ACTION_SECURITY_SETTINGS, "Android Advanced Protection settings") },
            update = { value, status -> value.copy(advancedProtectionUsb = status) },
            currentStatus = { it.advancedProtectionUsb }
        )
        root.addView(urlButton(
            "Open official Advanced Protection guidance",
            "https://support.google.com/android/answer/16339980?hl=en-GB"
        ))
        root.addView(urlButton(
            "Open official USB Protection guidance",
            "https://support.google.com/android/answer/16778864?hl=en-GB"
        ))

        root.addView(heading("WHAT THIS CHECKLIST DOES NOT VERIFY"))
        root.addView(body(
            "PrivaCage cannot read the modem's cipher state, detect every rogue base station, inspect bootloader " +
                "or Verified Boot state through a stable ordinary-app API, enumerate all apps that may request " +
                "installation, or read global USB debugging state. It also cannot verify carrier-side SIM-swap or " +
                "number-port protection, or determine whether optional Theft Protection / Advanced Protection " +
                "settings were enabled after you leave Android Settings. Those items remain user-reported or unavailable."
        ))
        root.addView(body(
            "A user-confirmed result can become outdated after a SIM change, OS update, settings reset or device " +
                "management change. Revisit the checklist after those events."
        ))

        root.addView(Button(this).apply {
            text = "Close security setup"
            setOnClickListener { finish() }
        }, matchWidth())

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        PrivaCageDesign.apply(this, root, scroll, statusText)
        scroll.addView(root)
        setContentView(scroll)
    }

    override fun onResume() {
        super.onResume()
        if (::lockSignalText.isInitialized) {
            lockSignalText.text = "Screen-lock credential: " + readSecureLockState()
        }
        if (::patchSignalText.isInitialized) {
            val patch = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() } ?: "not exposed"
            patchSignalText.text = "Reported Android security patch: " + patch
        }
    }

    private fun addChecklistItem(
        root: LinearLayout,
        title: String,
        explanation: String,
        status: CellularReviewStatus,
        enabled: Boolean,
        openSettings: () -> Unit,
        update: (CellularSecurityChecklist, CellularReviewStatus) -> CellularSecurityChecklist,
        currentStatus: (CellularSecurityChecklist) -> CellularReviewStatus
    ) {
        root.addView(heading(title))
        root.addView(body(explanation))
        root.addView(Button(this).apply {
            text = "Open related Android settings"
            setOnClickListener { openSettings() }
            PrivaCageDesign.styleControl(this@CellularSecurityOnboardingActivity, this)
        }, matchWidth())

        val group = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            setPadding(0, dp(2), 0, dp(10))
        }
        val ids = linkedMapOf<Int, CellularReviewStatus>()
        val choices = listOf(
            CellularReviewStatus.NOT_REVIEWED to "Not reviewed",
            CellularReviewStatus.USER_CONFIRMED to "I checked this manually",
            CellularReviewStatus.NOT_AVAILABLE to "Unavailable / could not verify"
        )
        choices.forEach { (value, label) ->
            val radio = RadioButton(this).apply {
                id = View.generateViewId()
                text = label
                isEnabled = enabled
                isChecked = value == status
                setPadding(dp(2), dp(4), dp(2), dp(4))
                contentDescription = title + ": " + label
            }
            ids[radio.id] = value
            group.addView(radio, RadioGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ))
        }
        group.isEnabled = enabled
        group.setOnCheckedChangeListener { _, checkedId ->
            if (suppressRadioChanges) return@setOnCheckedChangeListener
            val selected = ids[checkedId] ?: return@setOnCheckedChangeListener
            val before = checklist ?: return@setOnCheckedChangeListener
            val previousStatus = currentStatus(before)
            val next = update(before, selected)
            try {
                CellularSecurityChecklistStore.save(this@CellularSecurityOnboardingActivity, next)
                checklist = next
                statusText.text =
                    "SAVED LOCALLY · " + title + " · " + statusLabel(selected) +
                        ". This remains a user report, not an OS-verified result."
            } catch (exception: Exception) {
                suppressRadioChanges = true
                val previousId = ids.entries.firstOrNull { it.value == previousStatus }?.key
                if (previousId != null) group.check(previousId)
                suppressRadioChanges = false
                statusText.text =
                    "NOT SAVED · " + exception.javaClass.simpleName +
                        ". The previous encrypted checklist was preserved."
            }
        }
        root.addView(group, matchWidth())
        if (!enabled) {
            root.addView(body("Saved checklist is unavailable; controls are read-only until its encrypted data can be read."))
        }
    }

    private fun statusLabel(status: CellularReviewStatus): String = when (status) {
        CellularReviewStatus.NOT_REVIEWED -> "not reviewed"
        CellularReviewStatus.USER_CONFIRMED -> "user confirmed"
        CellularReviewStatus.NOT_AVAILABLE -> "unavailable / could not verify"
    }

    private fun readSecureLockState(): String = try {
        val manager = getSystemService(KeyguardManager::class.java)
        when {
            manager == null -> "UNAVAILABLE · Android did not provide KeyguardManager"
            manager.isDeviceSecure -> "SECURE LOCK CREDENTIAL CONFIGURED · direct Android API signal"
            else -> "NO SECURE LOCK CREDENTIAL REPORTED · review this in Android Settings"
        }
    } catch (exception: SecurityException) {
        "UNAVAILABLE · Android restricted the secure-lock query"
    } catch (exception: RuntimeException) {
        "UNAVAILABLE · " + exception.javaClass.simpleName
    }

    private fun openSystemUpdateSettings() {
        val action = "android.settings.SYSTEM_UPDATE_SETTINGS"
        try {
            val intent = Intent(action)
            val handlers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.queryIntentActivities(
                    intent,
                    PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_SYSTEM_ONLY.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                packageManager.queryIntentActivities(intent, PackageManager.MATCH_SYSTEM_ONLY)
            }
            val target = handlers.maxByOrNull { it.priority }
            val targetActivity = target?.activityInfo
            if (target == null || target.priority <= 0 || targetActivity == null) {
                statusText.text = "This Android build does not expose a trusted system update settings handler. Check for updates manually in Settings."
                return
            }
            startActivity(Intent(action).setClassName(targetActivity.packageName, targetActivity.name))
            statusText.text = "Opened the system update screen. Check both the Android security patch date and any separate Google Play system update."
        } catch (exception: ActivityNotFoundException) {
            statusText.text = "System update settings are not available on this Android build."
        } catch (exception: SecurityException) {
            statusText.text = "Android did not allow the system update settings screen to open."
        } catch (exception: RuntimeException) {
            statusText.text = "Could not safely resolve the system update settings screen (" + exception.javaClass.simpleName + ")."
        }
    }

    private fun openSettings(action: String, label: String) {
        try {
            startActivity(Intent(action))
            statusText.text = "Opened " + label + ". Android Settings owns the control; PrivaCage does not change it."
        } catch (exception: ActivityNotFoundException) {
            statusText.text = label + " is not exposed by this Android build."
        } catch (exception: SecurityException) {
            statusText.text = "Android did not allow " + label + " to open."
        }
    }

    private fun openPlayProtect() {
        try {
            val launchIntent = packageManager.getLaunchIntentForPackage("com.android.vending")
            if (launchIntent == null) {
                statusText.text = "Google Play Store is not available to open on this device. Play Protect is not assumed present."
                return
            }
            startActivity(launchIntent)
            statusText.text = "Opened Google Play. Navigate to profile → Play Protect → Settings and check “Scan apps with Play Protect”."
        } catch (exception: ActivityNotFoundException) {
            statusText.text = "Google Play Store could not be opened. Play Protect is not assumed present."
        } catch (exception: SecurityException) {
            statusText.text = "Android did not allow Google Play Store to open."
        }
    }

    private fun urlButton(label: String, url: String) = Button(this).apply {
        text = label
        setOnClickListener {
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            } catch (exception: ActivityNotFoundException) {
                statusText.text = "No browser is available for " + url
            } catch (exception: SecurityException) {
                statusText.text = "Android did not allow the browser handoff."
            }
        }
        PrivaCageDesign.styleControl(this@CellularSecurityOnboardingActivity, this)
    }

    private fun settingsButton(action: String, label: String) = Button(this).apply {
        text = label
        setOnClickListener { openSettings(action, label) }
        PrivaCageDesign.styleControl(this@CellularSecurityOnboardingActivity, this)
    }

    private fun heading(value: String) = TextView(this).apply {
        text = value
        textSize = 15f
        typeface = Typeface.MONOSPACE
        setTextColor(Color.WHITE)
        setPadding(0, dp(18), 0, dp(6))
        contentDescription = value
    }

    private fun body(value: String) = TextView(this).apply {
        text = value
        textSize = 13f
        setTextColor(Color.LTGRAY)
        setPadding(0, dp(4), 0, dp(8))
    }

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt().coerceAtLeast(1)
}
