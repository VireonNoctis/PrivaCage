package org.privacage.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.res.ColorStateList
import android.net.Uri
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import java.time.format.DateTimeFormatter

class MonitoringAccessReviewActivity : Activity() {
    private lateinit var scanButton: Button
    private lateinit var progressIndicator: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var resultsContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(36))
        }
        root.addView(heading("MONITORING ACCESS REVIEW"))
        root.addView(body(
            "Checks four Android-exposed settings: enabled accessibility services, active device administrators, " +
                "notification listeners, and VPN transport on the current default network."
        ))
        root.addView(body(
            "LOCAL ONLY · No network requests, notification contents, accessibility events or app traffic are read. " +
                "No Usage Access, full app inventory, saved report or upload. Nothing is changed automatically. " +
                "Assistive, work and companion tools may use these settings legitimately; this is not a stalkerware verdict. " +
                "No findings do not prove monitoring is absent. On shared or managed devices, review activity may be visible " +
                "to an administrator. Close this screen if that could put you at risk."
        ))
        scanButton = Button(this).apply {
            text = "Run local review"
            setOnClickListener { runReview() }
        }
        root.addView(scanButton, matchWidth())
        progressIndicator = ProgressBar(this).apply {
            isIndeterminate = true
            indeterminateTintList = ColorStateList.valueOf(Color.WHITE)
            visibility = View.GONE
            contentDescription = "Reading Android settings"
        }
        root.addView(progressIndicator, LinearLayout.LayoutParams(dp(28), dp(28)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            topMargin = dp(10)
            bottomMargin = dp(4)
        })
        statusText = body("No review run. Results are transient.")
        statusText.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        root.addView(statusText, matchWidth())
        resultsContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(resultsContainer, matchWidth())
        root.addView(Button(this).apply {
            text = "Close review"
            setOnClickListener { finish() }
        }, matchWidth())

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            overScrollMode = android.view.View.OVER_SCROLL_NEVER
        }
        PrivaCageDesign.apply(this, root, scroll, statusText)
        scroll.addView(root)
        setContentView(scroll)
    }

    private fun runReview() {
        scanButton.isEnabled = false
        progressIndicator.visibility = View.VISIBLE
        statusText.text = "Reading Android settings locally. Nothing will be saved."
        resultsContainer.removeAllViews()
        Thread({
            val outcome = try {
                MonitoringAccessAudit.collect(this) to null
            } catch (exception: Exception) {
                null to exception
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                scanButton.isEnabled = true
                progressIndicator.visibility = View.GONE
                val snapshot = outcome.first
                if (snapshot == null) {
                    val errorType = outcome.second?.javaClass?.simpleName ?: "unknown error"
                    statusText.text = "The review did not complete (" + errorType + "). No result was saved."
                    return@runOnUiThread
                }
                statusText.text = "REVIEW COMPLETE · " +
                    DateTimeFormatter.ISO_INSTANT.format(snapshot.capturedAt) +
                    " · DEVICE CLOCK · TRANSIENT"
                render(snapshot)
            }
        }, "PrivaCage-monitoring-access-review").start()
    }

    private fun render(snapshot: MonitoringAccessSnapshot) {
        addComponentObservation(
            "ACCESSIBILITY SERVICES",
            snapshot.accessibilityServices,
            "Screen readers, assistive tools and automation use accessibility access. The OS list does not show what a service reads or does.",
            Settings.ACTION_ACCESSIBILITY_SETTINGS,
            "accessibility settings"
        )
        addComponentObservation(
            "ACTIVE DEVICE ADMINISTRATORS",
            snapshot.activeDeviceAdministrators,
            "Device administrators can enforce selected policies, including legitimate work or school management. " +
                "This list covers the current user/profile; controller identity is unknown.",
            Settings.ACTION_SECURITY_SETTINGS,
            "security settings"
        )
        addComponentObservation(
            "NOTIFICATION LISTENERS",
            snapshot.notificationListeners,
            "Enabled listeners may receive notifications. This review reads only the component setting, not notification text or history. " +
                "Wearable and companion apps may use this access legitimately.",
            Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS,
            "notification-listener settings"
        )

        resultsContainer.addView(heading("DEFAULT NETWORK VPN STATE"))
        resultsContainer.addView(body(
            when (snapshot.defaultNetworkVpn.usesVpnTransportOnDefaultNetwork) {
                true -> "Android reports that the current default network uses a VPN transport. This may be PrivaCage or another VPN. " +
                    "The public API result does not identify the owning app or provider."
                false -> "The current default network does not report VPN transport. This does not prove that no other VPN configuration, " +
                    "per-app route or non-default network exists."
                null -> "VPN state is unknown because Android did not provide current default-network capabilities."
            }
        ))
        snapshot.defaultNetworkVpn.detail?.let { resultsContainer.addView(body(it)) }
        resultsContainer.addView(body("Evidence source: " + snapshot.defaultNetworkVpn.source))
        resultsContainer.addView(body(
            "Evidence confidence: direct for the active default network only; VPN ownership and other routes are unknown."
        ))
        resultsContainer.addView(settingsButton(Settings.ACTION_VPN_SETTINGS, "Open Android VPN settings"))
        resultsContainer.addView(heading("INTERPRETATION"))
        resultsContainer.addView(body(
            "No score or malware verdict is generated. A listed capability does not establish intent or prove that data was read. " +
                "No findings do not establish that monitoring is absent. Root/system-only indicators are outside this stock-app review."
        ))
        resultsContainer.addView(body(
            "Do not disable access based only on this report. Unavailable or partial sections are not empty; open the relevant Android settings to review further when safe."
        ))
    }

    private fun addComponentObservation(
        title: String,
        observation: MonitoringComponentObservation,
        explanation: String,
        settingsAction: String,
        settingsLabel: String
    ) {
        resultsContainer.addView(heading(title))
        resultsContainer.addView(body(explanation))
        resultsContainer.addView(body("Evidence source: " + observation.source))
        val confidence = if (observation.source == "Settings.Secure.enabled_notification_listeners") {
            "Evidence confidence: best-effort AOSP setting value; this key is not a stable public SDK contract and OEM exposure may vary. Intent and actual use are unknown."
        } else {
            "Evidence confidence: direct for the OS-reported enabled state; intent and actual use are unknown."
        }
        resultsContainer.addView(body(confidence))
        when (observation.status) {
            MonitoringObservationStatus.UNAVAILABLE -> resultsContainer.addView(body(
                "Status: unavailable. " + (observation.detail ?: "Android did not expose this information.")
            ))
            MonitoringObservationStatus.AVAILABLE,
            MonitoringObservationStatus.PARTIAL -> {
                if (observation.components.isEmpty()) {
                    val message = if (observation.status == MonitoringObservationStatus.PARTIAL) {
                        "The list is incomplete; no components could be displayed."
                    } else {
                        "Android reported no enabled components for this category in the current user/profile."
                    }
                    resultsContainer.addView(body(message))
                } else {
                    resultsContainer.addView(body("Components reported: " + observation.components.size))
                    val appInfoTargets = LinkedHashSet<String>()
                    observation.components.forEach { component ->
                        resultsContainer.addView(componentText(
                            component.packageName + "\n" + component.className
                        ))
                        if (appInfoTargets.add(component.packageName)) {
                            resultsContainer.addView(appInfoButton(component.packageName))
                        }
                    }
                }
                observation.detail?.let { resultsContainer.addView(body("Coverage note: " + it)) }
            }
        }
        resultsContainer.addView(settingsButton(settingsAction, "Open Android " + settingsLabel))
    }

    private fun appInfoButton(packageName: String) = Button(this).apply {
        text = "Review app info"
        contentDescription = "Open Android app info for $packageName"
        setOnClickListener {
            try {
                startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.fromParts("package", packageName, null)
                    }
                )
                statusText.text =
                    "Opened Android app info for $packageName. PrivaCage did not change any setting."
            } catch (exception: ActivityNotFoundException) {
                statusText.text =
                    "Android does not expose an app-info page for $packageName on this device. No setting was changed."
            } catch (exception: SecurityException) {
                statusText.text =
                    "Android did not allow app info for $packageName to open. No setting was changed."
            }
        }
        PrivaCageDesign.styleControl(this@MonitoringAccessReviewActivity, this)
    }

    private fun settingsButton(action: String, label: String) = Button(this).apply {
        text = label
        setOnClickListener {
            try {
                startActivity(Intent(action))
            } catch (exception: ActivityNotFoundException) {
                statusText.text = "Android does not expose " + label + " on this device. No setting was changed."
            } catch (exception: SecurityException) {
                statusText.text = "Android did not allow " + label + " to open. No setting was changed."
            }
        }
        PrivaCageDesign.styleControl(this@MonitoringAccessReviewActivity, this)
    }

    private fun heading(value: String) = TextView(this).apply {
        text = value
        textSize = 12f
        setTextColor(Color.WHITE)
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        setPadding(0, dp(16), 0, dp(6))
    }

    private fun body(value: String) = TextView(this).apply {
        text = value
        textSize = 12f
        setTextColor(Color.WHITE)
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        setPadding(0, dp(5), 0, dp(7))
    }

    private fun componentText(value: String) = TextView(this).apply {
        text = value
        textSize = 11f
        setTextColor(Color.WHITE)
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        setPadding(dp(12), dp(6), 0, dp(6))
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )
}
