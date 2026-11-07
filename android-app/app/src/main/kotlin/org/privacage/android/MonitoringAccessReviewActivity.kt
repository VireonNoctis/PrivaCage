package org.privacage.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.provider.Settings
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.time.format.DateTimeFormatter

class MonitoringAccessReviewActivity : Activity() {
    private lateinit var scanButton: Button
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
            "This is a user-triggered, read-only review of a few settings Android exposes to ordinary apps. " +
                "It checks enabled accessibility services, active device administrators, enabled notification-listener components, " +
                "and whether the current default network reports VPN transport."
        ))
        root.addView(body(
            "The review runs locally. It does not make network requests, read notification contents, observe accessibility events, " +
                "inspect app traffic, query a complete installed-app inventory, or save the results. It does not use Usage Access."
        ))
        root.addView(body(
            "A listed service may be an assistive technology, password manager, automation tool, wearable companion, work/school manager, " +
                "or VPN. These settings show granted capabilities, not intent or proof of monitoring. A result with no listed services " +
                "does not prove that a device is free of monitoring."
        ))
        root.addView(body(
            "If this is a shared or managed device, app usage and settings activity may be visible to someone with device-management access. " +
                "Do not change access based only on this report. Close this screen if reviewing it could create risk."
        ))
        scanButton = Button(this).apply {
            text = "Run local review"
            setOnClickListener { runReview() }
        }
        root.addView(scanButton, matchWidth())
        statusText = body("No review has been run. Nothing has been saved.")
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
        statusText.text = "Reading Android-exposed settings locally. No result will be saved."
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
                val snapshot = outcome.first
                if (snapshot == null) {
                    val errorType = outcome.second?.javaClass?.simpleName ?: "unknown error"
                    statusText.text = "The review did not complete (" + errorType + "). No result was saved."
                    return@runOnUiThread
                }
                statusText.text = "Review completed at " +
                    DateTimeFormatter.ISO_INSTANT.format(snapshot.capturedAt) +
                    " (device clock). Results exist only on this screen."
                render(snapshot)
            }
        }, "PrivaCage-monitoring-access-review").start()
    }

    private fun render(snapshot: MonitoringAccessSnapshot) {
        addComponentObservation(
            "ACCESSIBILITY SERVICES",
            snapshot.accessibilityServices,
            "Enabled accessibility services can support screen readers, assistive tools and automation. " +
                "Android's returned service list is direct settings evidence; it does not show what a service actually reads or does.",
            Settings.ACTION_ACCESSIBILITY_SETTINGS,
            "accessibility settings"
        )
        addComponentObservation(
            "ACTIVE DEVICE ADMINISTRATORS",
            snapshot.activeDeviceAdministrators,
            "An active device administrator can enforce selected device policies. This can be legitimate for work, school or a device-management arrangement. " +
                "This list is for the current user/profile and does not establish who controls the device.",
            Settings.ACTION_SECURITY_SETTINGS,
            "security settings"
        )
        addComponentObservation(
            "NOTIFICATION LISTENERS",
            snapshot.notificationListeners,
            "An enabled notification listener may receive notifications from Android. This review reads only the enabled-component setting; " +
                "it does not read notification text or history. Wearable, companion and automation apps can use this access legitimately.",
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
        resultsContainer.addView(settingsButton(Settings.ACTION_VPN_SETTINGS, "Open Android VPN settings"))
        resultsContainer.addView(heading("INTERPRETATION"))
        resultsContainer.addView(body(
            "No score or malware verdict is generated. A single accessibility, administrator, notification-listener or VPN observation " +
                "is not evidence that an app or person is abusive. Root/system-only indicators are not collected by this stock-app review."
        ))
        resultsContainer.addView(body(
            "Unavailable or partial sections are not treated as empty. Review the corresponding Android settings directly when it is safe to do so."
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
                    observation.components.forEach { component ->
                        resultsContainer.addView(componentText(
                            component.packageName + "\n" + component.className
                        ))
                    }
                }
                observation.detail?.let { resultsContainer.addView(body("Coverage note: " + it)) }
            }
        }
        resultsContainer.addView(settingsButton(settingsAction, "Open Android " + settingsLabel))
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
