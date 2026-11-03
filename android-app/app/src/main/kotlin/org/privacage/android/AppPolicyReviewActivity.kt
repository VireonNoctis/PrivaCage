package org.privacage.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.InputFilter
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class AppPolicyReviewActivity : Activity() {
    private lateinit var listContainer: LinearLayout
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(36))
        }
        root.addView(TextView(this).apply {
            text = "APP POLICY REVIEW QUEUE"
            textSize = 17f
        })
        root.addView(body(
            "PrivaCage watches only launcher-visible packages. New installs are detected the next time you return to PrivaCage. " +
                "App-open detection requires Android's separate Usage Access permission. Any prompt is shown when you return to PrivaCage; " +
                "ordinary apps cannot safely place an overlay over another app."
        ))
        root.addView(body(
            "There is no universal policy URL or reliable way to extract every app's Terms and Privacy Policy. Add official HTTPS links below, " +
                "open them in your browser, then paste the text you want analysed. PrivaCage does not upload an APK or crawl app content."
        ))
        root.addView(Button(this).apply {
            text = "Open Android Usage Access settings"
            setOnClickListener {
                try {
                    startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                } catch (exception: Exception) {
                    statusText.text = "Android did not expose the Usage Access settings screen on this device."
                }
            }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Refresh installed and opened apps"
            setOnClickListener { captureAndRefresh() }
        }, matchWidth())
        statusText = body("")
        root.addView(statusText, matchWidth())
        root.addView(TextView(this).apply {
            text = "PENDING APPS"
            textSize = 15f
            setPadding(0, dp(18), 0, dp(8))
        })
        listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(listContainer, matchWidth())

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
        }
        PrivaCageDesign.apply(this, root, scroll, statusText)
        scroll.addView(root)
        setContentView(scroll)
        refreshQueue()
    }

    override fun onResume() {
        super.onResume()
        if (::listContainer.isInitialized) refreshQueue()
    }

    private fun captureAndRefresh() {
        statusText.text = "Checking launcher-visible installations and any permitted app-open events..."
        Thread({
            val result = try {
                AppPolicyReviewMonitor.capture(this) to null
            } catch (exception: Exception) {
                null to (exception.message ?: exception.javaClass.simpleName)
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                val capture = result.first
                statusText.text = if (capture == null) {
                    "App review scan failed: " + result.second
                } else {
                    buildString {
                        append("New review items: ").append(capture.newPendingCount)
                        append(" | Pending: ").append(capture.pendingCount)
                        append(" | App-open access: ")
                            .append(if (capture.usageAccessAvailable) "enabled" else "not granted")
                        capture.warning?.let { append("\n").append(it) }
                        if (!capture.usageAccessAvailable) {
                            append("\nGrant Usage Access above to observe app-open events. Install detection still works on return to PrivaCage.")
                        }
                    }
                }
                refreshQueue()
            }
        }, "PrivaCage-app-policy-scan").start()
    }

    private fun refreshQueue() {
        if (!::listContainer.isInitialized) return
        listContainer.removeAllViews()
        try {
            val items = AppPolicyReviewMonitor.pending(this)
            if (items.isEmpty()) {
                listContainer.addView(body("No pending app policy reviews. Newly observed app installs and launches will appear here."))
            } else {
                items.forEach { item ->
                    val label = try {
                        val info = packageManager.getApplicationInfo(item.packageName, 0)
                        packageManager.getApplicationLabel(info).toString()
                    } catch (_: Exception) {
                        item.packageName
                    }
                    val card = LinearLayout(this).apply {
                        orientation = LinearLayout.VERTICAL
                        setPadding(dp(12), dp(8), dp(12), dp(12))
                    }
                    card.addView(TextView(this).apply {
                        text = label
                        textSize = 14f
                    })
                    card.addView(body(item.packageName + "\n" +
                        (if (item.trigger == "installed") "New launcher-visible app observed (may be newly installed or newly visible)" else "App opened since the previous review") +
                        "\nLast observed: " + java.text.DateFormat.getDateTimeInstance().format(java.util.Date(item.lastSeenAt))))
                    card.addView(Button(this).apply {
                        text = "Review Terms and Privacy Policy"
                        setOnClickListener { showReviewDialog(item, label) }
                    }, matchWidth())
                    listContainer.addView(card, matchWidth())
                }
            }
        } catch (exception: Exception) {
            listContainer.addView(body(
                "The encrypted app review queue could not be read. Existing data was preserved: " +
                    (exception.message ?: exception.javaClass.simpleName)
            ))
        }
        if (::statusText.isInitialized) {
            val access = AppPolicyReviewMonitor.hasUsageAccess(this)
            if (!access) {
                statusText.text = "Install review is available. App-open review is disabled until you grant Usage Access in Android Settings."
            } else if (statusText.text.isNullOrBlank()) {
                statusText.text = "App-open review is enabled. Events are read locally and queued for review when you return to PrivaCage."
            }
        }
    }

    private fun showReviewDialog(item: PendingAppPolicyReview, appLabel: String) {
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(8), dp(18), dp(14))
        }
        val termsInput = urlInput("Terms of Service URL", item.termsUrl)
        val privacyInput = urlInput("Privacy Policy URL", item.privacyUrl)
        val otherInput = urlInput("Other disclosure URL (optional)", item.otherUrl)
        val policyTextInput = EditText(this).apply {
            hint = "Paste policy or app-store disclosure text here"
            minLines = 6
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            filters = arrayOf(InputFilter.LengthFilter(48 * 1024))
        }
        fields.addView(body(
            "Save official links, open them in your browser, and paste only the document text you choose to analyse. " +
                "The policy text is not saved in this queue."
        ))
        fields.addView(termsInput, matchWidth())
        fields.addView(privacyInput, matchWidth())
        fields.addView(otherInput, matchWidth())
        fields.addView(policyTextInput, matchWidth())

        fun saveLinks(): Boolean = try {
            AppPolicyReviewMonitor.savePolicyLinks(
                this,
                item.packageName,
                termsInput.text.toString().trim(),
                privacyInput.text.toString().trim(),
                otherInput.text.toString().trim()
            )
            statusText.text = "Policy links encrypted and saved locally for " + appLabel + "."
            true
        } catch (exception: Exception) {
            statusText.text = "Policy links were not saved: " +
                (exception.message ?: exception.javaClass.simpleName)
            false
        }

        fun openLink(value: String, label: String) {
            if (!saveLinks()) return
            val url = value.trim()
            if (url.isBlank()) {
                statusText.text = "Enter the official HTTPS " + label + " URL first."
                return
            }
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            } catch (exception: Exception) {
                statusText.text = "Could not open the " + label + " URL. Check that a browser is installed."
            }
        }

        fields.addView(Button(this).apply {
            text = "Save policy links"
            setOnClickListener { saveLinks() }
        }, matchWidth())
        fields.addView(Button(this).apply {
            text = "Open Terms of Service"
            setOnClickListener { openLink(termsInput.text.toString(), "Terms of Service") }
        }, matchWidth())
        fields.addView(Button(this).apply {
            text = "Open Privacy Policy"
            setOnClickListener { openLink(privacyInput.text.toString(), "Privacy Policy") }
        }, matchWidth())
        fields.addView(Button(this).apply {
            text = "Open other disclosure"
            setOnClickListener { openLink(otherInput.text.toString(), "disclosure") }
        }, matchWidth())
        fields.addView(Button(this).apply {
            text = "Analyse pasted document with AI"
            setOnClickListener {
                val text = policyTextInput.text.toString()
                if (text.isBlank()) {
                    statusText.text = "Paste the policy text you want analysed first."
                    return@setOnClickListener
                }
                if (!saveLinks()) return@setOnClickListener
                chooseDocumentTask(item.packageName, appLabel, text)
            }
        }, matchWidth())

        var dialog: AlertDialog? = null
        fields.addView(Button(this).apply {
            text = "Mark review complete"
            setOnClickListener {
                if (!saveLinks()) return@setOnClickListener
                try {
                    AppPolicyReviewMonitor.markReviewed(this@AppPolicyReviewActivity, item.packageName)
                    dialog?.dismiss()
                    refreshQueue()
                    statusText.text = "Marked " + appLabel + " as reviewed. It may return to the queue after uninstalling and installing again."
                } catch (exception: Exception) {
                    statusText.text = "Could not update the review queue: " +
                        (exception.message ?: exception.javaClass.simpleName)
                }
            }
        }, matchWidth())

        val dialogScroll = ScrollView(this).apply {
            isFillViewport = false
            isVerticalScrollBarEnabled = true
            addView(fields)
        }
        dialog = AlertDialog.Builder(this)
            .setTitle(appLabel)
            .setView(dialogScroll)
            .setNegativeButton("Close", null)
            .create()
        dialog?.show()
    }

    private fun chooseDocumentTask(packageName: String, appLabel: String, text: String) {
        val tasks = arrayOf(
            PrivacyAutomationTask.TERMS_REVIEW,
            PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
            PrivacyAutomationTask.APP_DISCLOSURE_REVIEW
        )
        AlertDialog.Builder(this)
            .setTitle("Choose document type")
            .setItems(tasks.map { it.label }.toTypedArray()) { _, index ->
                val source = "App: " + appLabel + " (" + packageName + ")\n\n" + text
                startActivity(
                    Intent(this, ApiAutomationActivity::class.java)
                        .putExtra(ApiAutomationActivity.EXTRA_TASK_ID, tasks[index].id)
                        .putExtra(ApiAutomationActivity.EXTRA_SOURCE_TEXT, source)
                )
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun urlInput(hintText: String, value: String) = EditText(this).apply {
        hint = hintText
        setText(value)
        setSingleLine(true)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        filters = arrayOf(InputFilter.LengthFilter(2048))
    }

    private fun body(value: String) = TextView(this).apply {
        text = value
        textSize = 13f
        setPadding(0, dp(7), 0, dp(7))
    }

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
