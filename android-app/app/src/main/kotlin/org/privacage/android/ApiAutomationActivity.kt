package org.privacage.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class ApiAutomationActivity : Activity() {
    private val vault by lazy { ApiTokenVault(this) }
    private var selectedProvider = ApiProvider.OPENAI
    private var selectedTask = PrivacyAutomationTask.PRIVACY_POLICY_REVIEW
    private lateinit var providerButton: Button
    private lateinit var taskButton: Button
    private lateinit var modelInput: EditText
    private lateinit var apiKeyInput: EditText
    private lateinit var purposeInput: EditText
    private lateinit var sourceInput: EditText
    private lateinit var runButton: Button
    private lateinit var statusText: TextView
    private lateinit var resultText: TextView
    private val taskChecks = linkedMapOf<PrivacyAutomationTask, CheckBox>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(36))
        }
        root.addView(TextView(this).apply {
            text = "AI PRIVACY AUTOMATIONS"
            textSize = 17f
        })
        root.addView(body(
            "Optional, bring-your-own-key assistance. PrivaCage sends only the text you paste here, after a separate confirmation. " +
                "It never gives the model tools to change device settings, install apps, submit legal requests, or execute commands."
        ))
        root.addView(body(
            "Security: the key is encrypted at rest with a separate Android Keystore AES-256-GCM key and is not included in device sync or backups. " +
                "It must be available in app memory to make a request, so encryption cannot protect it from a compromised OS, rooted device, or malicious process. " +
                "The selected provider receives the text you submit and handles it under its own terms and privacy policy. API usage may incur charges."
        ))

        root.addView(heading("PROVIDER"))
        providerButton = Button(this).apply {
            isAllCaps = false
            setOnClickListener { chooseProvider() }
        }
        root.addView(providerButton, matchWidth())
        root.addView(body("Supported provider protocols: OpenAI, Anthropic, Google Gemini, Cohere, Mistral, Groq, DeepSeek, OpenRouter, xAI, Together AI, Fireworks AI, and Hugging Face Inference. Model availability and account access are controlled by each provider."))

        root.addView(heading("MODEL"))
        modelInput = EditText(this).apply {
            hint = "Provider model ID"
            singleLine = true
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            filters = arrayOf(InputFilter.LengthFilter(128))
        }
        root.addView(modelInput, matchWidth())

        root.addView(heading("API TOKEN"))
        apiKeyInput = EditText(this).apply {
            hint = "Paste provider API token"
            singleLine = true
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            filters = arrayOf(InputFilter.LengthFilter(4096))
        }
        root.addView(apiKeyInput, matchWidth())
        root.addView(body("Saved credentials are never displayed again. Leave this field empty to keep the already-saved key for the selected provider."))

        root.addView(heading("INTENDED USE"))
        purposeInput = EditText(this).apply {
            hint = "What should this key be used for? (optional note)"
            minLines = 2
            gravity = android.view.Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            filters = arrayOf(InputFilter.LengthFilter(500))
        }
        root.addView(purposeInput, matchWidth())
        root.addView(heading("PERMITTED AUTOMATIONS"))
        root.addView(body("Only checked tasks can use this provider key. Permissions are enforced by PrivaCage before a request is sent; the model cannot call device tools or perform actions."))
        PrivacyAutomationTask.values().forEach { task ->
            val check = CheckBox(this).apply {
                text = task.label
                isChecked = false
            }
            taskChecks[task] = check
            root.addView(check, matchWidth())
        }

        root.addView(Button(this).apply {
            text = "Save encrypted API token"
            setOnClickListener { saveCredential() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Forget token for this provider"
            setOnClickListener { forgetCredential() }
        }, matchWidth())

        root.addView(heading("RUN AN AUTOMATION"))
        taskButton = Button(this).apply {
            isAllCaps = false
            setOnClickListener { chooseTask() }
        }
        root.addView(taskButton, matchWidth())
        sourceInput = EditText(this).apply {
            hint = "Paste the Terms of Service, Privacy Policy, APK report, permission audit, DNS excerpt, or other text you want analysed."
            minLines = 7
            gravity = android.view.Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            filters = arrayOf(InputFilter.LengthFilter(48 * 1024))
        }
        root.addView(sourceInput, matchWidth())
        runButton = Button(this).apply {
            text = "Review supplied text"
            setOnClickListener { confirmAndRun() }
        }
        root.addView(runButton, matchWidth())

        statusText = body("No provider request has been made.")
        root.addView(statusText, matchWidth())
        resultText = TextView(this).apply {
            textSize = 14f
            setTextIsSelectable(true)
            setPadding(0, dp(12), 0, dp(12))
        }
        root.addView(resultText, matchWidth())

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
        }
        PrivaCageDesign.apply(this, root, scroll, statusText)
        scroll.addView(root)
        setContentView(scroll)

        selectedTask = PrivacyAutomationTask.values().firstOrNull {
            it.id == intent.getStringExtra(EXTRA_TASK_ID)
        } ?: PrivacyAutomationTask.PRIVACY_POLICY_REVIEW
        sourceInput.setText(intent.getStringExtra(EXTRA_SOURCE_TEXT).orEmpty())
        refreshSelectionLabels()
        loadSelectedProvider()
    }

    private fun chooseProvider() {
        val providers = ApiProvider.values()
        AlertDialog.Builder(this)
            .setTitle("Choose API provider")
            .setSingleChoiceItems(providers.map { it.label }.toTypedArray(), providers.indexOf(selectedProvider)) { dialog, which ->
                selectedProvider = providers[which]
                dialog.dismiss()
                loadSelectedProvider()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun chooseTask() {
        val tasks = PrivacyAutomationTask.values()
        AlertDialog.Builder(this)
            .setTitle("Choose automation")
            .setSingleChoiceItems(tasks.map { it.label }.toTypedArray(), tasks.indexOf(selectedTask)) { dialog, which ->
                selectedTask = tasks[which]
                dialog.dismiss()
                refreshSelectionLabels()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun refreshSelectionLabels() {
        providerButton.text = "Provider: " + selectedProvider.label
        taskButton.text = "Task: " + selectedTask.label
    }

    private fun loadSelectedProvider() {
        refreshSelectionLabels()
        try {
            val saved = vault.credential(selectedProvider)
            modelInput.setText(saved?.model.orEmpty())
            purposeInput.setText(saved?.purpose.orEmpty())
            apiKeyInput.setText("")
            PrivacyAutomationTask.values().forEach { task ->
                taskChecks[task]?.isChecked = saved?.allowedTasks?.contains(task) == true
            }
            statusText.text = if (saved == null) {
                "No API token is saved for " + selectedProvider.label + "."
            } else {
                "An encrypted token is saved for " + selectedProvider.label +
                    ". The secret is not read back into the input field."
            }
        } catch (exception: Exception) {
            statusText.text = "Could not read the encrypted API vault: " +
                (exception.message ?: exception.javaClass.simpleName) +
                ". Existing data was not replaced."
        }
    }

    private fun saveCredential() {
        val previous = try {
            vault.credential(selectedProvider)
        } catch (exception: Exception) {
            statusText.text = "Could not read the current encrypted token. Existing data was preserved: " +
                (exception.message ?: exception.javaClass.simpleName)
            return
        }
        val token = apiKeyInput.text.toString().trim().ifBlank { previous?.apiKey.orEmpty() }
        val allowed = taskChecks.filterValues { it.isChecked }.keys.toSet()
        val credential = StoredApiCredential(
            provider = selectedProvider,
            model = modelInput.text.toString().trim(),
            apiKey = token,
            purpose = purposeInput.text.toString().trim(),
            allowedTasks = allowed
        )
        try {
            ApiTokenVault.validateCredential(credential)
            vault.save(credential)
            apiKeyInput.setText("")
            statusText.text = "Encrypted provider credential and task permissions saved on this device. No network request was made."
        } catch (exception: Exception) {
            statusText.text = "The API token was not saved: " +
                (exception.message ?: exception.javaClass.simpleName)
        }
    }

    private fun forgetCredential() {
        AlertDialog.Builder(this)
            .setTitle("Forget " + selectedProvider.label + " token?")
            .setMessage("This deletes only the locally encrypted token and its permitted-task settings. It does not revoke the key at the provider.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Forget token") { _, _ ->
                try {
                    val removed = vault.delete(selectedProvider)
                    apiKeyInput.setText("")
                    modelInput.setText("")
                    purposeInput.setText("")
                    taskChecks.values.forEach { it.isChecked = false }
                    statusText.text = if (removed) {
                        "The local encrypted token was deleted. Revoke it separately with the provider if it may have been exposed."
                    } else {
                        "No local token existed for this provider."
                    }
                } catch (exception: Exception) {
                    statusText.text = "Could not delete the encrypted token: " +
                        (exception.message ?: exception.javaClass.simpleName)
                }
            }
            .show()
    }

    private fun confirmAndRun() {
        val source = sourceInput.text.toString()
        if (source.isBlank()) {
            statusText.text = "Paste the text you want analysed first."
            return
        }
        val credential = try {
            vault.credential(selectedProvider)
        } catch (exception: Exception) {
            statusText.text = "Could not load the encrypted API token: " +
                (exception.message ?: exception.javaClass.simpleName)
            return
        }
        if (credential == null) {
            statusText.text = "Save an API token for " + selectedProvider.label + " first."
            return
        }
        if (selectedTask !in credential.allowedTasks) {
            statusText.text = "This API key is not permitted to run " + selectedTask.label +
                ". Enable that task in Permitted Automations and save the settings."
            return
        }
        val preview = source.take(1800)
        val suffix = if (source.length > preview.length) "\n\n[Preview truncated; the full text in the input field will be sent.]" else ""
        val message = buildString {
            append("Provider: ").append(selectedProvider.label).append('\n')
            append("Model: ").append(credential.model).append('\n')
            append("Task: ").append(selectedTask.label).append('\n')
            append("Text length: ").append(source.length).append(" characters\n\n")
            append("Only the text in the input field is sent. No app inventory, files, DNS history, or other device data is attached automatically. ")
            append("The provider may process the text under its own terms. Usage may incur charges.\n\n")
            append(preview).append(suffix)
        }
        AlertDialog.Builder(this)
            .setTitle("Send text to " + selectedProvider.label + "?")
            .setMessage(message)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Send one request") { _, _ -> runAutomation(credential, selectedTask, source) }
            .show()
    }

    private fun runAutomation(
        credential: StoredApiCredential,
        task: PrivacyAutomationTask,
        source: String
    ) {
        runButton.isEnabled = false
        statusText.text = "Sending the confirmed text-only request to " + credential.provider.label + "..."
        resultText.text = ""
        Thread({
            val result = try {
                PrivacyAutomationClient.execute(credential, task, source) to null
            } catch (exception: Exception) {
                null to (exception.message ?: exception.javaClass.simpleName)
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                runButton.isEnabled = true
                val answer = result.first
                if (answer == null) {
                    statusText.text = "Automation failed: " + result.second
                } else {
                    statusText.text = "Response received from " + credential.provider.label +
                        ". No device action was performed."
                    resultText.text = answer
                }
            }
        }, "PrivaCage-privacy-automation").start()
    }

    private fun heading(value: String) = TextView(this).apply {
        text = value
        textSize = 15f
        setPadding(0, dp(18), 0, dp(6))
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

    companion object {
        const val EXTRA_TASK_ID = "org.privacage.android.extra.AI_TASK_ID"
        const val EXTRA_SOURCE_TEXT = "org.privacage.android.extra.AI_SOURCE_TEXT"
    }
}
