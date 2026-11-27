package org.privacage.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import org.privacage.security.AndroidPwnedPasswordDocumentAccess
import org.privacage.security.AndroidPwnedManifestAttestor
import org.privacage.security.PwnedPasswordManifestAttestation
import org.privacage.security.PwnedPasswordExposureResult
import org.privacage.security.PwnedPasswordExposureStatus
import org.privacage.security.PwnedPasswordInput
import org.privacage.security.PwnedPasswordCheckLifecycle
import org.privacage.security.PwnedPasswordRangeLookup
import org.privacage.security.PwnedPasswordSafSnapshot
import java.io.IOException
import java.io.InterruptedIOException
import java.nio.charset.StandardCharsets
import java.lang.ref.WeakReference

class PwnedPasswordCheckActivity : Activity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile private var destroyed = false
    private var worker: Thread? = null
    @Volatile private var providerCancellationSignal: CancellationSignal? = null
    private var checking = false
    private var exportingAttestation = false
    private var verifiedManifestSha256: String? = null
    @Volatile private var cancellationRequested = false
    private var selectedManifestUri: Uri? = null
    private var selectedRangeUri: Uri? = null

    private lateinit var manifestSelectionText: TextView
    private lateinit var rangeSelectionText: TextView
    private lateinit var expectedDigestInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var checkButton: Button
    private lateinit var cancelButton: Button
    private lateinit var attestationButton: Button
    private lateinit var progressIndicator: ProgressBar
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(36))
        }
        root.addView(heading("OFFLINE PASSWORD EXPOSURE"))
        root.addView(body(
            "Checks one password against a user-supplied Have I Been Pwned Pwned Passwords SHA-1 snapshot. " +
                "This is not an email/account breach search, password-strength test, or guarantee of safety."
        ))
        root.addView(body(
            "LOCAL CHECK · PrivaCage sends no password or dataset upload. The selected document provider may be " +
                "cloud-backed and can observe the manifest/range reads. Only those two bounded files are copied " +
                "into short-lived app-private cache and removed when the snapshot closes."
        ))
        root.addView(body(
            "The manifest SHA-256 must be retained independently and entered below. It is a local integrity anchor, " +
                "not a HIBP publisher signature and not proof of source completeness or freshness."
        ))

        val manifestButton = controlButton("Choose full-range manifest") { openDocument(REQUEST_MANIFEST) }
        root.addView(manifestButton, matchWidth())
        manifestSelectionText = body("Manifest: not selected.")
        root.addView(manifestSelectionText, matchWidth())

        val rangeButton = controlButton("Choose one PREFIX.txt range") { openDocument(REQUEST_RANGE) }
        root.addView(rangeButton, matchWidth())
        rangeSelectionText = body("Range: not selected.")
        root.addView(rangeSelectionText, matchWidth())

        root.addView(heading("INDEPENDENT MANIFEST DIGEST"))
        expectedDigestInput = textInput(
            "64-character SHA-256",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
            64
        )
        root.addView(expectedDigestInput, matchWidth())

        root.addView(heading("PASSWORD"))
        passwordInput = textInput(
            "Enter one password for this local check",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
            PwnedPasswordRangeLookup.MAX_PASSWORD_CHARS
        ).apply {
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            imeOptions = PwnedPasswordInput.requestNoPersonalizedLearning(imeOptions)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                setImportantForContentCapture(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO)
            }
            setSingleLine(true)
        }
        root.addView(passwordInput, matchWidth())
        root.addView(body(
            "The field is not saved in view state or offered to Android autofill. It requests that the keyboard not " +
                "personalize from this field and, on Android 10+, is marked not important for Android Content Capture. " +
                "An input method may ignore the learning request and still receives typed characters; PrivaCage cannot " +
                "guarantee that keyboard or other system buffers are zeroized."
        ))

        checkButton = controlButton("Check selected snapshot") { runCheck() }.apply { isEnabled = false }
        root.addView(checkButton, matchWidth())
        cancelButton = controlButton("Cancel operation") { cancelCheck() }.apply { visibility = View.GONE }
        root.addView(cancelButton, matchWidth())
        attestationButton = controlButton("Export local manifest attestation") { openAttestationExport() }.apply {
            visibility = View.GONE
        }
        root.addView(attestationButton, matchWidth())
        root.addView(body(
            "A local attestation binds only the manifest SHA-256 to a dedicated Android Keystore key. " +
                "It does not authenticate HIBP or prove every range was checked. Record the public-key fingerprint separately."
        ))

        progressIndicator = ProgressBar(this).apply {
            isIndeterminate = true
            indeterminateTintList = ColorStateList.valueOf(Color.WHITE)
            visibility = View.GONE
            contentDescription = "Verifying the local password snapshot"
        }
        root.addView(progressIndicator, LinearLayout.LayoutParams(dp(28), dp(28)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            topMargin = dp(10)
            bottomMargin = dp(4)
        })

        statusText = body("No check run. Results are transient and are not saved.")
        statusText.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        root.addView(statusText, matchWidth())
        root.addView(controlButton("Close check") { finish() }, matchWidth())

        attachAvailabilityWatcher(expectedDigestInput)
        expectedDigestInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                verifiedManifestSha256 = null
                if (::attestationButton.isInitialized) attestationButton.visibility = View.GONE
                updateCheckButton()
            }
            override fun afterTextChanged(s: Editable?) = Unit
        })
        attachAvailabilityWatcher(passwordInput)
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        PrivaCageDesign.apply(this, root, scroll, statusText)
        listOf(manifestButton, rangeButton, checkButton, cancelButton, attestationButton).forEach {
            PrivaCageDesign.styleControl(this, it)
        }
        scroll.addView(root)
        setContentView(scroll)
        updateCheckButton()
    }

    private fun openDocument(requestCode: Int) {
        if (checking || exportingAttestation) return
        try {
            startActivityForResult(
                Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                },
                requestCode
            )
        } catch (exception: ActivityNotFoundException) {
            statusText.text = "Android did not provide a compatible document picker."
        } catch (exception: SecurityException) {
            statusText.text = "Android did not allow the document picker to open."
        }
    }

    @Deprecated("Uses the platform Activity result contract without adding an Activity Result dependency.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) return
        val uri = data?.data
        if (uri == null || uri.scheme != "content") {
            statusText.text = "Select a readable content:// document. No file was imported."
            return
        }
        if (requestCode == REQUEST_ATTESTATION_EXPORT) {
            val digest = verifiedManifestSha256
            if (digest == null) {
                statusText.text = "ATTESTATION UNAVAILABLE · Run a successful snapshot check before exporting."
                return
            }
            exportAttestation(uri, digest)
            return
        }
        verifiedManifestSha256 = null
        attestationButton.visibility = View.GONE
        when (requestCode) {
            REQUEST_MANIFEST -> {
                selectedManifestUri = uri
                manifestSelectionText.text = "Manifest: selected. It will be streamed and verified before use."
            }
            REQUEST_RANGE -> {
                selectedRangeUri = uri
                rangeSelectionText.text = "Range: selected. Its uppercase PREFIX.txt name is checked before use."
            }
            else -> return
        }
        statusText.text = "Document selection updated. No file has been read yet."
        updateCheckButton()
    }

    private fun runCheck() {
        if (checking) return
        val manifestUri = selectedManifestUri
        val rangeUri = selectedRangeUri
        if (manifestUri == null || rangeUri == null) {
            statusText.text = "Choose both the manifest and one range file."
            return
        }
        val expectedDigest = expectedDigestInput.text.toString().trim()
        if (!expectedDigest.matches(Regex("[0-9A-Fa-f]{64}"))) {
            statusText.text = "Enter the independently retained 64-character manifest SHA-256."
            return
        }
        verifiedManifestSha256 = null
        attestationButton.visibility = View.GONE

        val password = PwnedPasswordInput.takeAndClear(passwordInput.text) { passwordInput.text.clear() }
        if (password.isEmpty()) {
            statusText.text = "Enter a password. The field has been cleared."
            updateCheckButton()
            return
        }

        cancellationRequested = false
        val operationCancellationSignal = CancellationSignal()
        providerCancellationSignal = operationCancellationSignal
        checking = true
        expectedDigestInput.isEnabled = false
        passwordInput.isEnabled = false
        checkButton.isEnabled = false
        cancelButton.isEnabled = true
        cancelButton.visibility = View.VISIBLE
        progressIndicator.visibility = View.VISIBLE
        statusText.text = "Verifying the complete manifest and selected range locally. This can take time."

        val appContext = applicationContext
        val activityReference = WeakReference(this)
        val handler = mainHandler
        val task = Thread({
            var result: PwnedPasswordExposureResult? = null
            var failure: Exception? = null
            var cancelled = false
            try {
                PwnedPasswordSafSnapshot.prepare(
                    manifestUri = manifestUri.toString(),
                    expectedManifestSha256 = expectedDigest,
                    rangeUri = rangeUri.toString(),
                    documents = AndroidPwnedPasswordDocumentAccess(appContext.contentResolver, operationCancellationSignal),
                    cacheDirectory = appContext.cacheDir.toPath()
                ).use { snapshot ->
                    result = snapshot.checkAndClear(password)
                }
                if (Thread.currentThread().isInterrupted) {
                    throw InterruptedIOException("Password snapshot check was cancelled.")
                }
            } catch (exception: Exception) {
                if (exception is InterruptedIOException || Thread.currentThread().isInterrupted) {
                    cancelled = true
                } else {
                    failure = exception
                }
            } finally {
                password.fill('\u0000')
            }

            val activity = activityReference.get() ?: return@Thread
            handler.post {
                if (activity.destroyed || activity.isFinishing || activity.isDestroyed) return@post
                activity.checking = false
                activity.worker = null
                activity.providerCancellationSignal = null
                activity.progressIndicator.visibility = View.GONE
                activity.cancelButton.visibility = View.GONE
                activity.cancelButton.isEnabled = true
                activity.expectedDigestInput.isEnabled = true
                activity.passwordInput.isEnabled = true
                activity.updateCheckButton()
                when {
                    cancelled || activity.cancellationRequested -> activity.statusText.text =
                        "CANCELLED · The snapshot was not reported as a match or no-match. Temporary-file cleanup was attempted."
                    failure != null -> activity.statusText.text =
                        "CHECK UNAVAILABLE · " + (failure?.message ?: "The selected snapshot could not be verified.") +
                            " No clean/no-match result was produced."
                    result != null -> {
                        activity.verifiedManifestSha256 = expectedDigest.uppercase()
                        activity.attestationButton.visibility = View.VISIBLE
                        activity.updateCheckButton()
                        activity.renderResult(result!!)
                    }
                    else -> activity.statusText.text = "CHECK UNAVAILABLE · No verified result was produced."
                }
            }
        }, "PrivaCage-offline-password-check")
        task.isDaemon = true
        worker = task
        task.start()
    }


    private fun openAttestationExport() {
        val digest = verifiedManifestSha256
        if (digest == null || checking || exportingAttestation) {
            statusText.text = "ATTESTATION UNAVAILABLE · Complete a successful snapshot check first."
            return
        }
        try {
            startActivityForResult(
                Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/json"
                    putExtra(Intent.EXTRA_TITLE, "pcage-pwned-manifest-attestation.json")
                    addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                },
                REQUEST_ATTESTATION_EXPORT
            )
        } catch (exception: ActivityNotFoundException) {
            statusText.text = "Android did not provide a compatible document destination."
        } catch (exception: SecurityException) {
            statusText.text = "Android did not allow the attestation destination picker to open."
        }
    }

    private fun exportAttestation(destination: Uri, manifestSha256: String) {
        if (checking || exportingAttestation) return
        cancellationRequested = false
        val operationCancellationSignal = CancellationSignal()
        providerCancellationSignal = operationCancellationSignal
        exportingAttestation = true
        checkButton.isEnabled = false
        attestationButton.isEnabled = false
        expectedDigestInput.isEnabled = false
        passwordInput.isEnabled = false
        cancelButton.isEnabled = true
        cancelButton.visibility = View.VISIBLE
        progressIndicator.visibility = View.VISIBLE
        statusText.text = "Creating a local P-256 attestation and writing it to the selected document provider."

        val appContext = applicationContext
        val activityReference = WeakReference(this)
        val handler = mainHandler
        val task = Thread({
            var signerFingerprint: String? = null
            var failure: Exception? = null
            var cancelled = false
            var outputBytes: ByteArray? = null
            try {
                val attestation = AndroidPwnedManifestAttestor.sign(manifestSha256)
                signerFingerprint = attestation.signerPublicKeySha256
                outputBytes = attestation.json.toByteArray(StandardCharsets.UTF_8)
                if (outputBytes!!.size > PwnedPasswordManifestAttestation.MAX_BYTES) {
                    throw IOException("The local attestation exceeds the 4 KiB output limit.")
                }
                if (Thread.currentThread().isInterrupted || operationCancellationSignal.isCanceled) {
                    throw InterruptedIOException("Attestation export was cancelled.")
                }
                val descriptor = appContext.contentResolver.openFileDescriptor(
                    destination,
                    "wt",
                    operationCancellationSignal
                ) ?: throw IOException("The selected document provider did not open a writable destination.")
                ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
                    output.write(outputBytes!!)
                    output.flush()
                }
                if (Thread.currentThread().isInterrupted || operationCancellationSignal.isCanceled) {
                    throw InterruptedIOException("Attestation export was cancelled.")
                }
            } catch (exception: Exception) {
                if (exception is InterruptedIOException ||
                    Thread.currentThread().isInterrupted ||
                    operationCancellationSignal.isCanceled
                ) {
                    cancelled = true
                } else {
                    failure = exception
                }
            } finally {
                outputBytes?.fill(0)
            }

            val activity = activityReference.get() ?: return@Thread
            handler.post {
                if (activity.destroyed || activity.isFinishing || activity.isDestroyed) return@post
                activity.exportingAttestation = false
                activity.worker = null
                activity.providerCancellationSignal = null
                activity.progressIndicator.visibility = View.GONE
                activity.cancelButton.visibility = View.GONE
                activity.cancelButton.isEnabled = true
                activity.expectedDigestInput.isEnabled = true
                activity.passwordInput.isEnabled = true
                activity.updateCheckButton()
                when {
                    cancelled || activity.cancellationRequested -> activity.statusText.text =
                        "CANCELLED · The destination may contain an incomplete attestation. Do not trust it; remove it before retrying."
                    failure != null -> activity.statusText.text =
                        "ATTESTATION EXPORT FAILED · " + (failure?.message ?: "The selected destination could not be written.") +
                            " The destination may be empty or incomplete."
                    signerFingerprint != null -> activity.statusText.text =
                        "ATTESTATION EXPORTED · Manifest SHA-256: " + manifestSha256.uppercase() +
                            "\nSigner public-key SHA-256: " + signerFingerprint +
                            "\nConfirm this fingerprint through a separate trusted channel. The signature does not authenticate HIBP, " +
                            "prove source completeness/freshness, or show that every range file was checked."
                    else -> activity.statusText.text = "ATTESTATION EXPORT FAILED · No verified attestation was produced."
                }
            }
        }, "PrivaCage-pwned-attestation-export")
        task.isDaemon = true
        worker = task
        task.start()
    }

    private fun requestCancellation(message: String) {
        if (!PwnedPasswordCheckLifecycle.requestCancellation(worker) {
                providerCancellationSignal?.cancel()
            }) return
        cancellationRequested = true
        cancelButton.isEnabled = false
        statusText.text = message
    }

    private fun cancelCheck() {
        requestCancellation(
            "Cancellation requested. The provider receives an Android cancellation signal, but a provider that ignores it may still delay a blocked operation."
        )
    }

    private fun renderResult(result: PwnedPasswordExposureResult) {
        statusText.text = when (result.status) {
            PwnedPasswordExposureStatus.FOUND ->
                "FOUND IN SUPPLIED SNAPSHOT · ${result.snapshotDate}\n" +
                    "Corpus occurrence count: ${result.occurrences}\n" +
                    "This count is from the supplied corpus; it is not a count of your use."
            PwnedPasswordExposureStatus.NOT_FOUND_IN_SNAPSHOT ->
                "NOT FOUND IN SUPPLIED SNAPSHOT · ${result.snapshotDate}\n" +
                    "This only means the hash was absent from this supplied snapshot. It does not establish that " +
                    "the password is safe, strong, unused, or absent from a newer or different dataset."
        }
    }

    private fun updateCheckButton() {
        if (!::checkButton.isInitialized || !::expectedDigestInput.isInitialized || !::passwordInput.isInitialized) return
        val digestValid = expectedDigestInput.text.toString().trim().matches(Regex("[0-9A-Fa-f]{64}"))
        val busy = checking || exportingAttestation
        checkButton.isEnabled = !busy && selectedManifestUri != null && selectedRangeUri != null &&
            digestValid && passwordInput.text.isNotEmpty()
        if (::attestationButton.isInitialized) {
            attestationButton.isEnabled = !busy && verifiedManifestSha256 != null
        }
    }

    private fun attachAvailabilityWatcher(input: EditText) {
        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = updateCheckButton()
            override fun afterTextChanged(s: Editable?) = Unit
        })
    }

    override fun onPause() {
        if (checking || exportingAttestation) {
            requestCancellation(
                "FOREGROUND LOST · Worker interruption and an Android provider-cancellation signal were requested. A provider that ignores cancellation may still delay cleanup."
            )
        }
        if (::passwordInput.isInitialized) {
            passwordInput.text.clear()
            updateCheckButton()
        }
        super.onPause()
    }

    override fun onDestroy() {
        destroyed = true
        worker?.interrupt()
        providerCancellationSignal?.cancel()
        providerCancellationSignal = null
        if (::passwordInput.isInitialized) passwordInput.text.clear()
        super.onDestroy()
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

    private fun textInput(hint: String, inputType: Int, maximumLength: Int) = EditText(this).apply {
        this.hint = hint
        this.inputType = inputType
        filters = arrayOf(InputFilter.LengthFilter(maximumLength))
        textSize = 12f
        setTextColor(Color.WHITE)
        setHintTextColor(0xff888888.toInt())
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        setPadding(dp(12), dp(10), dp(12), dp(10))
    }

    private fun controlButton(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { action() }
        PrivaCageDesign.styleControl(this@PwnedPasswordCheckActivity, this)
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    companion object {
        private const val REQUEST_MANIFEST = 8101
        private const val REQUEST_RANGE = 8102
        private const val REQUEST_ATTESTATION_EXPORT = 8103
    }
}
