package org.privacage.android

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

class LegalPrivacyActivity : Activity() {
    private data class PolicyDocument(
        val title: String,
        val buttonLabel: String,
        val assetName: String
    )

    private val documents = listOf(
        PolicyDocument("Terms of Service", "TERMS", "TERMS_OF_SERVICE.md"),
        PolicyDocument("Privacy Policy", "PRIVACY", "PRIVACY_POLICY.md"),
        PolicyDocument("Strict No-Telemetry Policy", "NO TELEMETRY", "NO_TELEMETRY_POLICY.md"),
        PolicyDocument("Data Retention and Encryption", "RETENTION", "DATA_RETENTION_AND_ENCRYPTION.md"),
        PolicyDocument("Authority and Legal-Request Policy", "AUTHORITIES", "AUTHORITY_REQUESTS.md"),
        PolicyDocument("External Services and Data Flows", "SERVICES", "EXTERNAL_SERVICES.md")
    )

    private lateinit var documentTitle: TextView
    private lateinit var documentText: TextView
    private lateinit var statusText: TextView
    private val maximumDocumentBytes = 256 * 1024

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(36))
        }
        root.addView(TextView(this).apply {
            text = "LEGAL & PRIVACY"
            textSize = 17f
        })
        root.addView(body(
            "These policies are packaged inside this PrivaCage installation. Opening a document reads a local asset; " +
                "it does not contact a policy server or send usage data."
        ))
        root.addView(body(
            "The current set is marked DRAFT. The project controller's legal name, postal address, privacy contact, " +
                "lawful bases, actual service operators and effective date must be completed and reviewed before release."
        ))

        val navigation = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        documents.forEach { document ->
            navigation.addView(Button(this).apply {
                text = document.buttonLabel
                isAllCaps = false
                setOnClickListener { loadDocument(document) }
            }, matchWidth())
        }
        root.addView(navigation, matchWidth())

        documentTitle = TextView(this).apply {
            textSize = 16f
            setPadding(0, dp(18), 0, dp(8))
        }
        root.addView(documentTitle, matchWidth())

        documentText = TextView(this).apply {
            textSize = 13f
            setTextIsSelectable(true)
            setLineSpacing(dp(3).toFloat(), 1f)
            setPadding(0, dp(4), 0, dp(14))
        }
        root.addView(documentText, matchWidth())

        statusText = body("Policy documents are stored in this app installation.")
        root.addView(statusText, matchWidth())

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
        }
        PrivaCageDesign.apply(this, root, scroll, statusText)
        scroll.addView(root)
        setContentView(scroll)

        val requested = documents.firstOrNull {
            it.assetName == intent.getStringExtra(EXTRA_DOCUMENT)
        } ?: documents.first { it.assetName == "PRIVACY_POLICY.md" }
        loadDocument(requested)
    }

    private fun loadDocument(document: PolicyDocument) {
        try {
            val markdown = readAsset(document.assetName)
            documentTitle.text = document.title
            documentText.text = renderMarkdown(markdown)
            statusText.text = "Read locally from the packaged " + document.assetName + " document. No network request was made."
        } catch (exception: Exception) {
            documentTitle.text = document.title
            documentText.text = "This document could not be read from the app installation. The packaged document was not modified."
            statusText.text = "Policy document read failed: " +
                (exception.message ?: exception.javaClass.simpleName)
        }
    }

    private fun readAsset(name: String): String {
        val bytes = assets.open(name).use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8 * 1024)
            try {
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() > maximumDocumentBytes - count) {
                        throw IOException("The packaged policy document exceeds the supported size.")
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            } finally {
                buffer.fill(0)
            }
        }
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } finally {
            bytes.fill(0)
        }
    }

    private fun renderMarkdown(markdown: String): CharSequence {
        val output = SpannableStringBuilder()
        markdown.lineSequence().forEach { rawLine ->
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) {
                output.append('\n')
                return@forEach
            }
            if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
                val cells = trimmed.removePrefix("|").removeSuffix("|")
                    .split("|")
                    .map(String::trim)
                if (cells.all { it.isNotEmpty() && it.all { ch -> ch == '-' || ch == ':' } }) {
                    return@forEach
                }
                output.append(cells.joinToString("  •  ") { cleanInline(it) }).append('\n')
                return@forEach
            }

            val headingLevel = trimmed.takeWhile { it == '#' }.length
            if (headingLevel in 1..4 && trimmed.length > headingLevel && trimmed[headingLevel] == ' ') {
                val title = cleanInline(trimmed.drop(headingLevel).trim())
                val start = output.length
                output.append(title).append('\n')
                output.setSpan(StyleSpan(Typeface.BOLD), start, output.length - 1, 0)
                output.setSpan(
                    RelativeSizeSpan(if (headingLevel == 1) 1.18f else if (headingLevel == 2) 1.08f else 1.0f),
                    start,
                    output.length - 1,
                    0
                )
                output.append('\n')
                return@forEach
            }

            val content = when {
                trimmed.startsWith("- ") || trimmed.startsWith("* ") -> "• " + cleanInline(trimmed.drop(2))
                trimmed.startsWith("> ") -> cleanInline(trimmed.drop(2))
                else -> cleanInline(trimmed)
            }
            output.append(content).append('\n')
        }
        return output
    }

    private fun cleanInline(value: String): String {
        val withoutLinks = Regex("\\[([^\\]]+)]\\(([^)]+)\\)").replace(value) { match ->
            match.groupValues[1] + " (" + match.groupValues[2] + ")"
        }
        return withoutLinks.replace("**", "").replace("__", "").filter { it != 96.toChar() }
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
        const val EXTRA_DOCUMENT = "org.privacage.android.extra.LEGAL_DOCUMENT"
    }
}
