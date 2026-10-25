package org.privacage.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

class AppAlternativesActivity : Activity() {
    private val preferences by lazy { getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE) }
    private val selectedIds = linkedSetOf<String>()
    private val completedIds = linkedSetOf<String>()
    private val sourceSelections = mutableMapOf<String, String>()

    private var catalog: List<AppAlternative> = emptyList()
    private var activeReplacementFilter: String? = null
    private var stateWarning: String? = null
    private lateinit var catalogContainer: LinearLayout
    private lateinit var filterSpinner: Spinner
    private lateinit var statusView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        restoreSelectionState()
        try {
            catalog = AppAlternativeCatalog.load(this)
        } catch (exception: Exception) {
            stateWarning = listOfNotNull(
                stateWarning,
                "Catalogue load failed: " + (exception.message ?: exception.javaClass.simpleName)
            ).joinToString("\n")
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(TextView(this).apply { text = "PrivaCage" }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Choose privacy-oriented alternatives to Google apps, pick a trusted source, and process them one at a time. Choices and queue state remain on this device."
        }, matchWidth())

        root.addView(TextView(this).apply {
            text = "INSTALL QUEUE"
            setPadding(0, dp(18), 0, dp(4))
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Select the apps you want to replace. “Completed” is a manual reminder only; PrivaCage cannot verify that a store installed the app."
            textSize = 12f
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Open next selected source"
            setOnClickListener { openNextQueuedSource() }
        }, matchWidth())
        root.addView(Button(this).apply {
            text = "Clear selections and completion marks"
            setOnClickListener {
                AlertDialog.Builder(this@AppAlternativesActivity)
                    .setTitle("Clear local install queue?")
                    .setMessage("This removes only PrivaCage's saved selections and manual completion ticks. It does not uninstall any apps.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Clear queue") { _, _ ->
                        selectedIds.clear()
                        completedIds.clear()
                        sourceSelections.clear()
                        saveSelectionState()
                        renderAlternatives()
                        updateQueueStatus()
                    }
                    .show()
            }
        }, matchWidth())

        root.addView(TextView(this).apply {
            text = "ALTERNATIVE CATALOG"
            setPadding(0, dp(18), 0, dp(4))
        }, matchWidth())
        root.addView(TextView(this).apply {
            text = "Read the evidence and trade-offs for each option. A privacy-oriented label is not a certification, and the best choice depends on your threat model and configuration."
            textSize = 12f
        }, matchWidth())

        filterSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@AppAlternativesActivity,
                android.R.layout.simple_spinner_item,
                listOf("All Google apps") + catalog.map { it.replaces }.distinct().sorted()
            ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            setSelection(0, false)
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    activeReplacementFilter = if (position == 0) null else (parent?.getItemAtPosition(position) as? String)
                    if (::catalogContainer.isInitialized) renderAlternatives()
                }
            }
        }
        root.addView(filterSpinner, matchWidth())

        catalogContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(catalogContainer, matchWidth())

        statusView = TextView(this).apply {
            textSize = 13f
            setPadding(0, dp(12), 0, dp(4))
        }
        root.addView(statusView, matchWidth())

        renderAlternatives()
        updateQueueStatus()
        stateWarning?.let { warning ->
            statusView.text = warning + "\n\n" + statusView.text
        }

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        PrivaCageDesign.apply(this, root, scroll, statusView)
        scroll.addView(root)
        setContentView(scroll)
    }

    private fun renderAlternatives() {
        if (!::catalogContainer.isInitialized) return
        catalogContainer.removeAllViews()
        val visible = catalog.filter { activeReplacementFilter == null || it.replaces == activeReplacementFilter }
        if (visible.isEmpty()) {
            catalogContainer.addView(TextView(this).apply {
                text = if (catalog.isEmpty()) {
                    "No alternative links are available because the bundled catalogue failed validation."
                } else {
                    "No alternatives match this filter."
                }
                setTextColor(Color.LTGRAY)
                setPadding(0, dp(12), 0, dp(12))
            }, matchWidth())
            return
        }

        for (alternative in visible) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(13), dp(12), dp(13), dp(12))
                background = GradientDrawable().apply {
                    setColor(Color.rgb(17, 17, 17))
                    setStroke(dp(1), Color.rgb(50, 50, 50))
                    cornerRadius = dp(14).toFloat()
                }
            }
            val selected = CheckBox(this).apply {
                text = alternative.name + "  ·  replaces " + alternative.replaces
                isChecked = alternative.id in selectedIds
                setTextColor(Color.WHITE)
                textSize = 14f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                minHeight = dp(48)
                setOnCheckedChangeListener { _, checked ->
                    if (checked) selectedIds.add(alternative.id) else selectedIds.remove(alternative.id)
                    saveSelectionState()
                    updateQueueStatus()
                }
            }
            card.addView(selected, matchWidth())

            card.addView(TextView(this).apply {
                text = alternative.category.uppercase()
                textSize = 10f
                letterSpacing = 0.06f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.LTGRAY)
                setPadding(dp(2), dp(3), 0, dp(5))
            }, matchWidth())
            card.addView(TextView(this).apply {
                text = alternative.summary
                textSize = 12f
                setTextColor(Color.rgb(220, 220, 220))
                setLineSpacing(dp(2).toFloat(), 1f)
            }, matchWidth())
            card.addView(TextView(this).apply {
                text = "TRADE-OFFS\n" + alternative.tradeoffs
                textSize = 11f
                setTextColor(Color.rgb(170, 170, 170))
                setPadding(0, dp(7), 0, dp(4))
                setLineSpacing(dp(2).toFloat(), 1f)
            }, matchWidth())

            card.addView(TextView(this).apply {
                text = "INSTALL SOURCE"
                textSize = 10f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.LTGRAY)
                setPadding(0, dp(5), 0, 0)
            }, matchWidth())

            val sourceSpinner = Spinner(this)
            val labels = alternative.sources.map { it.label }
            sourceSpinner.adapter = ArrayAdapter(
                this,
                android.R.layout.simple_spinner_item,
                labels
            ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            val savedSource = sourceSelections[alternative.id]
            val savedIndex = alternative.sources.indexOfFirst { it.id == savedSource }
            val defaultIndex = alternative.sources.indexOfFirst { it.id == "play" }
                .takeIf { it >= 0 }
                ?: alternative.sources.indexOfFirst { it.id == "fdroid" }
                    .takeIf { it >= 0 }
                ?: 0
            sourceSpinner.setSelection(if (savedIndex >= 0) savedIndex else defaultIndex, false)
            var spinnerReady = false
            sourceSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    if (!spinnerReady) return
                    alternative.sources.getOrNull(position)?.let { source ->
                        sourceSelections[alternative.id] = source.id
                        saveSelectionState()
                    }
                }
            }
            spinnerReady = true
            card.addView(sourceSpinner, matchWidth())

            val completion = CheckBox(this).apply {
                text = "I completed this install"
                isChecked = alternative.id in completedIds
                setTextColor(Color.LTGRAY)
                textSize = 12f
                setOnCheckedChangeListener { _, checked ->
                    if (checked) completedIds.add(alternative.id) else completedIds.remove(alternative.id)
                    saveSelectionState()
                    updateQueueStatus()
                }
            }
            card.addView(completion, matchWidth())

            card.addView(Button(this).apply {
                text = "Open evidence and project information"
                setOnClickListener { openTrustedUrl(alternative.evidenceUrl, "Evidence page opened.") }
            }, matchWidth())

            val params = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(10) }
            catalogContainer.addView(card, params)
        }
    }

    private fun openNextQueuedSource() {
        val next = catalog.firstOrNull { it.id in selectedIds && it.id !in completedIds }
        if (next == null) {
            val message = if (selectedIds.isEmpty()) {
                "Choose at least one app alternative to start the queue."
            } else {
                "Every selected item is manually marked completed. Untick one item to reopen its source."
            }
            statusView.text = message
            Toast.makeText(this, message, Toast.LENGTH_LONG).show()
            return
        }
        val selectedSourceId = sourceSelections[next.id]
        val source = next.sources.firstOrNull { it.id == selectedSourceId } ?: next.sources.first()
        openTrustedUrl(
            source.url,
            "Opened " + source.label + " for " + next.name +
                ". Complete the download/install in that source, then return and mark it completed. PrivaCage does not verify installation."
        )
    }

    private fun openTrustedUrl(url: String, statusMessage: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            statusView.text = statusMessage
        } catch (exception: ActivityNotFoundException) {
            statusView.text = "No installed app can open this HTTPS link. URL was not downloaded: " + url
            Toast.makeText(this, "No browser or store is available to open this link.", Toast.LENGTH_LONG).show()
        } catch (exception: SecurityException) {
            statusView.text = "Android refused to open the selected source: " +
                (exception.message ?: "permission denied")
        }
    }

    private fun updateQueueStatus() {
        if (!::statusView.isInitialized) return
        val queued = selectedIds.size
        val completed = selectedIds.count { it in completedIds }
        statusView.text = "Selected: " + queued + "  /  manually marked complete: " + completed +
            "\nQueue items open one official/project page at a time. The source app controls download and installation; no APK is silently fetched or installed."
    }

    private fun restoreSelectionState() {
        try {
            val selectedJson = JSONArray(preferences.getString(KEY_SELECTED, "[]") ?: "[]")
            for (index in 0 until selectedJson.length()) {
                selectedJson.optString(index).takeIf { it.matches(ID_PATTERN) }?.let(selectedIds::add)
            }
            val completedJson = JSONArray(preferences.getString(KEY_COMPLETED, "[]") ?: "[]")
            for (index in 0 until completedJson.length()) {
                completedJson.optString(index).takeIf { it.matches(ID_PATTERN) }?.let(completedIds::add)
            }
            val sourcesJson = JSONObject(preferences.getString(KEY_SOURCES, "{}") ?: "{}")
            val iterator = sourcesJson.keys()
            while (iterator.hasNext()) {
                val key = iterator.next()
                val value = sourcesJson.optString(key)
                if (key.matches(ID_PATTERN) && value in setOf("play", "fdroid", "official", "github", "gitlab")) {
                    sourceSelections[key] = value
                }
            }
        } catch (exception: JSONException) {
            stateWarning = "Saved alternative queue was malformed and has been discarded: " +
                (exception.message ?: "invalid local preference data")
            selectedIds.clear()
            completedIds.clear()
            sourceSelections.clear()
            preferences.edit().remove(KEY_SELECTED).remove(KEY_COMPLETED).remove(KEY_SOURCES).apply()
        }
    }

    private fun saveSelectionState() {
        val selectedJson = JSONArray()
        selectedIds.sorted().forEach(selectedJson::put)
        val completedJson = JSONArray()
        completedIds.sorted().forEach(completedJson::put)
        val sourcesJson = JSONObject()
        sourceSelections.toSortedMap().forEach { (key, value) -> sourcesJson.put(key, value) }
        preferences.edit()
            .putString(KEY_SELECTED, selectedJson.toString())
            .putString(KEY_COMPLETED, completedJson.toString())
            .putString(KEY_SOURCES, sourcesJson.toString())
            .apply()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    companion object {
        private const val PREFERENCES_NAME = "privacage_alternative_install_queue"
        private const val KEY_SELECTED = "selected_alternative_ids"
        private const val KEY_COMPLETED = "completed_alternative_ids"
        private const val KEY_SOURCES = "alternative_source_selections"
        private val ID_PATTERN = Regex("^[a-z0-9]+(?:-[a-z0-9]+)*$")
    }
}
