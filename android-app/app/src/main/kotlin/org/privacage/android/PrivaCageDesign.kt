package org.privacage.android

import android.animation.ValueAnimator
import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.graphics.drawable.StateListDrawable
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.util.Locale

/**
 * Shared monochrome presentation layer for the existing native Android controls.
 *
 * This decorates the existing view instances instead of replacing them, so current
 * listeners, state, and privacy operations remain connected to their real services.
 */
internal object PrivaCageDesign {
    private val pageBackground = Color.BLACK
    private val surfaceBackground = Color.BLACK
    private val inputSurfaceColor = Color.BLACK
    private val border = Color.WHITE
    private val textPrimary = Color.WHITE
    private val textSecondary = Color.WHITE
    private val textMuted = Color.WHITE
    private val ink = Color.BLACK

    private val sectionHeadings = setOf(
        "LEGAL & PRIVACY",
        "ANDROID PRIVACY CONTROLS",
        "DEVICE PRIVACY SNAPSHOT (LOCAL ONLY)",
        "PRIVACY HARDENING",
        "DNS PRIVACY",
        "DNS ROUTE DIAGNOSTICS",
        "PRIVACY AUDIT EXPORT",
        "ENCRYPTED DEVICE SYNC",
        "INSTALL QUEUE",
        "APP POLICY REVIEW",
        "APP POLICY REVIEW QUEUE",
        "MONITORING ACCESS REVIEW",
        "ACCESSIBILITY SERVICES",
        "ACTIVE DEVICE ADMINISTRATORS",
        "NOTIFICATION LISTENERS",
        "DEFAULT NETWORK VPN STATE",
        "INTERPRETATION",
        "ALTERNATIVE CATALOG"
    )

    private val primaryActionLabels = setOf(
        "save configuration",
        "enable dns filtering",
        "review installed and opened apps' policies",
        "review monitoring-sensitive access",
        "run local review"
    )

    private data class SectionCard(
        val heading: String,
        val view: LinearLayout
    )

    fun apply(
        activity: Activity,
        root: LinearLayout,
        scrollView: ScrollView,
        statusView: TextView
    ) {
        val originalViews = (0 until root.childCount).map(root::getChildAt)
        root.removeAllViews()
        root.orientation = LinearLayout.VERTICAL
        root.setBackgroundColor(pageBackground)
        root.setPadding(dp(activity, 18), dp(activity, 22), dp(activity, 18), dp(activity, 36))
        scrollView.setBackgroundColor(pageBackground)
        scrollView.isFillViewport = true
        scrollView.isVerticalScrollBarEnabled = false
        scrollView.overScrollMode = View.OVER_SCROLL_NEVER

        val hero = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(activity, 6))
        }
        val eyebrow = TextView(activity).apply {
            text = "LOCAL-FIRST  /  EVIDENCE-LED"
            textSize = 10f
            letterSpacing = 0.12f
            setTextColor(textMuted)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            setPadding(0, 0, 0, dp(activity, 10))
        }
        hero.addView(eyebrow, wrapContent())

        val brandRow = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val mark = TextView(activity).apply {
            text = "⠿"
            textSize = 28f
            setTextColor(textPrimary)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            gravity = Gravity.CENTER
            contentDescription = "PrivaCage mark"
        }
        brandRow.addView(mark, LinearLayout.LayoutParams(dp(activity, 36), dp(activity, 42)).apply {
            rightMargin = dp(activity, 9)
        })

        val title = originalViews.getOrNull(0) as? TextView
        if (title != null) {
            title.textSize = 30f
            title.setTextColor(textPrimary)
            title.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            title.setPadding(0, 0, 0, 0)
            title.includeFontPadding = false
            brandRow.addView(title, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ))
        }
        hero.addView(brandRow, wrapContent())

        val subtitle = originalViews.getOrNull(1) as? TextView
        if (subtitle != null) {
            subtitle.textSize = 13f
            subtitle.setTextColor(textSecondary)
            subtitle.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
            subtitle.setLineSpacing(dp(activity, 2).toFloat(), 1f)
            subtitle.setPadding(0, dp(activity, 9), 0, dp(activity, 12))
            hero.addView(subtitle, matchWidth())
        }
        val divider = View(activity).apply { setBackgroundColor(border) }
        hero.addView(divider, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(activity, 1)
        ))
        root.addView(hero, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = dp(activity, 12) })

        val sections = mutableListOf<SectionCard>()
        var currentCard: LinearLayout? = null
        var sectionNumber = 0

        for (view in originalViews.drop(2)) {
            if (view === statusView) continue
            val heading = sectionHeading((view as? TextView)?.text)

            if (heading != null) {
                sectionNumber += 1
                val card = LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    background = roundedBackground(
                        activity,
                        surfaceBackground,
                        border,
                        6
                    )
                    setPadding(
                        dp(activity, 16),
                        dp(activity, 15),
                        dp(activity, 16),
                        dp(activity, 14)
                    )
                }

                val headingRow = LinearLayout(activity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                }
                val number = TextView(activity).apply {
                    text = formatBrailleNumber(sectionNumber.toString().padStart(2, '0'))
                    textSize = 11f
                    setTextColor(textMuted)
                    typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                }
                headingRow.addView(number, LinearLayout.LayoutParams(
                    dp(activity, 26),
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ))

                val headingView = view as TextView
                headingView.textSize = 11f
                headingView.setTextColor(textPrimary)
                headingView.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                headingView.letterSpacing = 0.055f
                headingView.setPadding(0, 0, 0, 0)
                headingRow.addView(headingView, LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f
                ))
                card.addView(headingRow, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(activity, 11) })

                currentCard = card
                sections += SectionCard(heading.orEmpty(), card)
            } else {
                val destination = currentCard
                if (destination != null) {
                    styleControl(activity, view)
                    val params = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    )
                    params.topMargin = dp(activity, 4)
                    params.bottomMargin = dp(activity, 4)
                    destination.addView(view, params)
                } else {
                    // Keep any unexpected leading view visible instead of dropping it.
                    styleControl(activity, view)
                    root.addView(view, matchWidth())
                }
            }
        }

        root.addView(createNavigation(activity, sections, scrollView), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = dp(activity, 2)
            bottomMargin = dp(activity, 8)
        })

        sections.forEachIndexed { index, section ->
            root.addView(section.view, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(activity, 13) })

            if (ValueAnimator.areAnimatorsEnabled()) {
                section.view.alpha = 0f
                section.view.translationY = dp(activity, 5).toFloat()
                section.view.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setStartDelay((index * 18L).coerceAtMost(90L))
                    .setDuration(180L)
                    .start()
            }
        }

        val statusCard = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBackground(activity, surfaceBackground, border, 6)
            setPadding(dp(activity, 15), dp(activity, 13), dp(activity, 15), dp(activity, 13))
        }
        val statusHeading = TextView(activity).apply {
            text = "ACTION STATUS"
            textSize = 10f
            letterSpacing = 0.08f
            setTextColor(textMuted)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        }
        statusCard.addView(statusHeading, wrapContent())
        statusView.setTextColor(textSecondary)
        statusView.textSize = 13f
        statusView.setLineSpacing(dp(activity, 2).toFloat(), 1f)
        statusCard.addView(statusView, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(activity, 6) })
        root.addView(statusCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = dp(activity, 12) })
    }

    private fun createNavigation(
        context: Context,
        sections: List<SectionCard>,
        scrollView: ScrollView
    ): HorizontalScrollView {
        val scroller = HorizontalScrollView(context).apply {
            isHorizontalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            clipToPadding = false
        }
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        sections.forEachIndexed { index, section ->
            val label = navigationLabel(section.heading)
            val chip = TextView(context).apply {
                text = label
                textSize = 11f
                letterSpacing = 0.04f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(textSecondary)
                gravity = Gravity.CENTER
                setPadding(dp(context, 12), dp(context, 10), dp(context, 12), dp(context, 10))
                isFocusable = true
                minimumHeight = dp(context, 48)
                contentDescription = "Jump to $label section"
                background = rippleBackground(
                    roundedBackground(context, Color.BLACK, border, 6),
                    Color.WHITE
                )
                setOnClickListener {
                    scrollView.post {
                        val targetY = (section.view.top - dp(context, 8)).coerceAtLeast(0)
                        scrollView.smoothScrollTo(0, targetY)
                    }
                }
            }
            row.addView(chip, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                if (index > 0) leftMargin = dp(context, 7)
            })
        }
        scroller.addView(row, ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ))
        return scroller
    }

    internal fun sectionHeading(text: CharSequence?): String? =
        text?.toString()?.trim()?.uppercase(Locale.ROOT)?.takeIf { it in sectionHeadings }

    internal fun navigationLabel(heading: String): String = when (heading) {
        "LEGAL & PRIVACY" -> "LEGAL"
        "ANDROID PRIVACY CONTROLS" -> "DEVICE"
        "DEVICE PRIVACY SNAPSHOT (LOCAL ONLY)" -> "SNAPSHOT"
        "PRIVACY HARDENING" -> "HARDENING"
        "DNS PRIVACY" -> "DNS"
        "DNS ROUTE DIAGNOSTICS" -> "ROUTE"
        "PRIVACY AUDIT EXPORT" -> "AUDIT"
        "ENCRYPTED DEVICE SYNC" -> "SYNC"
        "INSTALL QUEUE" -> "QUEUE"
        "APP POLICY REVIEW" -> "APP POLICIES"
        "APP POLICY REVIEW QUEUE" -> "APP POLICIES"
        "ALTERNATIVE CATALOG" -> "CATALOG"
        else -> heading
    }

    private fun styleControl(context: Context, view: View) {
        when (view) {
            is EditText -> {
                view.setTextColor(textPrimary)
                view.setHintTextColor(textMuted)
                view.textSize = 14f
                view.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
                view.setPadding(
                    dp(context, 13),
                    dp(context, 12),
                    dp(context, 13),
                    dp(context, 12)
                )
                view.background = inputBackground(context)
                view.minHeight = dp(context, 48)
            }
            is CheckBox -> {
                view.setTextColor(textSecondary)
                view.textSize = 13f
                view.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
                view.buttonTintList = ColorStateList(
                    arrayOf(
                        intArrayOf(android.R.attr.state_checked),
                        intArrayOf()
                    ),
                    intArrayOf(textPrimary, textMuted)
                )
                view.minimumHeight = dp(context, 48)
                view.setPadding(dp(context, 2), dp(context, 3), dp(context, 2), dp(context, 3))
            }
            is Button -> styleButton(context, view)
            is TextView -> styleLabel(context, view)
        }
    }

    private fun styleLabel(context: Context, view: TextView) {
        val content = view.text?.toString().orEmpty()
        if (content.isBlank()) return
        if (content.length > 72 || content.contains('\n')) {
            view.setTextColor(textSecondary)
            view.textSize = 13f
            view.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
            view.setLineSpacing(dp(context, 2).toFloat(), 1f)
        } else {
            view.setTextColor(textPrimary)
            view.textSize = 14f
            view.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        }
        view.setLinkTextColor(textPrimary)
    }

    internal fun isPrimaryAction(label: CharSequence?): Boolean =
        label?.toString()?.trim()?.lowercase(Locale.ROOT) in primaryActionLabels

    internal fun formatBrailleButtonLabel(label: CharSequence?): String {
        val readable = label?.toString().orEmpty()
        if (readable.isBlank() || readable.startsWith("⠿ ")) return readable
        return "⠿ $readable"
    }

    private fun styleButton(context: Context, view: Button) {
        val actionLabel = view.text?.toString().orEmpty()
        val primary = isPrimaryAction(actionLabel)
        if (view.contentDescription.isNullOrBlank()) {
            view.contentDescription = actionLabel
        }
        view.text = formatBrailleButtonLabel(actionLabel)
        view.isAllCaps = false
        view.textSize = 12f
        view.typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        view.setTextColor(if (primary) ink else textPrimary)
        view.gravity = Gravity.CENTER
        view.setPadding(dp(context, 14), dp(context, 11), dp(context, 14), dp(context, 11))
        view.minimumHeight = dp(context, 48)
        view.elevation = 0f
        val fill = if (primary) Color.WHITE else Color.BLACK
        view.background = rippleBackground(
            roundedBackground(context, fill, Color.WHITE, 6),
            Color.WHITE
        )
        applyPressMotion(view)
    }

    private fun applyPressMotion(view: View) {
        if (!ValueAnimator.areAnimatorsEnabled()) return
        view.setOnTouchListener { target, event ->
            val pressed = when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> true
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> false
                else -> return@setOnTouchListener false
            }
            val scale = if (pressed) 0.985f else 1f
            target.animate().cancel()
            target.animate()
                .scaleX(scale)
                .scaleY(scale)
                .setDuration(if (pressed) 70L else 110L)
                .start()
            false
        }
    }

    private fun inputBackground(context: Context): StateListDrawable {
        val focused = roundedBackground(context, Color.BLACK, Color.WHITE, 6)
        val normal = roundedBackground(context, inputSurfaceColor, border, 6)
        return StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_focused), focused)
            addState(intArrayOf(), normal)
        }
    }

    private fun roundedBackground(
        context: Context,
        fill: Int,
        stroke: Int,
        radiusDp: Int
    ): GradientDrawable = GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(context, radiusDp).toFloat()
        setStroke(dp(context, 1), stroke)
    }

    private fun rippleBackground(
        content: Drawable,
        rippleColor: Int
    ): RippleDrawable = RippleDrawable(ColorStateList.valueOf(rippleColor), content, null)

    private fun matchWidth(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    private fun wrapContent(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    private fun dp(context: Context, value: Int): Int =
        (value * context.resources.displayMetrics.density).toInt()
}

private val BRAILLE_DIGITS = listOf("⠚", "⠁", "⠃", "⠉", "⠙", "⠑", "⠋", "⠛", "⠓", "⠊")

internal fun formatBrailleNumber(value: String): String {
    require(value.isNotEmpty() && value.all { it.isDigit() }) {
        "Braille number formatting accepts decimal digits only."
    }
    return "⠼" + value.map { BRAILLE_DIGITS[it.digitToInt()] }.joinToString("")
}
