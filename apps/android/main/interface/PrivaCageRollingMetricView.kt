package org.privacage.android

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.AlphaAnimation
import android.view.animation.Animation
import android.view.animation.AnimationSet
import android.view.animation.DecelerateInterpolator
import android.view.animation.TranslateAnimation
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.TextSwitcher
import android.widget.TextView
import java.text.NumberFormat
import java.util.Locale

/**
 * A local-only metric card with restrained, per-digit transitions.
 *
 * Values come from the existing DNS counter store. Digits move only when their
 * stored value changes; disabled system animations switch immediately.
 */
internal class PrivaCageRollingMetricView(
    context: Context,
    private val label: String
) : LinearLayout(context) {
    private data class DigitSlot(val switcher: TextSwitcher?)

    private val digitRow = LinearLayout(context).apply {
        orientation = HORIZONTAL
        gravity = Gravity.START or Gravity.CENTER_VERTICAL
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }
    private val digitScroller = HorizontalScrollView(context).apply {
        isHorizontalScrollBarEnabled = false
        overScrollMode = View.OVER_SCROLL_NEVER
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }
    private val slots = mutableListOf<DigitSlot>()
    private var currentText: String? = null
    private var currentValue: Long? = null

    init {
        orientation = VERTICAL
        minimumHeight = dp(84)
        setPadding(dp(13), dp(11), dp(13), dp(10))
        background = GradientDrawable().apply {
            setColor(Color.BLACK)
            cornerRadius = dp(6).toFloat()
            setStroke(dp(1), Color.WHITE)
        }

        addView(TextView(context).apply {
            text = label
            textSize = 9f
            letterSpacing = 0.075f
            setTextColor(Color.WHITE)
            typeface = Typeface.create("monospace", Typeface.BOLD)
            includeFontPadding = false
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ))

        digitScroller.addView(digitRow, ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.MATCH_PARENT
        ))
        addView(digitScroller, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(42)
        ).apply {
            topMargin = dp(5)
        })

        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
        setValue(0L)
    }

    fun setValue(value: Long) {
        val formatted = formatCounterValue(value)
        val previous = currentText

        if (previous == null || previous.length != formatted.length) {
            rebuildDigits(formatted)
            digitScroller.post { digitScroller.fullScroll(View.FOCUS_RIGHT) }
        } else if (previous != formatted) {
            val positionsMatch = previous.indices.all { index ->
                previous[index].isDigit() == formatted[index].isDigit()
            }
            if (!positionsMatch || !ValueAnimator.areAnimatorsEnabled()) {
                rebuildDigits(formatted)
            } else {
                val increasing = value >= (currentValue ?: value)
                formatted.forEachIndexed { index, nextCharacter ->
                    if (previous[index] == nextCharacter) return@forEachIndexed
                    val switcher = slots[index].switcher
                    if (switcher == null) {
                        rebuildDigits(formatted)
                        return@forEachIndexed
                    }
                    switcher.inAnimation = digitAnimation(entering = true, increasing = increasing)
                    switcher.outAnimation = digitAnimation(entering = false, increasing = increasing)
                    switcher.setText(brailleDigit(nextCharacter))
                }
            }
        }

        currentText = formatted
        currentValue = value
        contentDescription = "$label: $formatted"
    }

    private fun rebuildDigits(formatted: String) {
        digitRow.removeAllViews()
        slots.clear()
        digitRow.addView(TextView(context).apply {
            text = "⠼"
            textSize = 25f
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            includeFontPadding = false
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LayoutParams(dp(22), dp(42)))

        formatted.forEach { character ->
            if (character.isDigit()) {
                val switcher = TextSwitcher(context).apply {
                    setFactory {
                        TextView(context).apply {
                            textSize = 28f
                            gravity = Gravity.CENTER
                            setTextColor(Color.WHITE)
                            typeface = Typeface.create("monospace", Typeface.BOLD)
                            includeFontPadding = false
                            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                        }
                    }
                    inAnimation = digitAnimation(entering = true, increasing = true)
                    outAnimation = digitAnimation(entering = false, increasing = true)
                    setCurrentText(brailleDigit(character))
                }
                digitRow.addView(switcher, LayoutParams(dp(26), dp(42)))
                slots += DigitSlot(switcher)
            } else {
                digitRow.addView(TextView(context).apply {
                    text = if (character == ',') "⠂" else character.toString()
                    textSize = 21f
                    gravity = Gravity.CENTER
                    setTextColor(Color.WHITE)
                    typeface = Typeface.create("monospace", Typeface.NORMAL)
                    includeFontPadding = false
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                }, LayoutParams(dp(20), dp(42)))
                slots += DigitSlot(null)
            }
        }
    }

    private fun digitAnimation(entering: Boolean, increasing: Boolean): Animation =
        AnimationSet(true).apply {
            val startY = if (increasing) 1f else -1f
            val endY = if (entering) 0f else if (increasing) -1f else 1f
            addAnimation(
                TranslateAnimation(
                    Animation.RELATIVE_TO_SELF, 0f,
                    Animation.RELATIVE_TO_SELF, 0f,
                    Animation.RELATIVE_TO_SELF, if (entering) startY else 0f,
                    Animation.RELATIVE_TO_SELF, endY
                )
            )
            addAnimation(
                AlphaAnimation(
                    if (entering) 0f else 1f,
                    if (entering) 1f else 0f
                )
            )
            duration = 190L
            interpolator = DecelerateInterpolator()
        }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()
}

internal fun brailleDigit(character: Char): String {
    require(character in '0'..'9') { "Braille digit formatting accepts decimal digits only." }
    return listOf("⠚", "⠁", "⠃", "⠉", "⠙", "⠑", "⠋", "⠛", "⠓", "⠊")[character.digitToInt()]
}

internal fun formatBrailleCounterValue(value: Long): String {
    val formatted = formatCounterValue(value)
    return "⠼" + formatted.map { character ->
        when {
            character in '0'..'9' -> brailleDigit(character)
            character == ',' -> "⠂"
            else -> character.toString()
        }
    }.joinToString("")
}

internal fun formatCounterValue(value: Long): String {
    require(value >= 0L) { "Counter values cannot be negative." }
    return NumberFormat.getIntegerInstance(Locale.US).format(value)
}
