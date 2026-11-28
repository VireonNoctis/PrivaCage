package org.privacage.security

import android.view.inputmethod.EditorInfo

/** Copies a password editor's characters without creating an immutable String, then clears the editor. */
internal object PwnedPasswordInput {
    /**
     * Requests that the active IME not add this field's input to personalized learning data.
     * Android documents this as advisory; an IME may ignore the flag.
     */
    fun requestNoPersonalizedLearning(currentImeOptions: Int): Int =
        currentImeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING

    fun takeAndClear(source: CharSequence, clearSource: () -> Unit): CharArray {
        var copy = CharArray(0)
        try {
            copy = CharArray(source.length)
            for (index in copy.indices) copy[index] = source[index]
            return copy
        } catch (failure: Throwable) {
            copy.fill('\u0000')
            throw failure
        } finally {
            clearSource()
        }
    }
}
