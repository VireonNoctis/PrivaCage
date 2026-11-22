package org.privacage.security

/** Copies a password editor's characters without creating an immutable String, then clears the editor. */
internal object PwnedPasswordInput {
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
