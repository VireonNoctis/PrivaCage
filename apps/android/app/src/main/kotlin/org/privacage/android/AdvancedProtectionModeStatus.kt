package org.privacage.android

internal object AdvancedProtectionModeStatus {
    fun describe(apiLevel: Int, isEnabled: Boolean?): String {
        if (apiLevel < 36) {
            return "UNAVAILABLE · Android Advanced Protection status API requires Android 16 (API 36) or newer."
        }
        return when (isEnabled) {
            true -> "ENABLED · Android reports Advanced Protection Mode active."
            false -> "DISABLED · Android reports Advanced Protection Mode off."
            null -> "UNAVAILABLE · Android did not expose Advanced Protection Mode status."
        }
    }
}
