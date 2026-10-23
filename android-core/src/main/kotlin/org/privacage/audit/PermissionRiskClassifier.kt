package org.privacage.audit

/** Review labels describe declared capabilities, not a malware verdict or runtime observation. */
enum class PermissionReviewCategory(val displayName: String) {
    PERSONAL_DATA("Sensitive personal-data capability"),
    SPECIAL_ACCESS("Special access or system control"),
    NETWORK_CAPABILITY("Network capability"),
    OTHER("Other declared capability")
}

data class PermissionReview(
    val category: PermissionReviewCategory,
    val explanation: String
)

/**
 * Provides conservative explanations for common Android permission declarations.
 * Unknown and custom permissions remain unclassified instead of being labelled suspicious.
 */
object PermissionRiskClassifier {
    private val knownPermissions: Map<String, PermissionReview> = buildMap {
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request approximate location when permitted; this declaration alone does not show use.",
            "ACCESS_COARSE_LOCATION"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request precise location when permitted; this declaration alone does not show use.",
            "ACCESS_FINE_LOCATION"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request background location subject to Android version and access-grant rules.",
            "ACCESS_BACKGROUND_LOCATION"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request contacts access when the relevant permission is granted.",
            "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request calendar read or write access when the relevant permission is granted.",
            "READ_CALENDAR", "WRITE_CALENDAR"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request access to call history or outgoing-call information, depending on the permission.",
            "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request phone-state, phone-number, or call capabilities; actual access varies by permission and OS policy.",
            "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS",
            "READ_BASIC_PHONE_STATE"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request SMS/MMS or WAP-push capabilities; permission grants and platform restrictions still apply.",
            "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request camera access when authorized; this does not prove that camera data is captured.",
            "CAMERA"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request microphone access when authorized; this does not prove that audio is recorded.",
            "RECORD_AUDIO"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request body-sensor or activity-recognition data; device, permission, and OS restrictions apply.",
            "BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request access to media or external-storage content; the actual scope varies by Android version.",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
            "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED",
            "ACCESS_MEDIA_LOCATION", "MANAGE_EXTERNAL_STORAGE"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request nearby-device discovery or interaction; behavior and grant requirements vary by OS version.",
            "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE",
            "NEARBY_WIFI_DEVICES", "UWB_RANGING"))
        putAll(entries(PermissionReviewCategory.PERSONAL_DATA,
            "Can request biometric-authentication APIs; this does not grant access to raw biometric templates.",
            "USE_BIOMETRIC", "USE_FINGERPRINT"))
        putAll(entries(PermissionReviewCategory.SPECIAL_ACCESS,
            "Can request drawing windows over other apps, subject to separate user-controlled special access.",
            "SYSTEM_ALERT_WINDOW"))
        putAll(entries(PermissionReviewCategory.SPECIAL_ACCESS,
            "Can request package-installation capability; the Android installer and security policy still govern installation.",
            "REQUEST_INSTALL_PACKAGES"))
        putAll(entries(PermissionReviewCategory.SPECIAL_ACCESS,
            "Can request broad installed-package visibility, subject to Android package-visibility rules and policy.",
            "QUERY_ALL_PACKAGES"))
        putAll(entries(PermissionReviewCategory.SPECIAL_ACCESS,
            "Can request app-usage statistics; this normally requires user-granted special access.",
            "PACKAGE_USAGE_STATS"))
        putAll(entries(PermissionReviewCategory.SPECIAL_ACCESS,
            "Can request exemption from battery optimization; this is not proof of covert persistence.",
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
        putAll(entries(PermissionReviewCategory.SPECIAL_ACCESS,
            "Can receive the system boot broadcast; this alone does not prove that background work occurs.",
            "RECEIVE_BOOT_COMPLETED"))
        putAll(entries(PermissionReviewCategory.NETWORK_CAPABILITY,
            "Allows network sockets to be opened; it does not prove that information is transmitted or identify destinations.",
            "INTERNET"))
        putAll(entries(PermissionReviewCategory.NETWORK_CAPABILITY,
            "Allows checking network connectivity state; it does not by itself grant packet inspection.",
            "ACCESS_NETWORK_STATE"))
        putAll(entries(PermissionReviewCategory.NETWORK_CAPABILITY,
            "Allows reading Wi-Fi connection information available to the app; access and redaction vary by OS version.",
            "ACCESS_WIFI_STATE"))
    }

    fun classify(permissionName: String): PermissionReview =
        knownPermissions[permissionName] ?: PermissionReview(
            PermissionReviewCategory.OTHER,
            "Declared permission; inspect its owner, protection level, and platform documentation before drawing conclusions."
        )

    private fun entries(
        category: PermissionReviewCategory,
        explanation: String,
        vararg permissionNames: String
    ): Map<String, PermissionReview> = permissionNames.associate { permissionName ->
        "android.permission.$permissionName" to PermissionReview(category, explanation)
    }
}
