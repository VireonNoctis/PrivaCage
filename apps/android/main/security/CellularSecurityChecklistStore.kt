package org.privacage.android

import android.content.Context
import org.json.JSONObject
import java.io.IOException
import java.nio.charset.StandardCharsets

internal enum class CellularReviewStatus {
    NOT_REVIEWED,
    USER_CONFIRMED,
    NOT_AVAILABLE
}

internal data class CellularSecurityChecklist(
    val everySim2gProtection: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED,
    val unencryptedNetworkAlerts: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED,
    val securityUpdates: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED,
    val usbDebugging: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED,
    val playProtect: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED,
    val theftProtection: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED,
    val advancedProtectionUsb: CellularReviewStatus = CellularReviewStatus.NOT_REVIEWED
)

internal object CellularSecurityChecklistStore {
    private const val PREFERENCES = "org.privacage.android.cellular-security-checklist"
    private const val ENCRYPTED_KEY = "checklist_encrypted_v1"
    private const val KEY_ALIAS = "org.privacage.android.cellular-checklist.aes-gcm.v1"
    private const val AAD_LABEL = "cellular-checklist"
    private const val MAX_BYTES = 4096
    private const val LEGACY_SCHEMA_VERSION = 1
    private const val SCHEMA_VERSION = 2

    fun read(context: Context): CellularSecurityChecklist {
        val serialized = AndroidSensitivePreferenceVault.read(
            context = context,
            preferencesName = PREFERENCES,
            encryptedKey = ENCRYPTED_KEY,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            defaultValue = encode(CellularSecurityChecklist()),
            maximumPlaintextBytes = MAX_BYTES,
            validateValue = { decode(it) }
        ) ?: encode(CellularSecurityChecklist())
        val decoded = decode(serialized)
        if (readSchemaVersion(serialized) == LEGACY_SCHEMA_VERSION) {
            // Preserve the old five user choices; only the new items start as not reviewed.
            save(context, decoded)
        }
        return decoded
    }

    fun save(context: Context, checklist: CellularSecurityChecklist) {
        val serialized = encode(checklist)
        AndroidSensitivePreferenceVault.write(
            context = context,
            preferencesName = PREFERENCES,
            encryptedKey = ENCRYPTED_KEY,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            plaintext = serialized,
            maximumPlaintextBytes = MAX_BYTES,
            validateValue = { decode(it) }
        )
    }

    internal fun encode(checklist: CellularSecurityChecklist): String =
        JSONObject()
            .put("schema_version", SCHEMA_VERSION)
            .put("every_sim_2g_protection", checklist.everySim2gProtection.name)
            .put("unencrypted_network_alerts", checklist.unencryptedNetworkAlerts.name)
            .put("security_updates", checklist.securityUpdates.name)
            .put("usb_debugging", checklist.usbDebugging.name)
            .put("play_protect", checklist.playProtect.name)
            .put("theft_protection", checklist.theftProtection.name)
            .put("advanced_protection_usb", checklist.advancedProtectionUsb.name)
            .toString()
            .also { serialized ->
                require(serialized.toByteArray(StandardCharsets.UTF_8).size <= MAX_BYTES) {
                    "Cellular security checklist exceeds its storage limit."
                }
            }

    internal fun decode(serialized: String): CellularSecurityChecklist {
        if (serialized.toByteArray(StandardCharsets.UTF_8).size > MAX_BYTES) {
            throw IOException("Cellular security checklist exceeds its storage limit; stored data was preserved.")
        }
        try {
            StrictJsonKeyScanner.validate(serialized, "Cellular security checklist")
            val root = JSONObject(serialized)
            val legacyKeys = setOf(
                "schema_version",
                "every_sim_2g_protection",
                "unencrypted_network_alerts",
                "security_updates",
                "usb_debugging",
                "play_protect"
            )
            val currentKeys = legacyKeys + setOf("theft_protection", "advanced_protection_usb")
            val version = root.opt("schema_version") as? Int
                ?: throw IOException("Cellular security checklist schema version must be an integer.")

            when (version) {
                LEGACY_SCHEMA_VERSION -> if (root.keys().asSequence().toSet() != legacyKeys) {
                    throw IOException("Legacy cellular checklist fields are malformed; stored data was preserved.")
                }
                SCHEMA_VERSION -> if (root.keys().asSequence().toSet() != currentKeys) {
                    throw IOException("Cellular security checklist has unsupported fields; stored data was preserved.")
                }
                else -> throw IOException("Cellular security checklist has an unsupported schema version; stored data was preserved.")
            }

            fun status(key: String): CellularReviewStatus {
                val value = root.opt(key) as? String
                    ?: throw IOException("Cellular security checklist field " + key + " must be a string.")
                return try {
                    CellularReviewStatus.valueOf(value)
                } catch (exception: IllegalArgumentException) {
                    throw IOException("Cellular security checklist field " + key + " has an unsupported status.", exception)
                }
            }

            return CellularSecurityChecklist(
                everySim2gProtection = status("every_sim_2g_protection"),
                unencryptedNetworkAlerts = status("unencrypted_network_alerts"),
                securityUpdates = status("security_updates"),
                usbDebugging = status("usb_debugging"),
                playProtect = status("play_protect"),
                theftProtection = if (version == LEGACY_SCHEMA_VERSION) CellularReviewStatus.NOT_REVIEWED else status("theft_protection"),
                advancedProtectionUsb = if (version == LEGACY_SCHEMA_VERSION) CellularReviewStatus.NOT_REVIEWED else status("advanced_protection_usb")
            )
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("Cellular security checklist is malformed; stored data was preserved.", exception)
        }
    }

    private fun readSchemaVersion(serialized: String): Int = try {
        JSONObject(serialized).optInt("schema_version", -1)
    } catch (exception: Exception) {
        throw IOException("Cellular security checklist version could not be read; stored data was preserved.", exception)
    }
}
