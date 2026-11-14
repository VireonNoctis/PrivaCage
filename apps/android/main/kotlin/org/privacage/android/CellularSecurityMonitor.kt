package org.privacage.android

import android.content.Context
import android.content.pm.PackageManager
import android.telephony.TelephonyCallback
import android.telephony.TelephonyDisplayInfo
import android.telephony.TelephonyManager

internal enum class CellularRadioRisk {
    GSM_2G,
    LEGACY_2G_CLASS,
    OTHER,
    UNKNOWN,
    UNAVAILABLE
}

internal data class CellularNetworkAssessment(
    val networkLabel: String,
    val risk: CellularRadioRisk,
    val explanation: String
) {
    fun render(): String {
        val heading = when (risk) {
            CellularRadioRisk.GSM_2G -> "⚠ WARNING — GSM 2G REPORTED"
            CellularRadioRisk.LEGACY_2G_CLASS -> "⚠ LEGACY 2G-CLASS TECHNOLOGY REPORTED"
            CellularRadioRisk.OTHER -> "NO GSM 2G INDICATION IN REPORTED DATA NETWORK"
            CellularRadioRisk.UNKNOWN -> "CELLULAR SECURITY STATUS UNVERIFIED"
            CellularRadioRisk.UNAVAILABLE -> "CELLULAR STATUS UNAVAILABLE"
        }
        return "$heading\nReported packet-data type: $networkLabel\n$explanation"
    }
}

internal object CellularNetworkClassifier {
    fun waiting(): CellularNetworkAssessment = CellularNetworkAssessment(
        networkLabel = "waiting for Android",
        risk = CellularRadioRisk.UNKNOWN,
        explanation = "The live callback has not supplied a network type yet. Unknown is not a clean/security result."
    )

    fun unsupported(reason: String): CellularNetworkAssessment = CellularNetworkAssessment(
        networkLabel = "unsupported",
        risk = CellularRadioRisk.UNAVAILABLE,
        explanation = reason
    )

    fun unavailable(reason: String): CellularNetworkAssessment = CellularNetworkAssessment(
        networkLabel = "unavailable",
        risk = CellularRadioRisk.UNAVAILABLE,
        explanation = reason
    )

    fun classify(networkType: Int): CellularNetworkAssessment {
        val label = when (networkType) {
            TelephonyManager.NETWORK_TYPE_GPRS -> "GPRS (GSM 2G)"
            TelephonyManager.NETWORK_TYPE_EDGE -> "EDGE (GSM 2G)"
            TelephonyManager.NETWORK_TYPE_GSM -> "GSM (2G)"
            TelephonyManager.NETWORK_TYPE_CDMA -> "CDMA (legacy 2G-class)"
            TelephonyManager.NETWORK_TYPE_1xRTT -> "1xRTT (legacy 2G-class)"
            TelephonyManager.NETWORK_TYPE_IDEN -> "iDEN (legacy 2G-class)"
            TelephonyManager.NETWORK_TYPE_UMTS -> "UMTS (3G)"
            TelephonyManager.NETWORK_TYPE_HSDPA -> "HSDPA (3G)"
            TelephonyManager.NETWORK_TYPE_HSUPA -> "HSUPA (3G)"
            TelephonyManager.NETWORK_TYPE_HSPA -> "HSPA (3G)"
            TelephonyManager.NETWORK_TYPE_HSPAP -> "HSPA+ (3G)"
            TelephonyManager.NETWORK_TYPE_EVDO_0 -> "EVDO 0 (3G)"
            TelephonyManager.NETWORK_TYPE_EVDO_A -> "EVDO A (3G)"
            TelephonyManager.NETWORK_TYPE_EVDO_B -> "EVDO B (3G)"
            TelephonyManager.NETWORK_TYPE_EHRPD -> "eHRPD (3G)"
            TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "TD-SCDMA (3G)"
            TelephonyManager.NETWORK_TYPE_LTE -> "LTE (4G)"
            TelephonyManager.NETWORK_TYPE_IWLAN -> "IWLAN (Wi-Fi calling)"
            TelephonyManager.NETWORK_TYPE_NR -> "NR (5G)"
            TelephonyManager.NETWORK_TYPE_UNKNOWN -> "unknown"
            else -> "unrecognized network type ($networkType)"
        }

        return when (networkType) {
            TelephonyManager.NETWORK_TYPE_GPRS,
            TelephonyManager.NETWORK_TYPE_EDGE,
            TelephonyManager.NETWORK_TYPE_GSM -> CellularNetworkAssessment(
                networkLabel = label,
                risk = CellularRadioRisk.GSM_2G,
                explanation = "Android reports a GSM 2G packet-data network. This does not prove a false base station or reveal whether the radio link is ciphered. Disable 2G for this SIM in Android Settings if the device supports it."
            )
            TelephonyManager.NETWORK_TYPE_CDMA,
            TelephonyManager.NETWORK_TYPE_1xRTT,
            TelephonyManager.NETWORK_TYPE_IDEN -> CellularNetworkAssessment(
                networkLabel = label,
                risk = CellularRadioRisk.LEGACY_2G_CLASS,
                explanation = "This is a legacy 2G-class technology, not a direct detection of a GSM 2G downgrade. Android does not expose the link cipher state through this reading."
            )
            TelephonyManager.NETWORK_TYPE_UNKNOWN -> CellularNetworkAssessment(
                networkLabel = label,
                risk = CellularRadioRisk.UNKNOWN,
                explanation = "Android did not provide a known packet-data type. The app cannot determine the radio generation or encryption state."
            )
            else -> CellularNetworkAssessment(
                networkLabel = label,
                risk = CellularRadioRisk.OTHER,
                explanation = "The reported packet-data type is not GSM 2G. This does not prove the connection is encrypted, does not inspect voice-only service, and does not rule out a false base station."
            )
        }
    }
}

@Suppress("NewApi")
internal class CellularSecurityMonitor(
    context: Context,
    private val onAssessment: (CellularNetworkAssessment) -> Unit
) {
    private val appContext = context.applicationContext
    private var registeredManager: TelephonyManager? = null
    private var registeredCallback: TelephonyCallback? = null

    fun start(): CellularNetworkAssessment {
        if (registeredCallback != null) return CellularNetworkClassifier.waiting()

        if (!appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
            return CellularNetworkClassifier.unsupported(
                "This device does not expose a telephony radio to ordinary apps. Use the SIM settings handoff if this device has cellular service."
            )
        }

        val manager = appContext.getSystemService(TelephonyManager::class.java)
            ?: return CellularNetworkClassifier.unavailable("Android did not provide a TelephonyManager.")

        val callback = object : TelephonyCallback(), TelephonyCallback.DisplayInfoListener {
            override fun onDisplayInfoChanged(telephonyDisplayInfo: TelephonyDisplayInfo) {
                onAssessment(CellularNetworkClassifier.classify(telephonyDisplayInfo.networkType))
            }
        }

        return try {
            manager.registerTelephonyCallback(appContext.mainExecutor, callback)
            registeredManager = manager
            registeredCallback = callback
            CellularNetworkClassifier.waiting()
        } catch (exception: SecurityException) {
            CellularNetworkClassifier.unavailable(
                "Android restricted access to the reported network type (" + exception.javaClass.simpleName + "). No phone-state permission was requested."
            )
        } catch (exception: UnsupportedOperationException) {
            CellularNetworkClassifier.unsupported(
                "This Android build or modem does not support the display-information callback (" + exception.javaClass.simpleName + ")."
            )
        } catch (exception: IllegalStateException) {
            CellularNetworkClassifier.unavailable(
                "Android could not register the cellular status callback (" + exception.javaClass.simpleName + ")."
            )
        }
    }

    fun stop() {
        val manager = registeredManager
        val callback = registeredCallback
        registeredManager = null
        registeredCallback = null
        if (manager != null && callback != null) {
            manager.unregisterTelephonyCallback(callback)
        }
    }
}
