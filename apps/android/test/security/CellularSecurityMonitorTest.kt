package org.privacage.android

import android.telephony.TelephonyManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CellularSecurityMonitorTest {
    @Test
    fun gprsEdgeAndGsmAreProminentGsmTwoGWarnings() {
        listOf(
            TelephonyManager.NETWORK_TYPE_GPRS,
            TelephonyManager.NETWORK_TYPE_EDGE,
            TelephonyManager.NETWORK_TYPE_GSM
        ).forEach { networkType ->
            val assessment = CellularNetworkClassifier.classify(networkType)
            assertEquals(CellularRadioRisk.GSM_2G, assessment.risk)
            assertTrue(assessment.render().contains("WARNING — GSM 2G REPORTED"))
            assertTrue(assessment.render().contains("does not prove a false base station"))
        }
    }

    @Test
    fun cdmaOneRttAndIdenRemainSeparateLegacyWarnings() {
        listOf(
            TelephonyManager.NETWORK_TYPE_CDMA,
            TelephonyManager.NETWORK_TYPE_1xRTT,
            TelephonyManager.NETWORK_TYPE_IDEN
        ).forEach { networkType ->
            val assessment = CellularNetworkClassifier.classify(networkType)
            assertEquals(CellularRadioRisk.LEGACY_2G_CLASS, assessment.risk)
            assertTrue(assessment.render().contains("not a direct detection of a GSM 2G downgrade"))
        }
    }

    @Test
    fun newerNetworkTypesDoNotClaimEncryptionOrSafety() {
        listOf(
            TelephonyManager.NETWORK_TYPE_UMTS,
            TelephonyManager.NETWORK_TYPE_LTE,
            TelephonyManager.NETWORK_TYPE_NR,
            TelephonyManager.NETWORK_TYPE_IWLAN
        ).forEach { networkType ->
            val assessment = CellularNetworkClassifier.classify(networkType)
            assertEquals(CellularRadioRisk.OTHER, assessment.risk)
            assertTrue(assessment.render().contains("does not prove the connection is encrypted"))
        }
    }

    @Test
    fun unknownAndUnsupportedStatesNeverRenderAsClean() {
        val unknown = CellularNetworkClassifier.classify(TelephonyManager.NETWORK_TYPE_UNKNOWN)
        val waiting = CellularNetworkClassifier.waiting()
        val unavailable = CellularNetworkClassifier.unsupported("Not supported")

        assertEquals(CellularRadioRisk.UNKNOWN, unknown.risk)
        assertEquals(CellularRadioRisk.UNKNOWN, waiting.risk)
        assertEquals(CellularRadioRisk.UNAVAILABLE, unavailable.risk)
        assertTrue(unknown.render().contains("UNVERIFIED"))
        assertTrue(waiting.render().contains("UNVERIFIED"))
        assertTrue(unavailable.render().contains("UNAVAILABLE"))
    }
}
