package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException

class CellularSecurityChecklistStoreTest {
    @Test
    fun roundTripsEveryUserReviewState() {
        val expected = CellularSecurityChecklist(
            everySim2gProtection = CellularReviewStatus.USER_CONFIRMED,
            unencryptedNetworkAlerts = CellularReviewStatus.NOT_AVAILABLE,
            securityUpdates = CellularReviewStatus.USER_CONFIRMED,
            usbDebugging = CellularReviewStatus.NOT_REVIEWED,
            playProtect = CellularReviewStatus.USER_CONFIRMED
        )

        assertEquals(expected, CellularSecurityChecklistStore.decode(
            CellularSecurityChecklistStore.encode(expected)
        ))
    }

    @Test
    fun defaultChecklistStartsAsNotReviewed() {
        val decoded = CellularSecurityChecklistStore.decode(
            CellularSecurityChecklistStore.encode(CellularSecurityChecklist())
        )

        assertEquals(CellularReviewStatus.NOT_REVIEWED, decoded.everySim2gProtection)
        assertEquals(CellularReviewStatus.NOT_REVIEWED, decoded.unencryptedNetworkAlerts)
        assertEquals(CellularReviewStatus.NOT_REVIEWED, decoded.securityUpdates)
        assertEquals(CellularReviewStatus.NOT_REVIEWED, decoded.usbDebugging)
        assertEquals(CellularReviewStatus.NOT_REVIEWED, decoded.playProtect)
    }

    @Test
    fun rejectsUnknownFields() {
        val encoded = CellularSecurityChecklistStore.encode(CellularSecurityChecklist())
        val invalid = encoded.dropLast(1) + ",\"unexpected\":true}"

        assertThrows(IOException::class.java) {
            CellularSecurityChecklistStore.decode(invalid)
        }
    }

    @Test
    fun rejectsUnsupportedSchemaVersion() {
        val invalid = CellularSecurityChecklistStore.encode(CellularSecurityChecklist())
            .replace("\"schema_version\":1", "\"schema_version\":2")

        assertThrows(IOException::class.java) {
            CellularSecurityChecklistStore.decode(invalid)
        }
    }

    @Test
    fun rejectsUnknownReviewState() {
        val invalid = CellularSecurityChecklistStore.encode(CellularSecurityChecklist())
            .replace("NOT_REVIEWED", "UNKNOWN")

        assertThrows(IOException::class.java) {
            CellularSecurityChecklistStore.decode(invalid)
        }
    }

    @Test
    fun rejectsOversizedInput() {
        assertThrows(IOException::class.java) {
            CellularSecurityChecklistStore.decode("x".repeat(4097))
        }
    }
}
