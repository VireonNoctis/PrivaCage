package org.privacage.audit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PermissionRiskClassifierTest {

    @Test
    fun classifiesPreciseLocationAsSensitiveCapabilityWithoutImplyingUse() {
        val review = PermissionRiskClassifier.classify("android.permission.ACCESS_FINE_LOCATION")

        assertEquals(PermissionReviewCategory.PERSONAL_DATA, review.category)
        assertTrue(review.explanation.contains("does not show use"))
    }

    @Test
    fun distinguishesNetworkConnectivityFromPersonalDataPermissions() {
        val review = PermissionRiskClassifier.classify("android.permission.INTERNET")

        assertEquals(PermissionReviewCategory.NETWORK_CAPABILITY, review.category)
        assertTrue(review.explanation.contains("does not prove"))
    }

    @Test
    fun labelsSpecialAccessSeparately() {
        assertEquals(
            PermissionReviewCategory.SPECIAL_ACCESS,
            PermissionRiskClassifier.classify("android.permission.SYSTEM_ALERT_WINDOW").category
        )
    }

    @Test
    fun leavesUnknownAndCustomPermissionsUnclassified() {
        val review = PermissionRiskClassifier.classify("com.vendor.custom.PERMISSION")

        assertEquals(PermissionReviewCategory.OTHER, review.category)
        assertTrue(review.explanation.contains("protection level"))
    }
}
