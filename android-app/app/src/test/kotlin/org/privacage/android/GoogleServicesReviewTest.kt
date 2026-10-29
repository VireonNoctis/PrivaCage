package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GoogleServicesReviewTest {
    @Test
    fun targetListIsNarrowAndStable() {
        assertEquals(
            listOf(
                "com.google.android.gms",
                "com.google.android.gsf",
                "com.android.vending"
            ),
            GoogleServicesReview.targets.map { it.packageName }
        )
        assertEquals(
            GoogleServicesReview.targets.size,
            GoogleServicesReview.targets.map { it.packageName }.toSet().size
        )
    }

    @Test
    fun reportShowsObservedStatesAndUncertaintyWithoutClaimingRuntimeCoverage() {
        val targets = GoogleServicesReview.targets
        val report = GoogleServicesReview.render(
            listOf(
                GoogleServiceObservation(
                    target = targets[0],
                    status = GoogleServiceStatus.ENABLED,
                    versionName = "test-version",
                    systemPackage = true
                ),
                GoogleServiceObservation(
                    target = targets[1],
                    status = GoogleServiceStatus.NOT_INSTALLED_OR_NOT_VISIBLE,
                    diagnostic = "Android did not expose this package."
                ),
                GoogleServiceObservation(
                    target = targets[2],
                    status = GoogleServiceStatus.INSPECTION_UNAVAILABLE,
                    diagnostic = "Package inspection failed (SecurityException)."
                )
            )
        )

        assertTrue(report.contains("Google Play services (com.google.android.gms)"))
        assertTrue(report.contains("Installed and enabled"))
        assertTrue(report.contains("Version: test-version"))
        assertTrue(report.contains("System package: yes"))
        assertTrue(report.contains("Not installed or not visible"))
        assertTrue(report.contains("Inspection unavailable"))
        assertTrue(report.contains("does not inspect network connections"))
        assertTrue(report.contains("PrivaCage does not disable these packages"))
    }

    @Test
    fun disabledServiceStateIsNotDescribedAsMissing() {
        val target = GoogleServicesReview.targets.first()
        val report = GoogleServicesReview.render(
            listOf(
                GoogleServiceObservation(
                    target = target,
                    status = GoogleServiceStatus.DISABLED,
                    systemPackage = true
                )
            )
        )

        assertTrue(report.contains("Installed but disabled"))
        assertTrue(report.contains("System package: yes"))
        assertTrue(report.contains("PrivaCage does not disable these packages"))
    }

    @Test
    fun emptyReportIsExplicit() {
        val report = GoogleServicesReview.render(emptyList())
        assertTrue(report.contains("No package results were returned."))
        assertTrue(report.contains("Read-only"))
    }
}
