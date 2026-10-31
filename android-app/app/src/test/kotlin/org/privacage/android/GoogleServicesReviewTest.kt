package org.privacage.android

import org.junit.Assert.assertEquals
import android.content.pm.PackageManager
import org.junit.Assert.assertTrue
import org.junit.Test

class GoogleServicesReviewTest {
    @Test
    fun dnsPreflightDisclosureMatchesImplementedRoutingScope() {
        val disclosure = DnsVpnDisclosure.COVERAGE
        assertTrue(disclosure.contains("IPv4 UDP DNS"))
        assertTrue(disclosure.contains("constrained IPv6 UDP-DNS"))
        assertTrue(disclosure.contains("not a full-device VPN"))
        assertTrue(disclosure.contains("Client-initiated DNS-over-TCP"))
        assertTrue(disclosure.contains("DNS-over-HTTPS"))
        assertTrue(disclosure.contains("DNS-over-QUIC"))
        assertTrue(disclosure.contains("arbitrary DNS-over-TLS endpoints"))
        assertTrue(disclosure.contains("direct-IP connections"))
        assertTrue(disclosure.contains("general IPv6 traffic"))
        assertTrue(disclosure.contains("IPv6 extension headers, fragments, and jumbograms are rejected"))
        val compactScope = DnsVpnDisclosure.COMPACT_SCOPE
        assertTrue(compactScope.contains("virtual IPv4/IPv6 endpoints"))
        assertTrue(compactScope.contains("client-initiated DNS-over-TCP"))
        assertTrue(compactScope.contains("app-owned DoH/DoQ"))
        assertTrue(compactScope.contains("arbitrary DoT endpoints"))
        assertTrue(compactScope.contains("direct-IP connections"))
        assertTrue(compactScope.contains("general IPv6 traffic"))
        assertTrue(!compactScope.contains("IPv6 DNS remains outside"))
    }

    @Test
    fun explicitEnabledSettingOverridesManifestDefault() {
        assertEquals(
            GoogleServiceStatus.ENABLED,
            GoogleServicesReview.resolveStatus(
                applicationEnabled = false,
                enabledSetting = PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            )
        )
        assertEquals(
            GoogleServiceStatus.DISABLED,
            GoogleServicesReview.resolveStatus(
                applicationEnabled = true,
                enabledSetting = PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            )
        )
        assertEquals(
            GoogleServiceStatus.DISABLED,
            GoogleServicesReview.resolveStatus(
                applicationEnabled = true,
                enabledSetting = PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER
            )
        )
        assertEquals(
            GoogleServiceStatus.DISABLED,
            GoogleServicesReview.resolveStatus(
                applicationEnabled = true,
                enabledSetting = PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED
            )
        )
    }

    @Test
    fun manifestEnabledValueIsUsedOnlyForDefaultSetting() {
        assertEquals(
            GoogleServiceStatus.ENABLED,
            GoogleServicesReview.resolveStatus(
                applicationEnabled = true,
                enabledSetting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
            )
        )
        assertEquals(
            GoogleServiceStatus.DISABLED,
            GoogleServicesReview.resolveStatus(
                applicationEnabled = false,
                enabledSetting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
            )
        )
    }

    @Test
    fun unknownEnabledSettingFailsClosed() {
        assertEquals(
            GoogleServiceStatus.INSPECTION_UNAVAILABLE,
            GoogleServicesReview.resolveStatus(applicationEnabled = true, enabledSetting = Int.MIN_VALUE)
        )
    }

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
