package org.privacage.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PrivacyPolicyDocumentsTest {
    private val repositoryRoot: File
        get() = File(
            System.getProperty("privacage.repo-root")
                ?: throw IllegalStateException("Gradle must provide the repository root for policy-document tests.")
        )

    private val policyDirectory: File
        get() = File(repositoryRoot, "docs/privacy")

    private fun read(name: String): String {
        val file = File(policyDirectory, name)
        require(file.isFile) { "Required policy document is missing: " + file.path }
        require(file.length() in 1..(256L * 1024L)) {
            "Policy document has an invalid size: " + file.path
        }
        return file.readText(Charsets.UTF_8)
    }

    @Test
    fun allPolicyDocumentsExistAndAreConfiguredAsAndroidAssets() {
        val names = listOf(
            "README.md",
            "TERMS_OF_SERVICE.md",
            "PRIVACY_POLICY.md",
            "NO_TELEMETRY_POLICY.md",
            "DATA_RETENTION_AND_ENCRYPTION.md",
            "AUTHORITY_REQUESTS.md",
            "EXTERNAL_SERVICES.md"
        )
        names.forEach { name ->
            val content = read(name)
            assertTrue(name + " must have a Markdown heading", content.startsWith("# "))
        }

        val gradle = File(repositoryRoot, "android-app/app/build.gradle.kts").readText(Charsets.UTF_8)
        assertTrue(
            "The local policy documents must be packaged as Android assets.",
            gradle.contains("""assets.srcDir("../../docs/privacy")""")
        )
    }

    @Test
    fun inAppPolicyReaderLoadsPackagedAssetsWithoutAnHttpClient() {
        val source = File(
            repositoryRoot,
            "android-app/app/src/main/kotlin/org/privacage/android/LegalPrivacyActivity.kt"
        ).readText(Charsets.UTF_8)

        assertTrue(source.contains("assets.open(name)"))
        assertFalse(source.contains("HttpURLConnection"))
        assertFalse(source.contains("openConnection("))
        assertFalse(source.contains("URL("))
    }

    @Test
    fun authorityPolicyRejectsVoluntaryDisclosureButDoesNotPromiseImmunityFromLaw() {
        val policy = read("AUTHORITY_REQUESTS.md").lowercase()
        assertTrue(policy.contains("does not voluntarily"))
        assertTrue(policy.contains("binding legal demand") || policy.contains("valid legal"))
        assertTrue(policy.contains("minimum information"))
        assertTrue(policy.contains("notify") && policy.contains("lawfully"))
        assertTrue(policy.contains("opaque encrypted packet"))
        assertFalse(policy.contains("we will never disclose any information under any circumstances"))
    }

    @Test
    fun noTelemetryPolicySeparatesProductAnalyticsFromUserRequestedNetworkTraffic() {
        val policy = read("NO_TELEMETRY_POLICY.md").lowercase()
        assertTrue(policy.contains("product telemetry"))
        assertTrue(policy.contains("product analytics"))
        assertTrue(policy.contains("dns filtering"))
        assertTrue(policy.contains("app-policy"))
        assertFalse(policy.contains("ai provider"))
        assertTrue(policy.contains("encrypted sync"))
        assertTrue(policy.contains("platform/oem"))
    }

    @Test
    fun appPolicyReviewRemainsLocalAndHasNoProviderAutomationEntryPoint() {
        val appRoot = File(repositoryRoot, "android-app/app/src/main")
        val main = File(
            appRoot,
            "kotlin/org/privacage/android/MainActivity.kt"
        ).readText(Charsets.UTF_8)
        val policyQueue = File(
            appRoot,
            "kotlin/org/privacage/android/AppPolicyReviewActivity.kt"
        ).readText(Charsets.UTF_8)
        val manifest = File(appRoot, "AndroidManifest.xml").readText(Charsets.UTF_8)
        val androidPackage = File(
            appRoot,
            "kotlin/org/privacage/android"
        )

        assertFalse(main.contains("ApiAutomationActivity"))
        assertFalse(main.contains("showApiSetupPromptOnce"))
        assertFalse(policyQueue.contains("PrivacyAutomationTask"))
        assertFalse(policyQueue.contains("ApiAutomationActivity"))
        assertFalse(policyQueue.contains("Analyse pasted document"))
        assertFalse(manifest.contains("ApiAutomationActivity"))
        assertFalse(File(androidPackage, "ApiAutomationActivity.kt").exists())
        assertFalse(File(androidPackage, "ApiTokenVault.kt").exists())
        assertFalse(File(androidPackage, "PrivacyAutomationClient.kt").exists())
    }

    @Test
    fun privacyPolicyDisclosesExternalRecipientsAndIncompleteControllerDetails() {
        val policy = read("PRIVACY_POLICY.md")
        assertTrue(policy.contains("[CONTROLLER LEGAL NAME / ENTITY]"))
        assertTrue(policy.contains("[PRIVACY CONTACT EMAIL]"))
        assertTrue(policy.contains("DNS resolver"))
        assertFalse(policy.contains("AI provider"))
        assertTrue(policy.contains("relay"))
        assertTrue(policy.contains("international"))
        assertTrue(policy.contains("Keystore"))
    }
}
