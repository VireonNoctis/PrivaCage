package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacyAutomationClientTest {
    private fun credential(provider: ApiProvider, protocol: String = "mistral") =
        StoredApiCredential(
            provider = provider,
            model = if (provider == ApiProvider.GEMINI) "gemini-2.5-flash" else protocol,
            apiKey = "example-secret-token",
            purpose = "Review text explicitly supplied by the user",
            allowedTasks = setOf(PrivacyAutomationTask.PRIVACY_POLICY_REVIEW)
        )

    @Test
    fun usesFixedHttpsProviderHostsAndProviderSpecificAuthentication() {
        val openAi = PrivacyAutomationClient.buildRequest(
            credential(ApiProvider.OPENAI),
            PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
            "Example policy"
        )
        assertEquals("https://api.openai.com/v1/chat/completions", openAi.endpoint)
        assertEquals("Bearer example-secret-token", openAi.headers["Authorization"])

        val anthropic = PrivacyAutomationClient.buildRequest(
            credential(ApiProvider.ANTHROPIC),
            PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
            "Example policy"
        )
        assertEquals("https://api.anthropic.com/v1/messages", anthropic.endpoint)
        assertEquals("example-secret-token", anthropic.headers["x-api-key"])
        assertEquals("2023-06-01", anthropic.headers["anthropic-version"])

        val gemini = PrivacyAutomationClient.buildRequest(
            credential(ApiProvider.GEMINI),
            PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
            "Example policy"
        )
        assertTrue(gemini.endpoint.startsWith("https://generativelanguage.googleapis.com/"))
        assertEquals("example-secret-token", gemini.headers["x-goog-api-key"])
    }

    @Test
    fun compatibleProvidersUseTheirOwnPinnedHost() {
        val providers = mapOf(
            ApiProvider.MISTRAL to "https://api.mistral.ai/",
            ApiProvider.GROQ to "https://api.groq.com/",
            ApiProvider.DEEPSEEK to "https://api.deepseek.com/",
            ApiProvider.OPENROUTER to "https://openrouter.ai/",
            ApiProvider.XAI to "https://api.x.ai/",
            ApiProvider.TOGETHER to "https://api.together.xyz/",
            ApiProvider.FIREWORKS to "https://api.fireworks.ai/",
            ApiProvider.HUGGING_FACE to "https://router.huggingface.co/"
        )
        providers.forEach { (provider, expectedPrefix) ->
            val request = PrivacyAutomationClient.buildRequest(
                credential(provider),
                PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
                "Only this supplied text"
            )
            assertTrue(request.endpoint.startsWith(expectedPrefix))
            assertTrue(request.endpoint.startsWith("https://"))
        }
    }

    @Test
    fun neverAddsProviderToolCallsAndRequiresTheExplicitTaskPermission() {
        val request = PrivacyAutomationClient.buildRequest(
            credential(ApiProvider.OPENAI),
            PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
            "Only this supplied text"
        )
        assertFalse(request.body.contains("\"tools\""))
        assertTrue(request.body.contains("Do not call tools"))
        assertTrue(request.body.contains("Only this supplied text"))
        assertFalse(request.body.contains("Review text explicitly supplied by the user"))
    }
}
