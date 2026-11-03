package org.privacage.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64 as JavaBase64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal enum class ApiProvider(
    val id: String,
    val label: String,
    val endpoint: String,
    val protocol: Protocol
) {
    OPENAI("openai", "OpenAI", "https://api.openai.com/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    ANTHROPIC("anthropic", "Anthropic", "https://api.anthropic.com/v1/messages", Protocol.ANTHROPIC),
    GEMINI("gemini", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/models/", Protocol.GEMINI),
    COHERE("cohere", "Cohere", "https://api.cohere.com/v2/chat", Protocol.COHERE),
    MISTRAL("mistral", "Mistral AI", "https://api.mistral.ai/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    GROQ("groq", "Groq", "https://api.groq.com/openai/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    DEEPSEEK("deepseek", "DeepSeek", "https://api.deepseek.com/chat/completions", Protocol.OPENAI_COMPATIBLE),
    OPENROUTER("openrouter", "OpenRouter", "https://openrouter.ai/api/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    XAI("xai", "xAI", "https://api.x.ai/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    TOGETHER("together", "Together AI", "https://api.together.ai/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    FIREWORKS("fireworks", "Fireworks AI", "https://api.fireworks.ai/inference/v1/chat/completions", Protocol.OPENAI_COMPATIBLE),
    HUGGING_FACE("huggingface", "Hugging Face Inference", "https://router.huggingface.co/v1/chat/completions", Protocol.OPENAI_COMPATIBLE);

    enum class Protocol { OPENAI_COMPATIBLE, ANTHROPIC, GEMINI, COHERE }

    companion object {
        fun fromId(id: String): ApiProvider =
            values().firstOrNull { it.id == id }
                ?: throw IOException("The saved API provider is not supported.")
    }
}

internal enum class PrivacyAutomationTask(
    val id: String,
    val label: String,
    val instruction: String
) {
    TERMS_REVIEW(
        "terms_review",
        "Review Terms of Service",
        "Review the supplied Terms of Service. Summarise user obligations, account termination, content licences, dispute clauses, data sharing references, charges, and material risks. Separate explicit terms from inference and quote only short excerpts."
    ),
    PRIVACY_POLICY_REVIEW(
        "privacy_policy_review",
        "Review Privacy Policy",
        "Review the supplied privacy policy. Identify data categories, purposes, sharing recipients, retention, international transfers, user rights, security claims, profiling, and unclear omissions. Distinguish the policy's claims from verified facts."
    ),
    APP_DISCLOSURE_REVIEW(
        "app_disclosure_review",
        "Review App Store / Data Safety disclosure",
        "Review the supplied app-store privacy or data-safety disclosure. Explain declared collection, sharing, security practices, and mismatches or unanswered questions relative to any other supplied policy text. Do not claim the disclosure proves actual runtime behavior."
    ),
    APK_REPORT_EXPLANATION(
        "apk_report_explanation",
        "Explain an APK privacy report",
        "Explain the supplied static APK inspection report. Distinguish manifest declarations, embedded indicators, signer facts, and inferences. Do not claim that static markers prove runtime collection or that their absence proves safety."
    ),
    PERMISSION_AUDIT_EXPLANATION(
        "permission_audit_explanation",
        "Explain a permission audit",
        "Explain the supplied permission audit. Distinguish declared permissions, current grants, and actual permission use. A granted permission does not prove use."
    ),
    DNS_HISTORY_REVIEW(
        "dns_history_review",
        "Review DNS history",
        "Review only the supplied DNS history excerpt. Identify domains that match the provided indicators, uncertainty, and possible next checks. DNS observation alone does not prove the content sent or identify every app using a domain."
    ),
    RIGHTS_REQUEST_DRAFT(
        "rights_request_draft",
        "Help draft a data-rights request",
        "Help the user prepare a draft data-rights request from the supplied facts. Identify missing details and jurisdiction questions. This is drafting assistance, not legal advice, not proof of eligibility, and must never be submitted automatically."
    ),
    CUSTOM_ANALYSIS(
        "custom_analysis",
        "Custom text analysis",
        "Answer the user's question about the supplied text. Do not claim access to device state or perform actions outside this text-only request."
    );

    companion object {
        fun fromId(id: String): PrivacyAutomationTask =
            values().firstOrNull { it.id == id }
                ?: throw IOException("The saved automation permission is not supported.")
    }
}

internal data class StoredApiCredential(
    val provider: ApiProvider,
    val model: String,
    val apiKey: String,
    val purpose: String,
    val allowedTasks: Set<PrivacyAutomationTask>
)

internal object ApiTokenEnvelope {
    private const val VERSION = 1
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val MAX_PLAINTEXT_BYTES = 128 * 1024
    private const val MAX_ENVELOPE_BYTES = 180 * 1024
    private val AAD = "PrivaCage Android API credential vault v1".toByteArray(StandardCharsets.UTF_8)

    @Throws(IOException::class)
    fun encrypt(serialized: String, key: SecretKey): String {
        val cleartext = serialized.toByteArray(StandardCharsets.UTF_8)
        if (cleartext.size > MAX_PLAINTEXT_BYTES) {
            cleartext.fill(0)
            throw IOException("The API credential vault exceeds its safety limit.")
        }
        var iv = byteArrayOf()
        var ciphertext = byteArrayOf()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(AAD)
            ciphertext = cipher.doFinal(cleartext)
            iv = cipher.iv
            if (iv.size != IV_BYTES || ciphertext.size < TAG_BITS / 8) {
                throw IOException("The cryptographic provider returned an invalid credential envelope.")
            }
            val envelope = JSONObject()
                .put("version", VERSION)
                .put("iv", JavaBase64.getEncoder().encodeToString(iv))
                .put("ciphertext", JavaBase64.getEncoder().encodeToString(ciphertext))
                .toString()
            if (envelope.toByteArray(StandardCharsets.UTF_8).size > MAX_ENVELOPE_BYTES) {
                throw IOException("The encrypted API credential vault exceeds its safety limit.")
            }
            return envelope
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("The API credential vault could not be encrypted.", exception)
        } finally {
            cleartext.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    @Throws(IOException::class)
    fun decrypt(envelope: String, key: SecretKey): String {
        if (envelope.toByteArray(StandardCharsets.UTF_8).size !in 1..MAX_ENVELOPE_BYTES) {
            throw IOException("The encrypted API credential vault has an invalid size.")
        }
        val wrapper = try {
            StrictJsonKeyScanner.validate(envelope, "Encrypted API credential envelope")
            JSONObject(envelope)
        } catch (exception: Exception) {
            throw IOException("The encrypted API credential vault is malformed.", exception)
        }
        val keys = wrapper.keys().asSequence().toSet()
        if (keys != setOf("version", "iv", "ciphertext") || wrapper.opt("version") !is Int ||
            wrapper.optInt("version") != VERSION
        ) {
            throw IOException("The encrypted API credential vault has an unsupported envelope.")
        }
        val iv = try {
            JavaBase64.getDecoder().decode(wrapper.getString("iv"))
        } catch (exception: Exception) {
            throw IOException("The encrypted API credential vault has an invalid IV.", exception)
        }
        val ciphertext = try {
            JavaBase64.getDecoder().decode(wrapper.getString("ciphertext"))
        } catch (exception: Exception) {
            iv.fill(0)
            throw IOException("The encrypted API credential vault has invalid ciphertext.", exception)
        }
        if (iv.size != IV_BYTES || ciphertext.size < TAG_BITS / 8) {
            iv.fill(0)
            ciphertext.fill(0)
            throw IOException("The encrypted API credential vault has an invalid cryptographic envelope.")
        }
        val cleartext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(AAD)
            cipher.doFinal(ciphertext)
        } catch (exception: GeneralSecurityException) {
            throw IOException("Android Keystore could not authenticate the API credential vault.", exception)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(cleartext))
                .toString()
        } catch (exception: Exception) {
            throw IOException("The decrypted API credential vault is not valid UTF-8.", exception)
        } finally {
            cleartext.fill(0)
        }
    }
}

internal class ApiTokenVault(context: Context) {
    private val appContext = context.applicationContext
    private val vaultFile = File(File(appContext.filesDir, DIRECTORY_NAME), FILE_NAME)

    @Synchronized
    @Throws(IOException::class)
    fun credential(provider: ApiProvider): StoredApiCredential? =
        readCredentials()[provider.id]

    @Synchronized
    @Throws(IOException::class)
    fun save(credential: StoredApiCredential) {
        validateCredential(credential)
        val records = readCredentials().toMutableMap()
        records[credential.provider.id] = credential
        writeCredentials(records.values.toList())
    }

    @Synchronized
    @Throws(IOException::class)
    fun delete(provider: ApiProvider): Boolean {
        val records = readCredentials().toMutableMap()
        if (records.remove(provider.id) == null) return false
        if (records.isEmpty()) {
            if (!vaultFile.delete() && vaultFile.exists()) {
                throw IOException("The API credential vault could not be removed.")
            }
            return true
        }
        writeCredentials(records.values.toList())
        return true
    }

    @Synchronized
    @Throws(IOException::class)
    fun hasAnyCredential(): Boolean = readCredentials().isNotEmpty()

    private fun readCredentials(): Map<String, StoredApiCredential> {
        if (!vaultFile.exists()) return emptyMap()
        if (!vaultFile.isFile || vaultFile.length() !in 1..MAX_FILE_BYTES.toLong()) {
            throw IOException("The encrypted API credential vault has an invalid size or type; existing data was preserved.")
        }
        val wrapperBytes = try {
            vaultFile.readBytes()
        } catch (exception: Exception) {
            throw IOException("The encrypted API credential vault could not be read; existing data was preserved.", exception)
        }
        val wrapperText = try {
            String(wrapperBytes, StandardCharsets.UTF_8)
        } finally {
            wrapperBytes.fill(0)
        }
        val plaintext = ApiTokenEnvelope.decrypt(wrapperText, loadExistingKey())
        return decodeCredentials(plaintext)
    }

    private fun writeCredentials(credentials: List<StoredApiCredential>) {
        val serialized = encodeCredentials(credentials)
        val envelope = ApiTokenEnvelope.encrypt(serialized, getOrCreateKey())
        val parent = vaultFile.parentFile
            ?: throw IOException("The encrypted API credential vault has no parent directory.")
        if (!parent.exists() && !parent.mkdirs()) {
            throw IOException("The encrypted API credential directory could not be created.")
        }
        val temporary = File(parent, "$FILE_NAME.tmp")
        val bytes = envelope.toByteArray(StandardCharsets.UTF_8)
        try {
            FileOutputStream(temporary).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            try {
                Files.move(
                    temporary.toPath(),
                    vaultFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                )
            } catch (exception: Exception) {
                throw IOException("The encrypted API credential vault could not be updated atomically.", exception)
            }
        } finally {
            bytes.fill(0)
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun loadExistingKey(): SecretKey {
        val key = androidKeyStore().getKey(KEY_ALIAS, null) as? SecretKey
        return key ?: throw IOException(
            "The Android Keystore key for the API credential vault is missing. " +
                "The encrypted vault was preserved; do not overwrite it."
        )
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = androidKeyStore()
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        if (vaultFile.exists()) return loadExistingKey()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        private const val DIRECTORY_NAME = "privacage-ai"
        private const val FILE_NAME = "api-credentials-v1.enc"
        private const val KEY_ALIAS = "org.privacage.android.ai.credentials.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MAX_FILE_BYTES = 180 * 1024

        internal fun validateCredential(credential: StoredApiCredential) {
            require(credential.apiKey.length in 8..4096) { "API key length is outside the supported range." }
            require(credential.apiKey.none { it.isWhitespace() || it.isISOControl() }) {
                "API keys must not contain whitespace or control characters."
            }
            require(credential.model.matches(Regex("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"))) {
                "Enter a valid model ID from the selected provider."
            }
            require(credential.purpose.length <= 500 && credential.purpose.none(Char::isISOControl)) {
                "The intended-use note is too long or contains control characters."
            }
            require(credential.allowedTasks.isNotEmpty()) {
                "Select at least one permitted automation task."
            }
        }

        internal fun encodeCredentials(credentials: List<StoredApiCredential>): String {
            require(credentials.size <= ApiProvider.values().size)
            val seen = HashSet<String>()
            val items = JSONArray()
            credentials.forEach { credential ->
                validateCredential(credential)
                require(seen.add(credential.provider.id)) { "Only one API credential per provider may be stored." }
                val scopes = JSONArray()
                credential.allowedTasks.map { it.id }.sorted().forEach(scopes::put)
                items.put(
                    JSONObject()
                        .put("provider", credential.provider.id)
                        .put("model", credential.model)
                        .put("api_key", credential.apiKey)
                        .put("purpose", credential.purpose)
                        .put("allowed_tasks", scopes)
                )
            }
            return JSONObject()
                .put("schema_version", 1)
                .put("credentials", items)
                .toString()
        }

        internal fun decodeCredentials(serialized: String): Map<String, StoredApiCredential> {
            if (serialized.toByteArray(StandardCharsets.UTF_8).size > 128 * 1024) {
                throw IOException("The API credential vault exceeds its safety limit.")
            }
            val root = try {
                StrictJsonKeyScanner.validate(serialized, "Decrypted API credential vault")
                JSONObject(serialized)
            } catch (exception: Exception) {
                throw IOException("The decrypted API credential vault is malformed.", exception)
            }
            if (root.keys().asSequence().toSet() != setOf("schema_version", "credentials") ||
                root.opt("schema_version") !is Int || root.optInt("schema_version") != 1 ||
                root.opt("credentials") !is JSONArray
            ) {
                throw IOException("The decrypted API credential vault has an unsupported schema.")
            }
            val array = root.getJSONArray("credentials")
            if (array.length() > ApiProvider.values().size) {
                throw IOException("The API credential vault contains too many providers.")
            }
            val result = linkedMapOf<String, StoredApiCredential>()
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index)
                    ?: throw IOException("The API credential vault contains an invalid credential.")
                if (item.keys().asSequence().toSet() !=
                    setOf("provider", "model", "api_key", "purpose", "allowed_tasks")
                ) {
                    throw IOException("The API credential vault contains missing or unsupported fields.")
                }
                val providerId = item.opt("provider") as? String
                    ?: throw IOException("The API credential provider ID must be a string.")
                val model = item.opt("model") as? String
                    ?: throw IOException("The API credential model ID must be a string.")
                val apiKey = item.opt("api_key") as? String
                    ?: throw IOException("The API credential token must be a string.")
                val purpose = item.opt("purpose") as? String
                    ?: throw IOException("The API credential purpose note must be a string.")
                val provider = ApiProvider.fromId(providerId)
                val scopes = item.optJSONArray("allowed_tasks")
                    ?: throw IOException("The API credential permissions are invalid.")
                val allowed = linkedSetOf<PrivacyAutomationTask>()
                for (scopeIndex in 0 until scopes.length()) {
                    val scopeId = scopes.opt(scopeIndex) as? String
                        ?: throw IOException("The API credential permissions contain an invalid value.")
                    if (!allowed.add(PrivacyAutomationTask.fromId(scopeId))) {
                        throw IOException("The API credential permissions contain duplicates.")
                    }
                }
                val credential = StoredApiCredential(
                    provider = provider,
                    model = model,
                    apiKey = apiKey,
                    purpose = purpose,
                    allowedTasks = allowed
                )
                try {
                    validateCredential(credential)
                } catch (exception: IllegalArgumentException) {
                    throw IOException("The API credential vault contains invalid credential fields.", exception)
                }
                if (result.put(provider.id, credential) != null) {
                    throw IOException("The API credential vault contains duplicate providers.")
                }
            }
            return result
        }
    }
}
