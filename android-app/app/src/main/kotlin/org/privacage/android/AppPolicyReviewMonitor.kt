package org.privacage.android

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class PendingAppPolicyReview(
    val packageName: String,
    val trigger: String,
    val firstSeenAt: Long,
    val lastSeenAt: Long,
    val termsUrl: String = "",
    val privacyUrl: String = "",
    val otherUrl: String = ""
)

internal data class AppPolicyReviewCapture(
    val newPendingCount: Int,
    val pendingCount: Int,
    val usageAccessAvailable: Boolean,
    val warning: String?
)

internal data class AppPolicyUsageAccess(
    val available: Boolean,
    val warning: String? = null
)

internal data class AppPolicyReviewState(
    val inventoryInitialized: Boolean,
    val knownPackages: Set<String>,
    val reviewedPackages: Set<String>,
    val lastUsageScanAt: Long,
    val pending: Map<String, PendingAppPolicyReview>
)

internal object AppPolicyReviewEnvelope {
    private const val VERSION = 1
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val MAX_PLAINTEXT_BYTES = 512 * 1024
    private const val MAX_ENVELOPE_BYTES = 700 * 1024
    private val AAD = "PrivaCage local app policy review queue v1".toByteArray(StandardCharsets.UTF_8)

    @Throws(IOException::class)
    fun encrypt(plaintext: String, key: SecretKey): String {
        val clear = plaintext.toByteArray(StandardCharsets.UTF_8)
        if (clear.size > MAX_PLAINTEXT_BYTES) {
            clear.fill(0)
            throw IOException("The app policy review queue exceeds its safety limit.")
        }
        var iv = byteArrayOf()
        var ciphertext = byteArrayOf()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(AAD)
            ciphertext = cipher.doFinal(clear)
            iv = cipher.iv
            if (iv.size != IV_BYTES || ciphertext.size < TAG_BITS / 8) {
                throw IOException("The cryptographic provider returned an invalid app-review envelope.")
            }
            val result = JSONObject()
                .put("version", VERSION)
                .put("iv", Base64.getEncoder().encodeToString(iv))
                .put("ciphertext", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            if (result.toByteArray(StandardCharsets.UTF_8).size > MAX_ENVELOPE_BYTES) {
                throw IOException("The encrypted app review queue exceeds its safety limit.")
            }
            return result
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("The app policy review queue could not be encrypted.", exception)
        } finally {
            clear.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    @Throws(IOException::class)
    fun decrypt(envelope: String, key: SecretKey): String {
        if (envelope.toByteArray(StandardCharsets.UTF_8).size !in 1..MAX_ENVELOPE_BYTES) {
            throw IOException("The encrypted app policy review queue has an invalid size.")
        }
        val wrapper = try {
            StrictJsonKeyScanner.validate(envelope, "Encrypted app policy review envelope")
            JSONObject(envelope)
        } catch (exception: Exception) {
            throw IOException("The encrypted app policy review queue is malformed.", exception)
        }
        if (wrapper.keys().asSequence().toSet() != setOf("version", "iv", "ciphertext") ||
            wrapper.opt("version") !is Int || wrapper.optInt("version") != VERSION
        ) {
            throw IOException("The encrypted app policy review queue has an unsupported envelope.")
        }
        val iv = try {
            Base64.getDecoder().decode(wrapper.getString("iv"))
        } catch (exception: Exception) {
            throw IOException("The encrypted app policy review queue has an invalid IV.", exception)
        }
        val ciphertext = try {
            Base64.getDecoder().decode(wrapper.getString("ciphertext"))
        } catch (exception: Exception) {
            iv.fill(0)
            throw IOException("The encrypted app policy review queue has invalid ciphertext.", exception)
        }
        if (iv.size != IV_BYTES || ciphertext.size < TAG_BITS / 8) {
            iv.fill(0)
            ciphertext.fill(0)
            throw IOException("The encrypted app policy review queue has an invalid cryptographic envelope.")
        }
        val clear = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(AAD)
            cipher.doFinal(ciphertext)
        } catch (exception: GeneralSecurityException) {
            throw IOException("Android Keystore could not authenticate the app policy review queue.", exception)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(clear))
                .toString()
        } catch (exception: Exception) {
            throw IOException("The decrypted app policy review queue is not valid UTF-8.", exception)
        } finally {
            clear.fill(0)
        }
    }
}

internal class AppPolicyReviewStore(context: Context) {
    private val appContext = context.applicationContext
    private val queueFile = File(File(appContext.filesDir, DIRECTORY_NAME), FILE_NAME)

    @Synchronized
    @Throws(IOException::class)
    fun load(): AppPolicyReviewState {
        if (!queueFile.exists()) {
            return AppPolicyReviewState(false, emptySet(), emptySet(), 0L, emptyMap())
        }
        if (!queueFile.isFile || queueFile.length() !in 1..MAX_ENVELOPE_BYTES.toLong()) {
            throw IOException("The encrypted app review queue has an invalid size or type; existing data was preserved.")
        }
        val bytes = try {
            queueFile.readBytes()
        } catch (exception: Exception) {
            throw IOException("The encrypted app review queue could not be read; existing data was preserved.", exception)
        }
        val wrapper = try {
            String(bytes, StandardCharsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
        return decodeState(AppPolicyReviewEnvelope.decrypt(wrapper, loadExistingKey()))
    }

    @Synchronized
    @Throws(IOException::class)
    fun save(state: AppPolicyReviewState) {
        val encoded = encodeState(state)
        val envelope = AppPolicyReviewEnvelope.encrypt(encoded, getOrCreateKey())
        val parent = queueFile.parentFile
            ?: throw IOException("The app review queue has no parent directory.")
        if (!parent.exists() && !parent.mkdirs()) {
            throw IOException("The app review queue directory could not be created.")
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
                    queueFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                )
            } catch (exception: Exception) {
                throw IOException("The encrypted app review queue could not be updated atomically.", exception)
            }
        } finally {
            bytes.fill(0)
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun loadExistingKey(): SecretKey {
        val key = androidKeyStore().getKey(KEY_ALIAS, null) as? SecretKey
        return key ?: throw IOException(
            "The Android Keystore key for the app review queue is missing. The encrypted queue was preserved."
        )
    }

    private fun getOrCreateKey(): SecretKey {
        val store = androidKeyStore()
        val existing = store.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        if (queueFile.exists()) return loadExistingKey()
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
        private const val DIRECTORY_NAME = "privacage-app-review"
        private const val FILE_NAME = "app-review-queue-v1.enc"
        private const val KEY_ALIAS = "org.privacage.android.app-review.queue.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MAX_ENVELOPE_BYTES = 700 * 1024
        private const val MAX_PACKAGES = 2_000
        private const val MAX_PENDING = 100

        internal fun encodeState(state: AppPolicyReviewState): String {
            require(state.knownPackages.size <= MAX_PACKAGES)
            require(state.reviewedPackages.size <= MAX_PACKAGES)
            require(state.pending.size <= MAX_PENDING)
            require(state.lastUsageScanAt >= 0L)
            require(state.reviewedPackages.all { it in state.knownPackages })
            require(state.pending.keys.all { it in state.knownPackages && it !in state.reviewedPackages })
            val known = JSONArray()
            state.knownPackages.sorted().forEach { packageName ->
                require(isValidPackageName(packageName))
                known.put(packageName)
            }
            val reviewed = JSONArray()
            state.reviewedPackages.sorted().forEach { packageName ->
                require(isValidPackageName(packageName))
                reviewed.put(packageName)
            }
            val pending = JSONArray()
            state.pending.toSortedMap().forEach { (packageName, item) ->
                require(packageName == item.packageName && isValidPackageName(packageName))
                require(item.trigger in setOf("installed", "opened"))
                require(item.firstSeenAt > 0L && item.lastSeenAt >= item.firstSeenAt)
                validatePolicyUrl(item.termsUrl)
                validatePolicyUrl(item.privacyUrl)
                validatePolicyUrl(item.otherUrl)
                pending.put(
                    JSONObject()
                        .put("package_name", item.packageName)
                        .put("trigger", item.trigger)
                        .put("first_seen_at", item.firstSeenAt)
                        .put("last_seen_at", item.lastSeenAt)
                        .put("terms_url", item.termsUrl)
                        .put("privacy_url", item.privacyUrl)
                        .put("other_url", item.otherUrl)
                )
            }
            return JSONObject()
                .put("schema_version", 1)
                .put("inventory_initialized", state.inventoryInitialized)
                .put("known_packages", known)
                .put("reviewed_packages", reviewed)
                .put("last_usage_scan_at", state.lastUsageScanAt)
                .put("pending", pending)
                .toString()
        }

        internal fun decodeState(serialized: String): AppPolicyReviewState {
            if (serialized.toByteArray(StandardCharsets.UTF_8).size > 512 * 1024) {
                throw IOException("The app policy review queue exceeds its safety limit.")
            }
            val root = try {
                StrictJsonKeyScanner.validate(serialized, "Decrypted app policy review queue")
                JSONObject(serialized)
            } catch (exception: Exception) {
                throw IOException("The app policy review queue is malformed.", exception)
            }
            if (root.keys().asSequence().toSet() != setOf(
                    "schema_version", "inventory_initialized", "known_packages", "reviewed_packages", "last_usage_scan_at", "pending"
                ) ||
                root.opt("schema_version") !is Int || root.optInt("schema_version") != 1 ||
                root.opt("inventory_initialized") !is Boolean ||
                root.opt("known_packages") !is JSONArray ||
                root.opt("reviewed_packages") !is JSONArray ||
                (root.opt("last_usage_scan_at") !is Int && root.opt("last_usage_scan_at") !is Long) ||
                root.opt("pending") !is JSONArray
            ) {
                throw IOException("The app policy review queue has an unsupported schema.")
            }
            val knownArray = root.getJSONArray("known_packages")
            if (knownArray.length() > MAX_PACKAGES) throw IOException("The app inventory exceeds its safety limit.")
            val known = linkedSetOf<String>()
            for (index in 0 until knownArray.length()) {
                val packageName = knownArray.opt(index) as? String
                    ?: throw IOException("The app inventory contains an invalid package name.")
                if (!isValidPackageName(packageName) || !known.add(packageName)) {
                    throw IOException("The app inventory contains an invalid or duplicate package name.")
                }
            }
            val reviewedArray = root.getJSONArray("reviewed_packages")
            if (reviewedArray.length() > MAX_PACKAGES) throw IOException("The reviewed app inventory exceeds its safety limit.")
            val reviewed = linkedSetOf<String>()
            for (index in 0 until reviewedArray.length()) {
                val packageName = reviewedArray.opt(index) as? String
                    ?: throw IOException("The reviewed app inventory contains an invalid package name.")
                if (!isValidPackageName(packageName) || !reviewed.add(packageName)) {
                    throw IOException("The reviewed app inventory contains an invalid or duplicate package name.")
                }
            }
            val lastUsage = when (val raw = root.opt("last_usage_scan_at")) {
                is Int -> raw.toLong()
                is Long -> raw
                else -> throw IOException("The app usage scan timestamp must be an integer.")
            }
            if (lastUsage < 0L) throw IOException("The app usage scan timestamp is invalid.")
            val pendingArray = root.getJSONArray("pending")
            if (pendingArray.length() > MAX_PENDING) throw IOException("The pending app review queue is full.")
            val pending = linkedMapOf<String, PendingAppPolicyReview>()
            for (index in 0 until pendingArray.length()) {
                val item = pendingArray.optJSONObject(index)
                    ?: throw IOException("The app review queue contains an invalid item.")
                if (item.keys().asSequence().toSet() != setOf(
                        "package_name", "trigger", "first_seen_at", "last_seen_at",
                        "terms_url", "privacy_url", "other_url"
                    )
                ) throw IOException("The app review queue item has missing or unsupported fields.")
                fun requiredString(key: String): String =
                    item.opt(key) as? String
                        ?: throw IOException("The app review queue field '$key' must be a string.")
                fun requiredLong(key: String): Long = when (val raw = item.opt(key)) {
                    is Int -> raw.toLong()
                    is Long -> raw
                    else -> throw IOException("The app review queue field '$key' must be an integer.")
                }
                val packageName = requiredString("package_name")
                val trigger = requiredString("trigger")
                val firstSeen = requiredLong("first_seen_at")
                val lastSeen = requiredLong("last_seen_at")
                val terms = requiredString("terms_url")
                val privacy = requiredString("privacy_url")
                val other = requiredString("other_url")
                if (!isValidPackageName(packageName) || trigger !in setOf("installed", "opened") ||
                    firstSeen <= 0L || lastSeen < firstSeen
                ) throw IOException("The app review queue contains invalid event metadata.")
                try {
                    validatePolicyUrl(terms)
                    validatePolicyUrl(privacy)
                    validatePolicyUrl(other)
                } catch (exception: IllegalArgumentException) {
                    throw IOException("The app review queue contains an invalid policy URL.", exception)
                }
                if (pending.put(
                        packageName,
                        PendingAppPolicyReview(packageName, trigger, firstSeen, lastSeen, terms, privacy, other)
                    ) != null
                ) throw IOException("The app review queue contains duplicate packages.")
            }
            if (!known.containsAll(reviewed)) {
                throw IOException("The reviewed app set contains packages outside the known launcher inventory.")
            }
            if (pending.keys.any { it !in known || it in reviewed }) {
                throw IOException("The pending app queue is inconsistent with the known or reviewed inventory.")
            }
            return AppPolicyReviewState(
                root.getBoolean("inventory_initialized"),
                known,
                reviewed,
                lastUsage,
                pending
            )
        }

        internal fun validatePolicyUrl(value: String) {
            require(value.length <= 2048)
            if (value.isBlank()) return
            val parsed = try {
                URI(value)
            } catch (exception: Exception) {
                throw IllegalArgumentException("Policy links must be valid HTTPS URLs.", exception)
            }
            require(
                parsed.scheme.equals("https", ignoreCase = true) &&
                    !parsed.host.isNullOrBlank() &&
                    parsed.userInfo == null
            ) { "Policy links must use HTTPS and must not contain embedded credentials." }
        }

        private fun isValidPackageName(value: String): Boolean =
            value.length in 3..255 &&
                Regex("^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+$").matches(value)
    }
}

internal object AppPolicyReviewMonitor {
    private const val LAST_USAGE_LOOKBACK_MS = 24L * 60L * 60L * 1000L

    @Synchronized
    fun capture(context: Context): AppPolicyReviewCapture {
        val appContext = context.applicationContext
        val store = AppPolicyReviewStore(appContext)
        val previous = store.load()
        val now = System.currentTimeMillis()
        val currentPackages = launcherPackages(appContext)
        val removedPackages = previous.knownPackages - currentPackages
        val reviewed = (previous.reviewedPackages - removedPackages).toMutableSet()
        val queue = previous.pending.filterKeys { it in currentPackages }.toMutableMap()
        var newPending = 0

        fun enqueue(packageName: String, trigger: String, timestamp: Long) {
            val old = queue[packageName]
            if (old == null) {
                if (queue.size >= 100) {
                    throw IOException("The app review queue is full (100 pending apps). Review or clear existing items first.")
                }
                queue[packageName] = PendingAppPolicyReview(
                    packageName = packageName,
                    trigger = trigger,
                    firstSeenAt = timestamp.coerceAtLeast(1L),
                    lastSeenAt = timestamp.coerceAtLeast(1L)
                )
                newPending++
            } else {
                queue[packageName] = old.copy(
                    trigger = if (old.trigger == "installed") "installed" else trigger,
                    lastSeenAt = maxOf(old.lastSeenAt, timestamp)
                )
            }
        }

        if (!previous.inventoryInitialized) {
            store.save(previous.copy(inventoryInitialized = true, knownPackages = currentPackages, lastUsageScanAt = now))
            return AppPolicyReviewCapture(0, queue.size, hasUsageAccess(appContext), null)
        }

        (currentPackages - previous.knownPackages).forEach { packageName ->
            enqueue(packageName, "installed", now)
        }

        val usageAccess = inspectUsageAccess(appContext)
        val usageAvailable = usageAccess.available
        var lastUsageScan = previous.lastUsageScanAt
        var warning: String? = usageAccess.warning
        if (usageAvailable) {
            if (lastUsageScan <= 0L) {
                // Start a fresh observation window after the user grants special access.
                lastUsageScan = now
            } else {
                try {
                    val usage = appContext.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
                    val start = maxOf(lastUsageScan, now - LAST_USAGE_LOOKBACK_MS)
                    val events = usage.queryEvents(start, now)
                    val event = UsageEvents.Event()
                    val resumedEvent = if (Build.VERSION.SDK_INT >= 29) {
                        UsageEvents.Event.ACTIVITY_RESUMED
                    } else {
                        UsageEvents.Event.MOVE_TO_FOREGROUND
                    }
                    while (events.hasNextEvent()) {
                        events.getNextEvent(event)
                        if (event.eventType != resumedEvent) continue
                        val packageName = event.packageName ?: continue
                        if (packageName == appContext.packageName ||
                            packageName !in currentPackages ||
                            packageName in reviewed
                        ) continue
                        enqueue(packageName, "opened", event.timeStamp.coerceAtLeast(1L))
                    }
                    lastUsageScan = now
                } catch (exception: Exception) {
                    warning = "App-open history could not be read: " +
                        (exception.message ?: exception.javaClass.simpleName) +
                        ". The prior usage checkpoint was retained."
                }
            }
        }

        store.save(
            AppPolicyReviewState(
                inventoryInitialized = true,
                knownPackages = currentPackages,
                reviewedPackages = reviewed,
                lastUsageScanAt = lastUsageScan,
                pending = queue
            )
        )
        return AppPolicyReviewCapture(newPending, queue.size, usageAvailable, warning)
    }

    @Synchronized
    fun pending(context: Context): List<PendingAppPolicyReview> =
        AppPolicyReviewStore(context).load().pending.values.sortedByDescending { it.lastSeenAt }

    @Synchronized
    fun savePolicyLinks(
        context: Context,
        packageName: String,
        termsUrl: String,
        privacyUrl: String,
        otherUrl: String
    ) {
        AppPolicyReviewStore.validatePolicyUrl(termsUrl)
        AppPolicyReviewStore.validatePolicyUrl(privacyUrl)
        AppPolicyReviewStore.validatePolicyUrl(otherUrl)
        val store = AppPolicyReviewStore(context)
        val state = store.load()
        val item = state.pending[packageName]
            ?: throw IOException("This app is no longer in the pending review queue.")
        store.save(
            state.copy(
                pending = state.pending + (packageName to item.copy(
                    termsUrl = termsUrl.trim(),
                    privacyUrl = privacyUrl.trim(),
                    otherUrl = otherUrl.trim()
                ))
            )
        )
    }

    @Synchronized
    fun markReviewed(context: Context, packageName: String) {
        val store = AppPolicyReviewStore(context)
        val state = store.load()
        store.save(markReviewedState(state, packageName))
    }

    internal fun markReviewedState(
        state: AppPolicyReviewState,
        packageName: String
    ): AppPolicyReviewState {
        if (packageName !in state.pending) {
            throw IOException("This app is no longer in the pending review queue.")
        }
        return state.copy(
            pending = state.pending - packageName,
            reviewedPackages = state.reviewedPackages + packageName
        )
    }

    internal fun evaluateUsageAccess(readMode: () -> Int): AppPolicyUsageAccess = try {
        AppPolicyUsageAccess(available = readMode() == AppOpsManager.MODE_ALLOWED)
    } catch (exception: Exception) {
        AppPolicyUsageAccess(
            available = false,
            warning = "Usage Access status could not be checked: " +
                (exception.message ?: exception.javaClass.simpleName) +
                ". Install review remains available."
        )
    }

    fun inspectUsageAccess(context: Context): AppPolicyUsageAccess =
        evaluateUsageAccess {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
                ?: throw IllegalStateException("Android did not expose the AppOps service.")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        }

    internal fun validateLauncherInventory(
        packageNames: Set<String>,
        ownPackageName: String
    ): Set<String> {
        if (ownPackageName.isBlank() || ownPackageName !in packageNames) {
            throw IOException(
                "Android did not return PrivaCage in the launcher inventory; existing review data was preserved."
            )
        }
        val visiblePackages = packageNames - ownPackageName
        if (visiblePackages.isEmpty()) {
            throw IOException(
                "Android returned no other launcher-visible packages; existing review data was preserved."
            )
        }
        return visiblePackages
    }

    private fun launcherPackages(context: Context): Set<String> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val entries = context.packageManager.queryIntentActivities(launcherIntent, 0)
        val packageNames = entries.mapNotNull { it.activityInfo?.packageName }.toSet()
        return validateLauncherInventory(packageNames, context.packageName)
    }
}
