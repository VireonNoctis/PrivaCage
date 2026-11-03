package org.privacage.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.privacage.rights.PrivacyRight
import org.privacage.rights.RightsJurisdiction
import org.privacage.rights.RightsRequestStatus
import org.privacage.rights.PrivacyRightsRequestBuilder
import java.time.LocalDate
import java.util.UUID

internal data class StoredRightsRequest(
    val id: String,
    val jurisdiction: RightsJurisdiction,
    val right: PrivacyRight,
    val controllerName: String?,
    val preparedOn: LocalDate,
    val receivedOn: LocalDate?,
    val standardResponseDueOn: LocalDate?,
    val extendedResponseDueOn: LocalDate?,
    val extensionNoticeRecorded: Boolean,
    val status: RightsRequestStatus,
    val officialGuidanceUrl: String
) {
    fun displayLabel(): String = buildString {
        append(jurisdiction.label).append(" — ").append(right.label)
        if (!controllerName.isNullOrBlank()) append(" — ").append(controllerName)
        append("\nStatus: ").append(status.name.replace('_', ' '))
        append(" · Prepared ").append(preparedOn)
        standardResponseDueOn?.let { append(" · Planning date ").append(it) }
    }
}

/**
 * Stores only request-tracker metadata in an AES-GCM encrypted app-private preference.
 * It deliberately never stores draft message text, a user's name/email, identity documents,
 * or submission receipts. A status is user-reported workflow state, not proof that a controller
 * received or complied.
 */
internal object LocalRightsRequestStore {
    private const val PREFERENCES = "org.privacage.rights.tracker"
    private const val KEY_RECORDS = "records_json"
    private const val KEY_RECORDS_ENCRYPTED = "records_encrypted_v1"
    private const val KEY_ALIAS = "org.privacage.android.rights-tracker.aes-gcm.v1"
    private const val AAD_LABEL = "rights-request-tracker"
    private const val MAX_RECORDS = 100
    private const val MAX_CONTROLLER_LENGTH = 256
    private const val MAX_STORE_BYTES = 512 * 1024

    fun list(context: Context): List<StoredRightsRequest> {
        val raw = AndroidSensitivePreferenceVault.read(
            context = context,
            preferencesName = PREFERENCES,
            encryptedKey = KEY_RECORDS_ENCRYPTED,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            defaultValue = "[]",
            maximumPlaintextBytes = MAX_STORE_BYTES,
            legacyKeys = setOf(KEY_RECORDS),
            legacyValue = {
                context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                    .getString(KEY_RECORDS, null)
                    ?: throw IllegalStateException("The legacy rights-request tracker has no readable value.")
            },
            validateValue = { decodeRecords(it) }
        ) ?: "[]"
        return decodeRecords(raw)
    }

    internal fun decodeRecords(raw: String): List<StoredRightsRequest> {
        if (raw.length > MAX_STORE_BYTES ||
            raw.toByteArray(Charsets.UTF_8).size > MAX_STORE_BYTES
        ) {
            throw IllegalStateException("The local rights-request tracker exceeds its 512 KiB safety limit; existing data was not overwritten.")
        }
        val array = try {
            StrictJsonKeyScanner.validate(raw, "Local rights-request tracker")
            JSONArray(raw)
        } catch (exception: Exception) {
            throw IllegalStateException("The local rights-request tracker is unreadable; existing data was not overwritten.", exception)
        }
        if (array.length() > MAX_RECORDS) {
            throw IllegalStateException("The local rights-request tracker exceeds its supported record limit; existing data was not overwritten.")
        }
        val records = (0 until array.length()).map { index ->
            val item = array.optJSONObject(index)
                ?: throw IllegalStateException("The local rights-request tracker contains an invalid record; existing data was not overwritten.")
            decode(item)
        }
        val ids = HashSet<String>(records.size)
        if (records.any { !ids.add(it.id) }) {
            throw IllegalStateException("The local rights-request tracker contains duplicate record IDs; existing data was not overwritten.")
        }
        return records
    }

    fun add(context: Context, draft: org.privacage.rights.RightsRequestDraft): StoredRightsRequest {
        val controller = draft.controllerName
        require(controller == null || (
            controller.length <= MAX_CONTROLLER_LENGTH &&
            controller.none(Char::isISOControl)
        )) {
            "Controller name must be at most 256 characters and contain no control characters."
        }
        val current = list(context)
        require(current.size < MAX_RECORDS) { "The local rights-request tracker is full (100 records)." }
        val record = StoredRightsRequest(
            id = UUID.randomUUID().toString(),
            jurisdiction = draft.jurisdiction,
            right = draft.right,
            controllerName = controller,
            preparedOn = draft.preparedOn,
            receivedOn = draft.receivedOn,
            standardResponseDueOn = draft.standardResponseDueOn,
            extendedResponseDueOn = draft.extendedResponseDueOn,
            extensionNoticeRecorded = draft.extendedResponseDueOn != null,
            status = RightsRequestStatus.DRAFT,
            officialGuidanceUrl = draft.officialGuidanceUrl
        )
        save(context, current + record)
        return record
    }

    fun recordReceivedDate(
        context: Context,
        id: String,
        receivedOn: LocalDate,
        extensionNoticeRecorded: Boolean
    ): StoredRightsRequest {
        val current = list(context)
        val index = current.indexOfFirst { it.id == id }
        require(index >= 0) { "The selected rights-request record no longer exists." }
        val existing = current[index]
        require(existing.status != RightsRequestStatus.DRAFT && existing.status != RightsRequestStatus.REVIEWED) {
            "Record a receipt date only after you have manually submitted the request."
        }
        val deadlineGuidance = org.privacage.rights.PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = existing.jurisdiction,
            right = existing.right,
            controllerName = existing.controllerName.orEmpty(),
            preparedOn = LocalDate.now(),
            receivedOn = receivedOn,
            extensionNoticeRecorded = extensionNoticeRecorded
        )
        val updated = existing.copy(
            receivedOn = receivedOn,
            standardResponseDueOn = deadlineGuidance.standardResponseDueOn,
            extendedResponseDueOn = deadlineGuidance.extendedResponseDueOn,
            extensionNoticeRecorded = extensionNoticeRecorded
        )
        save(context, current.toMutableList().apply { set(index, updated) })
        return updated
    }

    fun delete(context: Context, id: String) {
        val current = list(context)
        require(current.any { it.id == id }) { "The selected rights-request record no longer exists." }
        save(context, current.filterNot { it.id == id })
    }

    fun clear(context: Context) {
        save(context, emptyList())
    }

    fun transition(context: Context, id: String, next: RightsRequestStatus): StoredRightsRequest {
        val current = list(context)
        val index = current.indexOfFirst { it.id == id }
        require(index >= 0) { "The selected rights-request record no longer exists." }
        val existing = current[index]
        require(PrivacyRightsRequestBuilder.canTransition(existing.status, next)) {
            "Invalid status transition from ${existing.status} to $next."
        }
        val updated = existing.copy(status = next)
        save(context, current.toMutableList().apply { set(index, updated) })
        return updated
    }

    internal fun encodeRecords(records: List<StoredRightsRequest>): String {
        require(records.size <= MAX_RECORDS) {
            "The local rights-request tracker is full (100 records)."
        }
        val ids = HashSet<String>(records.size)
        records.forEach { record ->
            require(record.id.length == 36) { "Local tracker record ID is invalid." }
            val parsedId = try {
                UUID.fromString(record.id)
            } catch (exception: IllegalArgumentException) {
                throw IllegalArgumentException("Local tracker record ID is invalid.", exception)
            }
            require(parsedId.toString() == record.id && ids.add(record.id)) {
                "Local tracker record IDs must be canonical and unique."
            }
            val controller = record.controllerName
            require(controller == null || (
                controller.isNotBlank() &&
                controller.length <= MAX_CONTROLLER_LENGTH &&
                controller == controller.trim() &&
                controller.none(Char::isISOControl)
            )) { "Local tracker controller name is invalid." }
            require(record.jurisdiction == RightsJurisdiction.CALIFORNIA_DROP || !controller.isNullOrBlank()) {
                "A direct rights request must retain its controller name."
            }
            require(record.officialGuidanceUrl == record.jurisdiction.officialGuidanceUrl) {
                "Local tracker guidance URL does not match the selected jurisdiction."
            }
        }

        val array = JSONArray()
        records.forEach { record ->
            array.put(JSONObject()
                .put("id", record.id)
                .put("jurisdiction", record.jurisdiction.name)
                .put("right", record.right.name)
                .put("controller_name", record.controllerName ?: JSONObject.NULL)
                .put("prepared_on", record.preparedOn.toString())
                .put("received_on", record.receivedOn?.toString() ?: JSONObject.NULL)
                .put("standard_due_on", record.standardResponseDueOn?.toString() ?: JSONObject.NULL)
                .put("extended_due_on", record.extendedResponseDueOn?.toString() ?: JSONObject.NULL)
                .put("extension_notice_recorded", record.extensionNoticeRecorded)
                .put("status", record.status.name)
                .put("official_guidance_url", record.officialGuidanceUrl))
        }
        val encoded = array.toString()
        require(encoded.toByteArray(Charsets.UTF_8).size <= MAX_STORE_BYTES) {
            "The local rights-request tracker exceeds its 512 KiB safety limit."
        }
        // Reuse the strict reader so writes and reads enforce the same record invariants.
        decodeRecords(encoded)
        return encoded
    }

    private fun save(context: Context, records: List<StoredRightsRequest>) {
        val encoded = encodeRecords(records)
        AndroidSensitivePreferenceVault.write(
            context = context,
            preferencesName = PREFERENCES,
            encryptedKey = KEY_RECORDS_ENCRYPTED,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            plaintext = encoded,
            maximumPlaintextBytes = MAX_STORE_BYTES,
            legacyKeys = setOf(KEY_RECORDS),
            validateValue = { decodeRecords(it) }
        )
    }

    private fun decode(item: JSONObject): StoredRightsRequest {
        return try {
            val expectedKeys = setOf(
                "id", "jurisdiction", "right", "controller_name", "prepared_on", "received_on",
                "standard_due_on", "extended_due_on", "extension_notice_recorded",
                "status", "official_guidance_url"
            )
            val legacyNullableKeys = setOf(
                "controller_name", "received_on", "standard_due_on", "extended_due_on"
            )
            val actualKeys = item.keys().asSequence().toSet()
            require(
                actualKeys.all { it in expectedKeys } &&
                    expectedKeys.minus(actualKeys).all { it in legacyNullableKeys }
            ) {
                "Local tracker record fields are missing or unsupported."
            }

            fun requiredString(key: String): String =
                item.opt(key) as? String
                    ?: throw IllegalArgumentException("Local tracker field $key must be a string.")

            fun optionalString(key: String): String? {
                // Before explicit JSON null serialization, Android JSONObject.put(key, null)
                // omitted nullable keys. Continue reading those existing records.
                if (!item.has(key)) return null
                return when (val value = item.opt(key)) {
                    JSONObject.NULL -> null
                    is String -> value
                    else -> throw IllegalArgumentException("Local tracker field $key must be a string or null.")
                }
            }

            fun optionalDate(key: String): LocalDate? = optionalString(key)?.let { raw ->
                val parsed = try {
                    LocalDate.parse(raw)
                } catch (exception: Exception) {
                    throw IllegalArgumentException("Local tracker date $key is invalid.", exception)
                }
                require(parsed.toString() == raw) { "Local tracker date $key is not canonical." }
                parsed
            }

            val id = requiredString("id")
            val parsedId = try {
                UUID.fromString(id)
            } catch (exception: IllegalArgumentException) {
                throw IllegalArgumentException("Local tracker record ID is invalid.", exception)
            }
            require(parsedId.toString() == id) { "Local tracker record ID is not canonical." }

            val jurisdiction = RightsJurisdiction.valueOf(requiredString("jurisdiction"))
            val right = PrivacyRight.valueOf(requiredString("right"))
            val controller = optionalString("controller_name")
            require(controller == null || (
                controller.isNotBlank() &&
                controller.length <= MAX_CONTROLLER_LENGTH &&
                controller == controller.trim() &&
                controller.none(Char::isISOControl)
            )) { "Local tracker controller name is invalid." }
            require(jurisdiction == RightsJurisdiction.CALIFORNIA_DROP || !controller.isNullOrBlank()) {
                "A direct rights request must retain its controller name."
            }

            val preparedOn = optionalDate("prepared_on")
                ?: throw IllegalArgumentException("Local tracker preparation date is required.")
            val receivedOn = optionalDate("received_on")
            val standardDueOn = optionalDate("standard_due_on")
            val extendedDueOn = optionalDate("extended_due_on")
            val extensionNoticeRecorded = item.opt("extension_notice_recorded") as? Boolean
                ?: throw IllegalArgumentException("Local tracker extension flag must be a boolean.")
            val status = RightsRequestStatus.valueOf(requiredString("status"))
            val guidanceUrl = requiredString("official_guidance_url")
            require(guidanceUrl == jurisdiction.officialGuidanceUrl) {
                "Local tracker guidance URL does not match the selected jurisdiction."
            }

            if (receivedOn == null) {
                require(standardDueOn == null && extendedDueOn == null && !extensionNoticeRecorded) {
                    "Local tracker deadlines require a recorded receipt date."
                }
            }
            if (jurisdiction == RightsJurisdiction.CALIFORNIA_DROP) {
                require(standardDueOn == null && extendedDueOn == null) {
                    "The DROP checklist must not contain an individual response deadline."
                }
            } else if (receivedOn != null) {
                val expectedStandardDueOn = when (jurisdiction) {
                    RightsJurisdiction.UK_GDPR -> receivedOn.plusMonths(1)
                    RightsJurisdiction.CALIFORNIA_CCPA -> receivedOn.plusDays(45)
                    RightsJurisdiction.CALIFORNIA_DROP -> null
                }
                val expectedExtendedDueOn = if (!extensionNoticeRecorded) {
                    null
                } else {
                    when (jurisdiction) {
                        RightsJurisdiction.UK_GDPR -> receivedOn.plusMonths(3)
                        RightsJurisdiction.CALIFORNIA_CCPA -> receivedOn.plusDays(90)
                        RightsJurisdiction.CALIFORNIA_DROP -> null
                    }
                }
                require(standardDueOn == expectedStandardDueOn) {
                    "The standard planning date does not match the configured jurisdiction calculation."
                }
                require(extendedDueOn == expectedExtendedDueOn) {
                    "The extended planning date does not match the recorded extension notice and jurisdiction calculation."
                }
            }

            StoredRightsRequest(
                id, jurisdiction, right, controller, preparedOn, receivedOn, standardDueOn,
                extendedDueOn, extensionNoticeRecorded, status, guidanceUrl
            )
        } catch (exception: Exception) {
            throw IllegalStateException("The local rights-request tracker contains a malformed record; existing data was not overwritten.", exception)
        }
    }
}
