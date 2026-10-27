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
 * Stores only request-tracker metadata in app-private preferences. It deliberately never stores
 * draft message text, a user's name/email, identity documents, or submission receipts.
 * A status is user-reported workflow state, not proof that a controller received or complied.
 */
internal object LocalRightsRequestStore {
    private const val PREFERENCES = "org.privacage.rights.tracker"
    private const val KEY_RECORDS = "records_json"
    private const val MAX_RECORDS = 100
    private const val MAX_CONTROLLER_LENGTH = 256

    fun list(context: Context): List<StoredRightsRequest> {
        val raw = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(KEY_RECORDS, "[]") ?: "[]"
        val array = try {
            JSONArray(raw)
        } catch (exception: Exception) {
            throw IllegalStateException("The local rights-request tracker is unreadable; existing data was not overwritten.", exception)
        }
        if (array.length() > MAX_RECORDS) {
            throw IllegalStateException("The local rights-request tracker exceeds its supported record limit; existing data was not overwritten.")
        }
        return (0 until array.length()).map { index ->
            val item = array.optJSONObject(index)
                ?: throw IllegalStateException("The local rights-request tracker contains an invalid record; existing data was not overwritten.")
            decode(item)
        }
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

    private fun save(context: Context, records: List<StoredRightsRequest>) {
        val array = JSONArray()
        records.forEach { record ->
            array.put(JSONObject()
                .put("id", record.id)
                .put("jurisdiction", record.jurisdiction.name)
                .put("right", record.right.name)
                .put("controller_name", record.controllerName)
                .put("prepared_on", record.preparedOn.toString())
                .put("received_on", record.receivedOn?.toString())
                .put("standard_due_on", record.standardResponseDueOn?.toString())
                .put("extended_due_on", record.extendedResponseDueOn?.toString())
                .put("extension_notice_recorded", record.extensionNoticeRecorded)
                .put("status", record.status.name)
                .put("official_guidance_url", record.officialGuidanceUrl))
        }
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        check(preferences.edit().putString(KEY_RECORDS, array.toString()).commit()) {
            "Could not persist the local rights-request tracker."
        }
    }

    private fun decode(item: JSONObject): StoredRightsRequest {
        return try {
            val keys = setOf(
                "id", "jurisdiction", "right", "controller_name", "prepared_on", "received_on",
                "standard_due_on", "extended_due_on", "extension_notice_recorded",
                "status", "official_guidance_url"
            )
            val iterator = item.keys()
            while (iterator.hasNext()) {
                val key = iterator.next()
                require(key in keys) { "Unknown local tracker field: $key" }
            }
            val id = item.getString("id")
            require(id.length <= 64)
            val jurisdiction = RightsJurisdiction.valueOf(item.getString("jurisdiction"))
            val right = PrivacyRight.valueOf(item.getString("right"))
            val controller = if (item.isNull("controller_name")) null else item.getString("controller_name")
            require(controller == null || controller.length <= MAX_CONTROLLER_LENGTH)
            val preparedOn = LocalDate.parse(item.getString("prepared_on"))
            fun optionalDate(key: String): LocalDate? =
                if (item.isNull(key)) null else LocalDate.parse(item.getString(key))
            val receivedOn = optionalDate("received_on")
            val standardDueOn = optionalDate("standard_due_on")
            val extendedDueOn = optionalDate("extended_due_on")
            val status = RightsRequestStatus.valueOf(item.getString("status"))
            val guidanceUrl = item.getString("official_guidance_url")
            require(guidanceUrl.startsWith("https://") && guidanceUrl.length <= 2048)
            StoredRightsRequest(
                id, jurisdiction, right, controller, preparedOn, receivedOn, standardDueOn,
                extendedDueOn, item.optBoolean("extension_notice_recorded", false), status, guidanceUrl
            )
        } catch (exception: Exception) {
            throw IllegalStateException("The local rights-request tracker contains a malformed record; existing data was not overwritten.", exception)
        }
    }
}
