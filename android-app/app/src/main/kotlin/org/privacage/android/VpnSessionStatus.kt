package org.privacage.android

/**
 * Interprets the service's local lifecycle record without treating a previous process's
 * persisted "active" bit as a live tunnel.
 */
internal object VpnSessionStatus {
    const val KEY_STATE = "dns_vpn_state"
    const val KEY_MESSAGE = "dns_vpn_state_message"
    const val KEY_PROCESS_ID = "dns_vpn_state_process_id"

    const val STATE_STARTING = "starting"
    const val STATE_ACTIVE = "active"
    const val STATE_STOPPING = "stopping"
    const val STATE_STOPPED = "stopped"
    const val STATE_ERROR = "error"

    private val knownStates = setOf(
        STATE_STARTING,
        STATE_ACTIVE,
        STATE_STOPPING,
        STATE_STOPPED,
        STATE_ERROR
    )
    private val statesThatRequireCurrentProcess = setOf(STATE_STARTING, STATE_ACTIVE, STATE_STOPPING)

    internal data class Snapshot(
        val state: String,
        val message: String,
        val stale: Boolean
    )

    internal fun resolve(
        state: String?,
        message: String?,
        processId: String?,
        currentProcessId: String
    ): Snapshot {
        val validState = state?.takeIf { it in knownStates }
        val normalizedState = validState ?: STATE_STOPPED
        if (normalizedState in statesThatRequireCurrentProcess && processId != currentProcessId) {
            return Snapshot(
                STATE_STOPPED,
                "The stored VPN state belongs to an earlier app process; a live tunnel is not assumed.",
                stale = true
            )
        }

        val fallbackMessage = when (normalizedState) {
            STATE_STARTING -> "PrivaCage is preparing the virtual DNS interface."
            STATE_ACTIVE -> "The service established the virtual DNS interface and started its packet loop."
            STATE_STOPPING -> "PrivaCage is stopping DNS filtering."
            STATE_ERROR -> "The DNS filtering service reported an error."
            else -> "DNS filtering is not active."
        }
        return Snapshot(
            state = normalizedState,
            message = if (validState != null) message?.takeIf { it.isNotBlank() } ?: fallbackMessage else fallbackMessage,
            stale = false
        )
    }
}
