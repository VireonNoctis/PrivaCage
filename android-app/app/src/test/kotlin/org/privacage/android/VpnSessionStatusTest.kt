package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnSessionStatusTest {
    @Test
    fun activeStateIsAcceptedOnlyForCurrentProcess() {
        val snapshot = VpnSessionStatus.resolve(
            state = VpnSessionStatus.STATE_ACTIVE,
            message = "Tunnel established.",
            processId = "process-a",
            currentProcessId = "process-a"
        )

        assertEquals(VpnSessionStatus.STATE_ACTIVE, snapshot.state)
        assertEquals("Tunnel established.", snapshot.message)
        assertFalse(snapshot.stale)
    }

    @Test
    fun activeStateFromEarlierProcessIsReportedAsStopped() {
        val snapshot = VpnSessionStatus.resolve(
            state = VpnSessionStatus.STATE_ACTIVE,
            message = "Old active state.",
            processId = "process-a",
            currentProcessId = "process-b"
        )

        assertEquals(VpnSessionStatus.STATE_STOPPED, snapshot.state)
        assertTrue(snapshot.stale)
        assertFalse(snapshot.message.contains("Old active state"))
    }

    @Test
    fun startingStateWithoutProcessIdentityIsNotTrusted() {
        val snapshot = VpnSessionStatus.resolve(
            state = VpnSessionStatus.STATE_STARTING,
            message = "Old start.",
            processId = null,
            currentProcessId = "process-b"
        )

        assertEquals(VpnSessionStatus.STATE_STOPPED, snapshot.state)
        assertTrue(snapshot.stale)
    }

    @Test
    fun previousProcessErrorIsPreservedAsACompletedFailure() {
        val snapshot = VpnSessionStatus.resolve(
            state = VpnSessionStatus.STATE_ERROR,
            message = "DNS filtering could not start.",
            processId = "process-a",
            currentProcessId = "process-b"
        )

        assertEquals(VpnSessionStatus.STATE_ERROR, snapshot.state)
        assertEquals("DNS filtering could not start.", snapshot.message)
        assertFalse(snapshot.stale)
    }

    @Test
    fun unknownStateFallsBackToStoppedWithoutUsingUnknownMessage() {
        val snapshot = VpnSessionStatus.resolve(
            state = "connected-ish",
            message = "Unrecognized state.",
            processId = "process-a",
            currentProcessId = "process-a"
        )

        assertEquals(VpnSessionStatus.STATE_STOPPED, snapshot.state)
        assertEquals("DNS filtering is not active.", snapshot.message)
        assertFalse(snapshot.stale)
    }

    @Test
    fun seededPersistedStateMutationsAlwaysResolveToBoundedKnownStatus() {
        val random = java.util.Random(0x56504e53L)
        val states = listOf(
            VpnSessionStatus.STATE_STARTING,
            VpnSessionStatus.STATE_ACTIVE,
            VpnSessionStatus.STATE_STOPPING,
            VpnSessionStatus.STATE_STOPPED,
            VpnSessionStatus.STATE_ERROR,
            "connected-ish",
            "",
            null
        )
        repeat(512) {
            val randomMessage = CharArray(random.nextInt(0, 1025)) {
                random.nextInt(0, 0x10000).toChar()
            }.concatToString()
            val snapshot = VpnSessionStatus.resolve(
                state = states[random.nextInt(states.size)],
                message = randomMessage,
                processId = if (random.nextBoolean()) "process-a" else null,
                currentProcessId = "process-a"
            )
            assertTrue(snapshot.state in setOf(
                VpnSessionStatus.STATE_STARTING,
                VpnSessionStatus.STATE_ACTIVE,
                VpnSessionStatus.STATE_STOPPING,
                VpnSessionStatus.STATE_STOPPED,
                VpnSessionStatus.STATE_ERROR
            ))
            assertTrue(snapshot.message.length <= 512)
            assertTrue(snapshot.message.none(Char::isISOControl))
            if (snapshot.stale) assertEquals(VpnSessionStatus.STATE_STOPPED, snapshot.state)
        }
    }
}
