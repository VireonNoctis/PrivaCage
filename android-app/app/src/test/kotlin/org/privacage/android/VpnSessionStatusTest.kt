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
}
