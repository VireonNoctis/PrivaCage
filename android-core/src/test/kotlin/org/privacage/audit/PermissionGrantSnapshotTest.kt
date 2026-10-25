package org.privacage.audit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PermissionGrantSnapshotTest {
    @Test
    fun detectsNewlyGrantedAndRevokedPermissions() {
        val previous = PermissionGrantSnapshot(
            mapOf("com.example" to mapOf(
                "android.permission.CAMERA" to false,
                "android.permission.RECORD_AUDIO" to true
            ))
        )
        val current = PermissionGrantSnapshot(
            mapOf("com.example" to mapOf(
                "android.permission.CAMERA" to true,
                "android.permission.RECORD_AUDIO" to false
            ))
        )

        val diff = current.compare(previous)
        assertEquals(
            listOf(
                PermissionChangeKind.NEWLY_GRANTED,
                PermissionChangeKind.GRANT_REVOKED
            ),
            diff.changes.map { it.kind }
        )
        assertTrue(diff.newlyObservedPackages.isEmpty())
        assertTrue(diff.noLongerObservedPackages.isEmpty())
    }

    @Test
    fun reportsRequestedPermissionSetChangesSeparatelyFromGrantChanges() {
        val previous = PermissionGrantSnapshot(
            mapOf("com.example" to mapOf("android.permission.CAMERA" to false))
        )
        val current = PermissionGrantSnapshot(
            mapOf("com.example" to mapOf("android.permission.CONTACTS" to false))
        )

        val diff = current.compare(previous)
        assertEquals(
            setOf(
                PermissionChangeKind.NEWLY_REQUESTED,
                PermissionChangeKind.NO_LONGER_REQUESTED
            ),
            diff.changes.map { it.kind }.toSet()
        )
    }

    @Test
    fun doesNotInferPermissionRevocationForPackagesNoLongerVisible() {
        val previous = PermissionGrantSnapshot(
            mapOf("com.removed" to mapOf("android.permission.CAMERA" to true))
        )
        val current = PermissionGrantSnapshot(emptyMap())

        val diff = current.compare(previous)
        assertTrue(diff.changes.isEmpty())
        assertEquals(setOf("com.removed"), diff.noLongerObservedPackages)
    }

    @Test
    fun unchangedInventoryProducesNoPermissionChanges() {
        val snapshot = PermissionGrantSnapshot(
            mapOf("com.example" to mapOf("android.permission.CAMERA" to true))
        )
        val diff = snapshot.compare(snapshot)
        assertTrue(diff.changes.isEmpty())
        assertTrue(diff.newlyObservedPackages.isEmpty())
        assertTrue(diff.noLongerObservedPackages.isEmpty())
    }
}
