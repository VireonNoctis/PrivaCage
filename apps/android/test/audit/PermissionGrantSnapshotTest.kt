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
    fun permissionChangesAreOrderedIndependentlyOfMapInsertionOrder() {
        val previous = PermissionGrantSnapshot(
            linkedMapOf(
                "com.zeta" to linkedMapOf("android.permission.MICROPHONE" to false),
                "com.alpha" to linkedMapOf("android.permission.CAMERA" to false)
            )
        )
        val current = PermissionGrantSnapshot(
            linkedMapOf(
                "com.alpha" to linkedMapOf("android.permission.CAMERA" to true),
                "com.zeta" to linkedMapOf("android.permission.MICROPHONE" to true)
            )
        )

        val first = current.compare(previous)
        val second = PermissionGrantSnapshot(current.packages.toSortedMap().mapValues { it.value.toSortedMap() })
            .compare(PermissionGrantSnapshot(previous.packages.toSortedMap().mapValues { it.value.toSortedMap() }))

        assertEquals(first, second)
        assertEquals(
            listOf("com.alpha", "com.zeta"),
            first.changes.map { it.packageName }
        )
    }

    @Test
    fun newlyObservedPackageDoesNotCreateInferredGrantChanges() {
        val previous = PermissionGrantSnapshot(
            mapOf("com.existing" to mapOf("android.permission.CAMERA" to false))
        )
        val current = PermissionGrantSnapshot(
            mapOf(
                "com.existing" to mapOf("android.permission.CAMERA" to false),
                "com.newly.installed" to mapOf("android.permission.RECORD_AUDIO" to true)
            )
        )

        val diff = current.compare(previous)

        assertTrue(diff.changes.isEmpty())
        assertEquals(setOf("com.newly.installed"), diff.newlyObservedPackages)
        assertTrue(diff.noLongerObservedPackages.isEmpty())
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
