package org.privacage.audit

/**
 * Local-only snapshot of dangerous permissions declared by packages PrivaCage could inspect.
 * A snapshot is an inventory, not evidence that a permission was used.
 */
data class PermissionGrantSnapshot(
    val packages: Map<String, Map<String, Boolean>>
) {
    fun compare(previous: PermissionGrantSnapshot): PermissionGrantDiff {
        val currentPackages = packages.keys
        val previousPackages = previous.packages.keys
        val observedTogether = currentPackages intersect previousPackages
        val changes = mutableListOf<PermissionGrantChange>()

        for (packageName in observedTogether.sorted()) {
            val current = packages[packageName].orEmpty()
            val old = previous.packages[packageName].orEmpty()
            for (permission in (current.keys + old.keys).toSortedSet()) {
                val hasCurrent = current.containsKey(permission)
                val hadPrevious = old.containsKey(permission)
                when {
                    hasCurrent && !hadPrevious -> changes += PermissionGrantChange(
                        packageName = packageName,
                        permissionName = permission,
                        kind = PermissionChangeKind.NEWLY_REQUESTED,
                        previouslyGranted = null,
                        currentlyGranted = current[permission]
                    )
                    !hasCurrent && hadPrevious -> changes += PermissionGrantChange(
                        packageName = packageName,
                        permissionName = permission,
                        kind = PermissionChangeKind.NO_LONGER_REQUESTED,
                        previouslyGranted = old[permission],
                        currentlyGranted = null
                    )
                    hasCurrent && hadPrevious && old[permission] == false && current[permission] == true ->
                        changes += PermissionGrantChange(
                            packageName = packageName,
                            permissionName = permission,
                            kind = PermissionChangeKind.NEWLY_GRANTED,
                            previouslyGranted = false,
                            currentlyGranted = true
                        )
                    hasCurrent && hadPrevious && old[permission] == true && current[permission] == false ->
                        changes += PermissionGrantChange(
                            packageName = packageName,
                            permissionName = permission,
                            kind = PermissionChangeKind.GRANT_REVOKED,
                            previouslyGranted = true,
                            currentlyGranted = false
                        )
                }
            }
        }
        return PermissionGrantDiff(
            changes = changes,
            newlyObservedPackages = (currentPackages - previousPackages).toSortedSet(),
            noLongerObservedPackages = (previousPackages - currentPackages).toSortedSet()
        )
    }
}

enum class PermissionChangeKind {
    NEWLY_REQUESTED,
    NO_LONGER_REQUESTED,
    NEWLY_GRANTED,
    GRANT_REVOKED
}

data class PermissionGrantChange(
    val packageName: String,
    val permissionName: String,
    val kind: PermissionChangeKind,
    val previouslyGranted: Boolean?,
    val currentlyGranted: Boolean?
)

data class PermissionGrantDiff(
    val changes: List<PermissionGrantChange>,
    val newlyObservedPackages: Set<String>,
    val noLongerObservedPackages: Set<String>
)
