package org.privacage.security

/** Requests cooperative cancellation for sensitive work owned by an Activity. */
internal object PwnedPasswordCheckLifecycle {
    fun requestCancellation(
        worker: Thread?,
        cancelProvider: () -> Unit = {}
    ): Boolean {
        if (worker?.isAlive != true) return false
        worker.interrupt()
        cancelProvider()
        return true
    }
}
