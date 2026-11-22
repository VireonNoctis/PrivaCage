package org.privacage.security

/** Requests cooperative cancellation for sensitive work owned by an Activity. */
internal object PwnedPasswordCheckLifecycle {
    fun requestCancellation(worker: Thread?): Boolean {
        if (worker?.isAlive != true) return false
        worker.interrupt()
        return true
    }
}
