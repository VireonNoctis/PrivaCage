package org.privacage.security

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PwnedPasswordCheckLifecycleTest {
    @Test
    fun doesNotReportCancellationWhenThereIsNoLiveWorker() {
        assertFalse(PwnedPasswordCheckLifecycle.requestCancellation(null))

        val finished = Thread {}
        finished.start()
        finished.join(5_000)
        assertFalse(finished.isAlive)
        assertFalse(PwnedPasswordCheckLifecycle.requestCancellation(finished))
    }

    @Test
    fun interruptsALiveWorkerAndReportsTheRequest() {
        val started = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val worker = Thread {
            started.countDown()
            try {
                CountDownLatch(1).await()
            } catch (_: InterruptedException) {
                interrupted.countDown()
            }
        }.apply { isDaemon = true }

        worker.start()
        assertTrue(started.await(5, TimeUnit.SECONDS))
        assertTrue(PwnedPasswordCheckLifecycle.requestCancellation(worker))
        assertTrue(interrupted.await(5, TimeUnit.SECONDS))
        worker.join(5_000)
        assertFalse(worker.isAlive)
    }
}
