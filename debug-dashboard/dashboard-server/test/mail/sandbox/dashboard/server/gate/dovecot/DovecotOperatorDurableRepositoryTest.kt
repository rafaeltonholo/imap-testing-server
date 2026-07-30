package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.ReadableByteChannel
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotOperatorDurableRepositoryTest {
    @Test
    fun trailingGrowthReadWipesItsNamedOneByteBackingArray() {
        var growthProbeBacking: ByteArray? = null
        val channel = object : ReadableByteChannel {
            private var open = true

            override fun read(destination: ByteBuffer): Int {
                growthProbeBacking = destination.array()
                destination.put(0x5a.toByte())
                return 1
            }

            override fun isOpen(): Boolean = open

            override fun close() {
                open = false
            }
        }

        assertEquals(
            1,
            readDovecotOperatorTrailingGrowthByte(channel),
        )

        assertTrue(
            requireNotNull(growthProbeBacking)
                .all { byte -> byte == 0.toByte() },
        )
    }

    @Test
    fun failedTrailingGrowthReadWipesItsNamedOneByteBackingArray() {
        val expected = IOException("Synthetic trailing-growth read failure")
        var growthProbeBacking: ByteArray? = null
        val channel = object : ReadableByteChannel {
            override fun read(destination: ByteBuffer): Int {
                growthProbeBacking = destination.array()
                destination.put(0x5a.toByte())
                throw expected
            }

            override fun isOpen(): Boolean = true

            override fun close() = Unit
        }

        val caught = assertFailsWith<IOException> {
            readDovecotOperatorTrailingGrowthByte(channel)
        }

        assertSame(expected, caught)
        assertTrue(
            requireNotNull(growthProbeBacking)
                .all { byte -> byte == 0.toByte() },
        )
    }

    @Test
    fun processLockRegistrySerializesWaitersAndEvictsTheIdleKey() {
        val registry = DovecotOperatorProcessLockRegistry()
        val lockPath = Path.of("/unused/dovecot-operator.lock")
        val firstEntered = CountDownLatch(1)
        val firstRelease = CountDownLatch(1)
        val secondStarted = CountDownLatch(1)
        val secondEntered = CountDownLatch(1)
        val first = thread(isDaemon = true, name = "process-lock-first") {
            registry.withLock(lockPath) {
                firstEntered.countDown()
                firstRelease.await()
            }
        }
        assertTrue(firstEntered.await(1, TimeUnit.SECONDS))
        val second = thread(isDaemon = true, name = "process-lock-second") {
            secondStarted.countDown()
            registry.withLock(lockPath) {
                secondEntered.countDown()
            }
        }
        assertTrue(secondStarted.await(1, TimeUnit.SECONDS))
        assertTrue(
            awaitCondition {
                registry.referenceCount(lockPath) == 2
            },
        )

        assertFalse(secondEntered.await(100, TimeUnit.MILLISECONDS))
        firstRelease.countDown()
        first.join(1_000)
        second.join(1_000)

        assertFalse(first.isAlive)
        assertFalse(second.isAlive)
        assertEquals(0, registry.referenceCount(lockPath))
        assertEquals(0, registry.retainedLockCount())
    }

    private fun awaitCondition(condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.yield()
        }
        return condition()
    }
}
