/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import org.joda.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

class KdbxGatedMergePublisherTest {
    private fun fixedTime() = DateInstant(Instant(1_700_000_000_000L))
    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    private fun db(): DatabaseKDBX {
        val rootId = UUID.randomUUID()
        val database = DatabaseKDBX()
        database.rootGroup = GroupKDBX().also {
            it.nodeId = NodeIdUUID(rootId)
            fixNodeTimes(it)
        }
        return database
    }

    private fun ciphertext(tag: Byte) = byteArrayOf(tag, tag, tag, tag)

    @Test
    fun `unauthorized report never invokes publish`() {
        val copy = db()
        val report = KdbxThreeCopyReview.read(
            copy, copy, copy,
            unknownExtensionsRefused = true
        )
        val published = AtomicBoolean(false)
        val result = KdbxGatedMergePublisher.attempt(
            KdbxGatedMergePublisher.Request(
                report = report,
                baseCiphertext = ciphertext(1),
                localCiphertext = ciphertext(2),
                remoteCiphertext = ciphertext(3),
                mergedCiphertext = ciphertext(4),
                expectedBaseRevision = "0",
                hasLiveLease = { true },
                leasedDownload = { null },
                publish = {
                    published.set(true)
                    fail("publish must not run while unauthorized")
                    "dead"
                }
            )
        )
        assertFalse(result.published)
        assertNull(result.confirmedRevision)
        assertFalse(published.get())
        assertTrue(result.blockers.any { it.contains("merge writer") })
    }

    @Test
    fun `missing originals are rejected before any network use`() {
        val copy = db()
        val report = KdbxThreeCopyReview.read(copy, copy, copy, unknownExtensionsRefused = true)
        try {
            KdbxGatedMergePublisher.attempt(
                KdbxGatedMergePublisher.Request(
                    report = report,
                    baseCiphertext = byteArrayOf(),
                    localCiphertext = ciphertext(2),
                    remoteCiphertext = ciphertext(3),
                    mergedCiphertext = ciphertext(4),
                    expectedBaseRevision = "0",
                    hasLiveLease = { fail("lease check must not run"); false },
                    leasedDownload = { fail("download must not run"); null },
                    publish = { fail("publish must not run"); "dead" }
                )
            )
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }
}
