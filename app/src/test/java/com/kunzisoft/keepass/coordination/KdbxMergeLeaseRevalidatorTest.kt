/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class KdbxMergeLeaseRevalidatorTest {
    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    @Test
    fun `missing lease fails closed`() {
        val outcome = KdbxMergeLeaseRevalidator.revalidate(
            expectedBaseRevision = "0",
            hasLiveLease = { false },
            leasedDownload = { null }
        )
        assertFalse(outcome.ok)
        assertTrue(outcome.reason!!.contains("lease"))
    }

    @Test
    fun `empty database revision validates when download is null`() {
        val outcome = KdbxMergeLeaseRevalidator.revalidate(
            expectedBaseRevision = "0",
            hasLiveLease = { true },
            leasedDownload = { null }
        )
        assertTrue(outcome.ok)
    }

    @Test
    fun `matching hash under live lease succeeds`() {
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        val outcome = KdbxMergeLeaseRevalidator.revalidate(
            expectedBaseRevision = sha256(payload),
            hasLiveLease = { true },
            leasedDownload = { payload }
        )
        assertTrue(outcome.ok)
    }

    @Test
    fun `stale server revision fails closed`() {
        val payload = byteArrayOf(9, 9, 9)
        val outcome = KdbxMergeLeaseRevalidator.revalidate(
            expectedBaseRevision = sha256(byteArrayOf(1)),
            hasLiveLease = { true },
            leasedDownload = { payload }
        )
        assertFalse(outcome.ok)
        assertEquals("server revision no longer matches the merge base", outcome.reason)
    }

    @Test
    fun `lease lost after download fails closed`() {
        var checks = 0
        val payload = byteArrayOf(7, 7)
        val outcome = KdbxMergeLeaseRevalidator.revalidate(
            expectedBaseRevision = sha256(payload),
            hasLiveLease = {
                checks += 1
                checks == 1 // true before download, false after
            },
            leasedDownload = { payload }
        )
        assertFalse(outcome.ok)
        assertTrue(outcome.reason!!.contains("lost"))
    }
}
