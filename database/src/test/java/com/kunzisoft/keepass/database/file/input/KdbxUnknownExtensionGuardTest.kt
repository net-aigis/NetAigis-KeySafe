/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.database.file.input

import com.kunzisoft.keepass.database.exception.DatabaseInputException
import com.kunzisoft.keepass.database.file.DatabaseHeaderKDBX
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class KdbxUnknownExtensionGuardTest {
    @Test
    fun `permissive mode keeps unknown XML`() {
        KdbxUnknownExtensionGuard.refuseUnknownXmlElement("Evil", refuseUnknownExtensions = false)
    }

    @Test
    fun `strict mode refuses unknown XML`() {
        try {
            KdbxUnknownExtensionGuard.refuseUnknownXmlElement("Evil", refuseUnknownExtensions = true)
            fail("expected DatabaseInputException")
        } catch (expected: DatabaseInputException) {
            assertTrue(expected.message!!.contains("Evil"))
        }
    }

    @Test
    fun `permissive mode keeps unknown inner-header IDs`() {
        KdbxUnknownExtensionGuard.refuseUnknownInnerHeaderField(0x4A, refuseUnknownExtensions = false)
    }

    @Test
    fun `strict mode refuses unknown inner-header IDs`() {
        try {
            KdbxUnknownExtensionGuard.refuseUnknownInnerHeaderField(0x4A, refuseUnknownExtensions = true)
            fail("expected DatabaseInputException")
        } catch (expected: DatabaseInputException) {
            assertTrue(expected.message!!.contains("74") || expected.message!!.contains("0x4a") ||
                expected.message!!.contains("inner-header"))
        }
    }

    @Test
    fun `known inner-header IDs remain accepted under strict mode`() {
        for (id in listOf(
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.EndOfHeader,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.InnerRandomStreamID,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.InnerRandomstreamKey,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.Binary
        )) {
            assertTrue(KdbxUnknownExtensionGuard.isKnownInnerHeaderField(id))
            KdbxUnknownExtensionGuard.refuseUnknownInnerHeaderField(id, refuseUnknownExtensions = true)
        }
        assertFalse(KdbxUnknownExtensionGuard.isKnownInnerHeaderField(0x4A))
    }
}
