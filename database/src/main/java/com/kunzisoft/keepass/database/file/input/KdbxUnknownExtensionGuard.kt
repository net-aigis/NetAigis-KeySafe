/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.database.file.input

import com.kunzisoft.keepass.database.exception.DatabaseInputException
import com.kunzisoft.keepass.database.file.DatabaseHeaderKDBX

/**
 * Fail-closed decisions for KDBX extensions the shared parser does not model.
 * Used only when [refuseUnknownExtensions] is enabled (coordination inventory /
 * merge candidates). Everyday UI loads stay permissive.
 */
internal object KdbxUnknownExtensionGuard {
    fun refuseUnknownXmlElement(elementName: String, refuseUnknownExtensions: Boolean) {
        if (!refuseUnknownExtensions) return
        val name = elementName.ifBlank { "<unnamed>" }
        throw DatabaseInputException("Unknown KDBX XML element: $name")
    }

    fun refuseUnknownInnerHeaderField(fieldId: Byte, refuseUnknownExtensions: Boolean) {
        if (!refuseUnknownExtensions) return
        when (fieldId) {
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.EndOfHeader,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.InnerRandomStreamID,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.InnerRandomstreamKey,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.Binary -> return
            else -> throw DatabaseInputException(
                "Unknown KDBX inner-header field ID: ${fieldId.toInt() and 0xff}"
            )
        }
    }

    fun isKnownInnerHeaderField(fieldId: Byte): Boolean =
        when (fieldId) {
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.EndOfHeader,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.InnerRandomStreamID,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.InnerRandomstreamKey,
            DatabaseHeaderKDBX.PwDbInnerHeaderV4Fields.Binary -> true
            else -> false
        }
}
