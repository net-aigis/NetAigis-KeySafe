/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Load policy for any KDBX copy that may enter three-copy review or a later
 * gated merge writer. Everyday UI password-entry opens must NOT use this flag.
 */
internal object KdbxCoordinationLoadPolicy {
    /** Required for coordination inventory / merge-candidate loads. */
    const val REFUSE_UNKNOWN_EXTENSIONS: Boolean = true
}
