/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.MasterCredential
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * Opens a KeePassXC-cli-created KDBX under StrictLoad (cross-client reopen).
 * Env: KEYSAFE_XC_CLI_KDBX (path), KEYSAFE_XC_CLI_PASSWORD. Skips if unset.
 * KeePassXC defaults to Argon2; JVM without libargon2 may fail closed — that is
 * a measured gap, not auto-publish authorization.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class KdbxCrossClientReopenIntegrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun opensXcCliCreatedKdbx() {
        val path = System.getenv("KEYSAFE_XC_CLI_KDBX")
        assumeTrue("KEYSAFE_XC_CLI_KDBX required", !path.isNullOrBlank())
        val password = System.getenv("KEYSAFE_XC_CLI_PASSWORD")
        assumeTrue("KEYSAFE_XC_CLI_PASSWORD required", !password.isNullOrBlank())
        val file = File(path!!)
        assumeTrue("XC KDBX must exist: $path", file.isFile && file.length() > 0)

        val ciphertext = file.readBytes()
        val opened = KdbxCoordinationStrictLoad.openEncrypted(
            encryptedKdbx = ciphertext,
            masterCredential = MasterCredential(password!!.toCharArray()),
            binaryCacheDirectory = tempFolder.newFolder("xc-cli-reopen"),
        )
        assertTrue(opened.database.rootGroup != null)
        val titles = mutableListOf<String>()
        opened.database.rootGroup?.getChildEntries()?.forEach { entry ->
            titles += entry.title
        }
        assertTrue(
            "expected CrossEntry among ${titles.joinToString()}",
            titles.any { it.contains("CrossEntry", ignoreCase = true) },
        )
    }
}
