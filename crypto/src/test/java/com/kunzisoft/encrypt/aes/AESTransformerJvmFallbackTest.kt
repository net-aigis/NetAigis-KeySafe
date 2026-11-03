/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.encrypt.aes

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.util.Random

/** Ensures AES-KDF works when native libaes is unavailable (JVM unit tests). */
class AESTransformerJvmFallbackTest {
    @Test
    fun `transformKey falls back to JVM when native libraries are absent`() {
        val rand = Random(42)
        val seed = ByteArray(32).also { rand.nextBytes(it) }
        val key = ByteArray(32).also { rand.nextBytes(it) }
        val rounds = 16uL
        val viaPublic = AESTransformer.transformKey(seed, key, rounds)
        val viaJvm = AESTransformer.transformKeyInJVM(seed, key, rounds)
        assertNotNull(viaPublic)
        assertArrayEquals(viaJvm, viaPublic)
    }
}
