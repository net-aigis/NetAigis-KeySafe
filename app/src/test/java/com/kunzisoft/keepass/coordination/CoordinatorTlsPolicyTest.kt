/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.net.HttpURLConnection
import java.net.URL
import org.junit.Assert.assertTrue
import org.junit.Test

class CoordinatorTlsPolicyTest {
    @Test
    fun `leaves cleartext connections untouched`() {
        val connection = URL("http://127.0.0.1:9/").openConnection() as HttpURLConnection
        try {
            CoordinatorTlsPolicy.apply(connection)
            assertTrue(connection !is javax.net.ssl.HttpsURLConnection)
        } finally {
            connection.disconnect()
        }
    }

    @Test
    fun `applies TLS factory to https connections without connecting`() {
        val connection = URL("https://example.org/").openConnection() as HttpURLConnection
        try {
            CoordinatorTlsPolicy.apply(connection)
            val https = connection as javax.net.ssl.HttpsURLConnection
            assertTrue(https.sslSocketFactory.javaClass.name.contains("Tls12Plus"))
        } finally {
            connection.disconnect()
        }
    }
}
