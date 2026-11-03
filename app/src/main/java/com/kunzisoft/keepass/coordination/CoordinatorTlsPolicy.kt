/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.IOException
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Restricts coordinator HTTPS to TLS 1.2+ with the platform trust store.
 * Cleartext loopback is never hardened here; [KdbxCoordinatorClient] already
 * refuses non-HTTPS endpoints outside explicit protocol tests.
 */
internal object CoordinatorTlsPolicy {
    private val ALLOWED_PROTOCOLS = arrayOf("TLSv1.2", "TLSv1.3")

    fun apply(connection: HttpURLConnection) {
        if (connection !is HttpsURLConnection) {
            return
        }
        connection.sslSocketFactory = Tls12PlusSocketFactory(connection.sslSocketFactory)
        connection.hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
    }

    private class Tls12PlusSocketFactory(
        private val delegate: SSLSocketFactory
    ) : SSLSocketFactory() {
        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(s: java.net.Socket, host: String, port: Int, autoClose: Boolean) =
            restrict(delegate.createSocket(s, host, port, autoClose))

        override fun createSocket(host: String, port: Int) =
            restrict(delegate.createSocket(host, port))

        override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int) =
            restrict(delegate.createSocket(host, port, localHost, localPort))

        override fun createSocket(address: java.net.InetAddress, port: Int) =
            restrict(delegate.createSocket(address, port))

        override fun createSocket(
            address: java.net.InetAddress,
            port: Int,
            localAddress: java.net.InetAddress,
            localPort: Int
        ) = restrict(delegate.createSocket(address, port, localAddress, localPort))

        private fun restrict(socket: java.net.Socket): java.net.Socket {
            val ssl = socket as? SSLSocket
                ?: throw IOException("Coordinator HTTPS socket is not an SSLSocket")
            val enabled = ssl.supportedProtocols.filter { it in ALLOWED_PROTOCOLS }
            if (enabled.isEmpty()) {
                throw IOException("TLS 1.2 or newer is required for the coordinator")
            }
            ssl.enabledProtocols = enabled.toTypedArray()
            return ssl
        }
    }
}
