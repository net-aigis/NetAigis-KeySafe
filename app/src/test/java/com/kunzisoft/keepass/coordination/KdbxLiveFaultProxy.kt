/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/**
 * Test-only fault proxy for live coordinator scenarios. Accepts bounded
 * HTTP/1.1 Content-Length requests from the local client only.
 */
internal class KdbxLiveFaultProxy(
    private val backend: String,
    private val interceptPut: (String, ByteArray) -> Mode
) : AutoCloseable {
    enum class Mode { NORMAL, REJECT_BEFORE_FORWARD, ACK_LOST }

    private val listener = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
    private val executor = Executors.newCachedThreadPool { task ->
        Thread(task, "keysafe-test-fault-proxy").apply { isDaemon = true }
    }
    val url: String get() = "http://127.0.0.1:${listener.localPort}"

    init {
        executor.execute {
            while (!listener.isClosed) {
                try {
                    val socket = listener.accept()
                    executor.execute {
                        socket.use { connection ->
                            try {
                                connection.soTimeout = 30_000
                                serve(connection)
                            } catch (_: IOException) {
                                // Closing the socket signals network failure to the client.
                            }
                        }
                    }
                } catch (_: SocketException) {
                    break
                } catch (_: IOException) {
                    if (listener.isClosed) break
                }
            }
        }
    }

    private fun line(input: BufferedInputStream): String {
        val output = ByteArrayOutputStream()
        while (true) {
            val next = input.read()
            if (next == -1) throw IOException("Unexpected end of test HTTP headers")
            if (next == 10) break
            if (next != 13) output.write(next)
            if (output.size() > 8192) throw IOException("Test HTTP header too long")
        }
        return output.toString(StandardCharsets.US_ASCII.name())
    }

    private fun requestBody(input: BufferedInputStream, length: Int): ByteArray {
        if (length !in 0..(1024 * 1024)) throw IOException("Oversized test HTTP request")
        val result = ByteArray(length)
        var received = 0
        while (received < length) {
            val n = input.read(result, received, length - received)
            if (n < 0) throw IOException("Truncated test HTTP request")
            received += n
        }
        return result
    }

    private fun respond(socket: Socket, code: Int, body: ByteArray, etag: String?) {
        val headers = buildString {
            append("HTTP/1.1 $code Test\r\n")
            append("Content-Length: ${body.size}\r\n")
            append("Connection: close\r\n")
            if (etag != null) append("ETag: $etag\r\n")
            append("\r\n")
        }
        socket.getOutputStream().apply {
            write(headers.toByteArray(StandardCharsets.US_ASCII))
            write(body)
            flush()
        }
    }

    private fun serve(socket: Socket) {
        val input = BufferedInputStream(socket.getInputStream())
        val request = line(input).split(' ')
        if (request.size != 3 || request[2] != "HTTP/1.1") {
            throw IOException("Unexpected test HTTP request")
        }
        val method = request[0]
        val path = request[1]
        if (!path.startsWith("/v1/databases/")) throw IOException("Unexpected test URL")
        val headers = mutableMapOf<String, String>()
        var headerCount = 0
        while (true) {
            val header = line(input)
            if (header.isEmpty()) break
            if (++headerCount > 64) throw IOException("Too many test HTTP headers")
            val colon = header.indexOf(':')
            if (colon <= 0) throw IOException("Malformed test HTTP header")
            headers[header.substring(0, colon).lowercase()] = header.substring(colon + 1).trim()
        }
        val length = headers["content-length"]?.toIntOrNull() ?: 0
        val body = requestBody(input, length)
        val mode = if (method == "PUT") interceptPut(path, body) else Mode.NORMAL
        if (mode == Mode.REJECT_BEFORE_FORWARD) {
            respond(socket, 503, byteArrayOf(), null)
            return
        }

        val connection = URI(backend + path).toURL().openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 30_000
            connection.requestMethod = method
            for (key in listOf("Authorization", "X-KDBX-Lease", "If-Match", "Content-Type")) {
                headers[key.lowercase()]?.let { connection.setRequestProperty(key, it) }
            }
            if (method == "PUT" || method == "POST") {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val reply = (if (status in 200..299) connection.inputStream else connection.errorStream)
                ?.use { it.readBytes() } ?: byteArrayOf()
            if (mode == Mode.ACK_LOST) {
                check(status == 200) { "Backend did not commit before simulated lost acknowledgement" }
                return
            }
            respond(socket, status, reply, connection.getHeaderField("ETag"))
        } finally {
            connection.disconnect()
        }
    }

    override fun close() {
        listener.close()
        executor.shutdownNow()
    }
}
