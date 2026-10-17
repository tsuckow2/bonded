package com.bonded.bonded_app

import android.content.Context
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.math.max
import kotlin.math.min
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo

data class ProtocolStressConfig(
        val dnsHost: String,
        val dnsResolver: String,
        val httpUrl: String,
        val httpsUrl: String,
        val http3Url: String,
        val rounds: Int,
)

object ProtocolStressTester {
    private const val dnsPort = 53
    private const val dnsTimeoutMs = 10000
    private const val httpTimeoutMs = 10000
    private const val http3TimeoutMs = 15000L
    private val secureRandom = SecureRandom()

    fun run(
            context: Context,
            config: ProtocolStressConfig,
            logI: (String) -> Unit,
            logD: (String) -> Unit,
            logW: (String) -> Unit,
            logE: (String, Throwable?) -> Unit,
    ) {
        val rounds = config.rounds.coerceIn(1, 25)
        val engineBuilder =
                CronetEngine.Builder(context.applicationContext)
                        .enableHttp2(true)
                        .enableQuic(true)
                        .enableBrotli(true)
        // Without a QUIC hint, a cold Cronet engine can only learn that
        // the host supports QUIC from an Alt-Svc advertisement on a
        // first HTTP/2 response — so the first rounds of every run fell
        // back to h2 and failed the protocol check even though the
        // fetch itself succeeded (the "unreliable" early-round http3
        // failures; the engine is rebuilt per run, so the penalty was
        // paid on every invocation). The hint makes QUIC eligible from
        // the very first request.
        val http3Target = try {
            URL(config.http3Url)
        } catch (_: Exception) {
            null
        }
        if (http3Target != null && http3Target.protocol.equals("https", ignoreCase = true)) {
            val port = if (http3Target.port >= 0) http3Target.port else 443
            engineBuilder.addQuicHint(http3Target.host, port, port)
        }
        val engine = engineBuilder.build()
        val executor = Executors.newFixedThreadPool(min(8, max(4, rounds * 2)))
        val successCounts =
                linkedMapOf(
                        "edns_udp" to AtomicInteger(0),
                        "http" to AtomicInteger(0),
                        "https" to AtomicInteger(0),
                        "http3" to AtomicInteger(0),
                )
        val failureCounts =
                linkedMapOf(
                        "edns_udp" to AtomicInteger(0),
                        "http" to AtomicInteger(0),
                        "https" to AtomicInteger(0),
                        "http3" to AtomicInteger(0),
                )

        try {
            logI(
                    "Starting protocol stress test: rounds=$rounds dnsHost=${config.dnsHost} resolver=${config.dnsResolver} http=${config.httpUrl} https=${config.httpsUrl} http3=${config.http3Url}"
            )
            // Unscored warm-up: lets the engine finish QUIC discovery
            // (Alt-Svc / session state) before the scored rounds, so
            // they measure steady-state HTTP/3 transport rather than
            // cold-start protocol fallback. A warm-up failure does not
            // fail the run — the scored rounds still execute.
            try {
                val warmupDetail = runHttp3Query(engine, config.http3Url, requireHttp3 = false)
                logI("HTTP/3 warm-up completed | $warmupDetail")
            } catch (e: Exception) {
                logW("HTTP/3 warm-up failed; scored rounds will still run: ${e.message}")
            }
            repeat(rounds) { index ->
                val round = index + 1
                val roundStart = System.currentTimeMillis()
                val startGate = CountDownLatch(1)
                val doneGate = CountDownLatch(4)

                val tasks =
                        listOf(
                                "edns_udp" to { runEdnsQuery(config.dnsHost, config.dnsResolver) },
                                "http" to { runHttpQuery(config.httpUrl, requireHttps = false) },
                                "https" to { runHttpQuery(config.httpsUrl, requireHttps = true) },
                                "http3" to { runHttp3Query(engine, config.http3Url) },
                        )

                tasks.forEach { (name, task) ->
                    executor.execute {
                        try {
                            startGate.await(2, TimeUnit.SECONDS)
                            val taskStart = System.currentTimeMillis()
                            val detail = task.invoke()
                            val elapsed = System.currentTimeMillis() - taskStart
                            successCounts.getValue(name).incrementAndGet()
                            logI("[round $round/$rounds] $name success in ${elapsed}ms | $detail")
                        } catch (e: Exception) {
                            failureCounts.getValue(name).incrementAndGet()
                            logE("[round $round/$rounds] $name failed", e)
                        } finally {
                            doneGate.countDown()
                        }
                    }
                }

                logD("Dispatching simultaneous round $round/$rounds")
                startGate.countDown()

                val completed = doneGate.await(http3TimeoutMs + 5000L, TimeUnit.MILLISECONDS)
                val roundElapsed = System.currentTimeMillis() - roundStart
                if (!completed) {
                    logW("Round $round/$rounds timed out after ${roundElapsed}ms")
                } else {
                    logI("Completed round $round/$rounds in ${roundElapsed}ms")
                }
            }

            val summary = buildString {
                append("Protocol stress summary")
                successCounts.forEach { (name, success) ->
                    append(" | ")
                    append(name)
                    append(": ")
                    append(success.get())
                    append(" ok / ")
                    append(failureCounts.getValue(name).get())
                    append(" failed")
                }
            }
            logI(summary)
        } finally {
            executor.shutdownNow()
            try {
                engine.shutdown()
            } catch (_: Exception) {}
        }
    }

    private fun runEdnsQuery(host: String, resolverIp: String): String {
        val transactionId = secureRandom.nextInt(0x10000)
        val query = buildEdnsQuery(host, transactionId)
        val responseBuffer = ByteArray(2048)
        val resolver = InetAddress.getByName(resolverIp)

        DatagramSocket().use { socket ->
            socket.soTimeout = dnsTimeoutMs
            socket.connect(resolver, dnsPort)

            val startMs = System.currentTimeMillis()
            socket.send(DatagramPacket(query, query.size))
            val response = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(response)
            val elapsedMs = System.currentTimeMillis() - startMs

            val parsed = parseDnsResponse(response.data, response.length, transactionId)
            if (!parsed.ednsPresent) {
                throw IllegalStateException("resolver response did not include an OPT record")
            }

            return "resolver=$resolverIp host=$host rcode=${parsed.responseCode} answers=${parsed.answerCount} additional=${parsed.additionalCount} bytes=${response.length} in ${elapsedMs}ms"
        }
    }

    private fun runHttpQuery(urlString: String, requireHttps: Boolean): String {
        val url = URL(urlString)
        val connection =
                (url.openConnection() as? HttpURLConnection)
                        ?: throw IllegalStateException(
                                "URL did not produce an HttpURLConnection: $urlString"
                        )

        connection.instanceFollowRedirects = true
        connection.connectTimeout = httpTimeoutMs
        connection.readTimeout = httpTimeoutMs
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "BondedStress/1.0")

        if (requireHttps && connection !is HttpsURLConnection) {
            connection.disconnect()
            throw IllegalArgumentException("Expected an HTTPS URL for $urlString")
        }

        return try {
            val startMs = System.currentTimeMillis()
            val responseCode = connection.responseCode
            val elapsedMs = System.currentTimeMillis() - startMs
            val bodyBytes = drainStream(connection)
            val scheme = if (connection is HttpsURLConnection) "https" else "http"
            "scheme=$scheme status=$responseCode bytes=$bodyBytes in ${elapsedMs}ms"
        } finally {
            connection.disconnect()
        }
    }

    private fun runHttp3Query(
            engine: CronetEngine,
            urlString: String,
            requireHttp3: Boolean = true,
    ): String {
        val completed = CountDownLatch(1)
        val protocolRef = AtomicReference<String>()
        val statusRef = AtomicReference<Int>()
        val errorRef = AtomicReference<Throwable?>()
        val bodyBytes = AtomicInteger(0)
        val callbackExecutor = Executors.newSingleThreadExecutor()

        val callback =
                object : UrlRequest.Callback() {
                    override fun onRedirectReceived(
                            request: UrlRequest,
                            info: UrlResponseInfo,
                            newLocationUrl: String,
                    ) {
                        request.followRedirect()
                    }

                    override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                        statusRef.set(info.httpStatusCode)
                        protocolRef.set(info.negotiatedProtocol)
                        request.read(ByteBuffer.allocateDirect(16 * 1024))
                    }

                    override fun onReadCompleted(
                            request: UrlRequest,
                            info: UrlResponseInfo,
                            byteBuffer: ByteBuffer,
                    ) {
                        byteBuffer.flip()
                        bodyBytes.addAndGet(byteBuffer.remaining())
                        byteBuffer.clear()
                        request.read(byteBuffer)
                    }

                    override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                        statusRef.set(info.httpStatusCode)
                        protocolRef.set(info.negotiatedProtocol)
                        completed.countDown()
                    }

                    override fun onFailed(
                            request: UrlRequest,
                            info: UrlResponseInfo?,
                            error: CronetException,
                    ) {
                        errorRef.set(error)
                        completed.countDown()
                    }
                }

        try {
            val request =
                    engine.newUrlRequestBuilder(urlString, callback, callbackExecutor)
                            .setHttpMethod("GET")
                            .addHeader("User-Agent", "BondedStress/1.0")
                            .addHeader("Accept", "*/*")
                            .build()

            val startMs = System.currentTimeMillis()
            request.start()

            if (!completed.await(http3TimeoutMs, TimeUnit.MILLISECONDS)) {
                request.cancel()
                throw SocketTimeoutException("HTTP/3 request timed out for $urlString")
            }

            errorRef.get()?.let { throw it }

            val elapsedMs = System.currentTimeMillis() - startMs
            val protocol = protocolRef.get().orEmpty()
            if (requireHttp3 &&
                            !protocol.contains("h3", ignoreCase = true) &&
                            !protocol.contains("quic", ignoreCase = true)
            ) {
                throw IllegalStateException(
                        "Request completed without HTTP/3 or QUIC negotiation (protocol='$protocol')"
                )
            }

            return "status=${statusRef.get() ?: 0} protocol=$protocol bytes=${bodyBytes.get()} in ${elapsedMs}ms"
        } finally {
            callbackExecutor.shutdownNow()
        }
    }

    private fun drainStream(connection: HttpURLConnection): Int {
        val stream =
                try {
                    connection.inputStream
                } catch (_: Exception) {
                    connection.errorStream
                }

        if (stream == null) {
            return 0
        }

        stream.use { input ->
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) {
                    return total
                }
                total += read
            }
        }
    }

    private fun buildEdnsQuery(host: String, transactionId: Int): ByteArray {
        val output = ByteArrayOutputStream()
        writeShort(output, transactionId)
        writeShort(output, 0x0100)
        writeShort(output, 1)
        writeShort(output, 0)
        writeShort(output, 0)
        writeShort(output, 1)

        host.split('.').filter { it.isNotBlank() }.forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output.write(bytes.size)
            output.write(bytes)
        }
        output.write(0)

        writeShort(output, 1)
        writeShort(output, 1)

        output.write(0)
        writeShort(output, 41)
        writeShort(output, 1232)
        output.write(0)
        output.write(0)
        writeShort(output, 0x8000)

        val options = ByteArrayOutputStream()
        writeShort(options, 3)
        writeShort(options, 0)
        writeShort(options, 10)
        writeShort(options, 8)
        val cookie = ByteArray(8)
        secureRandom.nextBytes(cookie)
        options.write(cookie)
        writeShort(options, 12)
        writeShort(options, 8)
        options.write(ByteArray(8))

        val optionBytes = options.toByteArray()
        writeShort(output, optionBytes.size)
        output.write(optionBytes)
        return output.toByteArray()
    }

    private fun parseDnsResponse(data: ByteArray, length: Int, expectedId: Int): DnsResponseInfo {
        if (length < 12) {
            throw IllegalArgumentException("DNS response too short: $length")
        }

        val id = readUnsignedShort(data, 0)
        if (id != expectedId) {
            throw IllegalStateException("DNS transaction mismatch: expected=$expectedId actual=$id")
        }

        val flags = readUnsignedShort(data, 2)
        val questionCount = readUnsignedShort(data, 4)
        val answerCount = readUnsignedShort(data, 6)
        val authorityCount = readUnsignedShort(data, 8)
        val additionalCount = readUnsignedShort(data, 10)
        var offset = 12

        repeat(questionCount) {
            offset = skipDnsName(data, length, offset)
            if (offset + 4 > length) {
                throw IllegalArgumentException("DNS question truncated")
            }
            offset += 4
        }

        repeat(answerCount + authorityCount) {
            offset = skipResourceRecord(data, length, offset).nextOffset
        }

        var ednsPresent = false
        repeat(additionalCount) {
            val record = skipResourceRecord(data, length, offset)
            if (record.type == 41) {
                ednsPresent = true
            }
            offset = record.nextOffset
        }

        return DnsResponseInfo(
                responseCode = flags and 0x000F,
                answerCount = answerCount,
                additionalCount = additionalCount,
                ednsPresent = ednsPresent,
        )
    }

    private fun skipResourceRecord(data: ByteArray, length: Int, offset: Int): ParsedRecord {
        var cursor = skipDnsName(data, length, offset)
        if (cursor + 10 > length) {
            throw IllegalArgumentException("DNS resource record truncated")
        }

        val type = readUnsignedShort(data, cursor)
        val rdLength = readUnsignedShort(data, cursor + 8)
        cursor += 10
        if (cursor + rdLength > length) {
            throw IllegalArgumentException("DNS resource data truncated")
        }
        return ParsedRecord(type = type, nextOffset = cursor + rdLength)
    }

    private fun skipDnsName(data: ByteArray, length: Int, offset: Int): Int {
        var cursor = offset
        while (cursor < length) {
            val value = data[cursor].toInt() and 0xFF
            if (value == 0) {
                return cursor + 1
            }
            if ((value and 0xC0) == 0xC0) {
                if (cursor + 1 >= length) {
                    throw IllegalArgumentException("DNS compression pointer truncated")
                }
                return cursor + 2
            }
            cursor += value + 1
        }
        throw IllegalArgumentException("DNS name exceeded packet bounds")
    }

    private fun writeShort(output: ByteArrayOutputStream, value: Int) {
        output.write((value ushr 8) and 0xFF)
        output.write(value and 0xFF)
    }

    private fun readUnsignedShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }
}

private data class DnsResponseInfo(
        val responseCode: Int,
        val answerCount: Int,
        val additionalCount: Int,
        val ednsPresent: Boolean,
)

private data class ParsedRecord(
        val type: Int,
        val nextOffset: Int,
)
