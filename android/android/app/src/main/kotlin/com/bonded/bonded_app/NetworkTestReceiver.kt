package com.bonded.bonded_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import kotlin.concurrent.thread

/**
 * Broadcast receiver for network diagnostic tests.
 *
 * IMPORTANT: Before running any tests:
 * 1. Compile and reinstall the app: flutter build apk --debug && adb install -r
 * build/app/outputs/flutter-apk/app-debug.apk
 * 2. Open the app in the foreground via adb: adb shell am start -n
 * com.bonded.bonded_app/.MainActivity
 * 3. Check/set the VPN state before running tests:
 * ```
 *      - Check VPN status: adb shell am broadcast -a com.bonded.bonded_app.TEST_VPN_STATUS
 *      - To disconnect: adb shell am broadcast -a com.bonded.bonded_app.TEST_VPN_DISCONNECT
 *      - To connect: adb shell am broadcast -a com.bonded.bonded_app.TEST_VPN_CONNECT
 * ```
 * Usage: adb shell am broadcast -a com.bonded.bonded_app.TEST_VPN_PREPARED adb shell am broadcast
 * -a com.bonded.bonded_app.TEST_VPN_STATUS adb shell am broadcast -a
 * com.bonded.bonded_app.TEST_VPN_CONNECT adb shell am broadcast -a
 * com.bonded.bonded_app.TEST_VPN_DISCONNECT adb shell am broadcast -a
 * com.bonded.bonded_app.TEST_DNS -e host charter.codingwell.net -e expected_ip 97.115.185.254 adb
 * shell am broadcast -a com.bonded.bonded_app.TEST_TCP -e host example.com -e port 443 adb shell am
 * broadcast -a com.bonded.bonded_app.TEST_HTTP -e url https://example.com adb shell am broadcast -a
 * com.bonded.bonded_app.TEST_HTTP_CODINGWELL adb shell am broadcast -a
 * com.bonded.bonded_app.TEST_PROTOCOL_STRESS -e host cloudflare.com -e resolver 1.1.1.1 -e http_url
 * http://httpforever.com/ -e https_url https://example.com/ -e http3_url
 * https://cloudflare-quic.com/ -e rounds 5 adb shell am broadcast -a
 * com.bonded.bonded_app.TEST_UDP_PROBE -e host charter.codingwell.net -e port 443
 */
class NetworkTestReceiver : BroadcastReceiver() {
    companion object {
        private const val DEFAULT_DNS_HOST = "charter.codingwell.net"
        private const val DEFAULT_DNS_EXPECTED_IP = "97.115.185.254"
        private const val MAX_LOG_LINES = 300
        private val logBuffer = ArrayDeque<String>()

        @Synchronized fun getBufferedLogs(): List<String> = logBuffer.toList()

        @Synchronized
        fun clearBufferedLogs() {
            logBuffer.clear()
        }

        @Synchronized
        fun appendServiceLog(level: String, message: String) {
            appendBufferedLog(level, message)
        }

        @Synchronized
        private fun appendBufferedLog(level: String, message: String) {
            val timestamp = System.currentTimeMillis()
            logBuffer.addLast("$timestamp [$level] $message")
            while (logBuffer.size > MAX_LOG_LINES) {
                logBuffer.removeFirst()
            }
        }
    }

    private fun logI(message: String) {
        android.util.Log.i("NetworkTest", message)
        appendBufferedLog("I", message)
    }

    private fun logD(message: String) {
        android.util.Log.d("NetworkTest", message)
        appendBufferedLog("D", message)
    }

    private fun logW(message: String) {
        android.util.Log.w("NetworkTest", message)
        appendBufferedLog("W", message)
    }

    private fun logE(message: String, error: Throwable? = null) {
        if (error != null) {
            android.util.Log.e("NetworkTest", message, error)
        } else {
            android.util.Log.e("NetworkTest", message)
        }
        appendBufferedLog(
                "E",
                if (error == null) message
                else "$message | ${error::class.java.simpleName}: ${error.message}"
        )
    }

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null) return

        logI("=== Test Action: ${intent.action} ===")

        val action = intent.action
        val isAsyncAction =
                action == "com.bonded.bonded_app.TEST_DNS" ||
                        action == "com.bonded.bonded_app.TEST_TCP" ||
                        action == "com.bonded.bonded_app.TEST_HTTP" ||
                        action == "com.bonded.bonded_app.TEST_HTTP_CODINGWELL" ||
                        action == "com.bonded.bonded_app.TEST_PROTOCOL_STRESS" ||
                        action == "com.bonded.bonded_app.TEST_UDP_PROBE" ||
                        action == "com.bonded.bonded_app.TEST_ALL"

        if (isAsyncAction) {
            val pendingResult = goAsync()
            thread {
                try {
                    when (action) {
                        "com.bonded.bonded_app.TEST_DNS" -> {
                            val host = intent.getStringExtra("host") ?: DEFAULT_DNS_HOST
                            val expectedIp =
                                    intent.getStringExtra("expected_ip")
                                            ?: if (host == DEFAULT_DNS_HOST) DEFAULT_DNS_EXPECTED_IP
                                            else null
                            testDnsResolution(host, expectedIp).join()
                        }
                        "com.bonded.bonded_app.TEST_TCP" -> {
                            val host = intent.getStringExtra("host") ?: "example.com"
                            val port = intent.getIntExtra("port", 443)
                            testTcpConnection(host, port).join()
                        }
                        "com.bonded.bonded_app.TEST_HTTP" -> {
                            val url = intent.getStringExtra("url") ?: "https://example.com"
                            testHttpConnection(url).join()
                        }
                        "com.bonded.bonded_app.TEST_HTTP_CODINGWELL" -> {
                            testCodingwellConnection().join()
                        }
                        "com.bonded.bonded_app.TEST_PROTOCOL_STRESS" -> {
                            ProtocolStressTester.run(
                                    context = context,
                                    config =
                                            ProtocolStressConfig(
                                                    dnsHost = intent.getStringExtra("host")
                                                                    ?: "cloudflare.com",
                                                    dnsResolver = intent.getStringExtra("resolver")
                                                                    ?: "1.1.1.1",
                                                    httpUrl = intent.getStringExtra("http_url")
                                                                    ?: "http://httpforever.com/",
                                                    httpsUrl = intent.getStringExtra("https_url")
                                                                    ?: "https://example.com/",
                                                    http3Url = intent.getStringExtra("http3_url")
                                                                    ?: "https://cloudflare-quic.com/",
                                                    rounds = intent.getIntExtra("rounds", 5),
                                            ),
                                    logI = ::logI,
                                    logD = ::logD,
                                    logW = ::logW,
                                    logE = ::logE,
                            )
                        }
                        "com.bonded.bonded_app.TEST_UDP_PROBE" -> {
                            UdpProbeTester.run(
                                    host = intent.getStringExtra("host")
                                                    ?: "charter.codingwell.net",
                                    port = intent.getIntExtra("port", 443),
                                    logI = ::logI,
                                    logW = ::logW,
                                    logE = ::logE,
                            )
                        }
                        "com.bonded.bonded_app.TEST_ALL" -> {
                            testVpnStatus()
                            val dnsThread =
                                    testDnsResolution(DEFAULT_DNS_HOST, DEFAULT_DNS_EXPECTED_IP)
                            val loopbackTcpThread = testLoopbackTcpConnection()
                            val loopbackHttpThread = testLoopbackHttpConnection()
                            dnsThread.join()
                            loopbackTcpThread.join()
                            loopbackHttpThread.join()
                        }
                    }
                } finally {
                    logI("=== Test Complete ===")
                    pendingResult.finish()
                }
            }
            return
        }

        when (action) {
            "com.bonded.bonded_app.TEST_VPN_PREPARED" -> {
                testVpnPrepared(context)
            }
            "com.bonded.bonded_app.TEST_VPN_STATUS" -> {
                testVpnStatus()
            }
            "com.bonded.bonded_app.TEST_VPN_CONNECT" -> {
                logI(">>> Requesting VPN Connect")
                // Start VPN with the first available paired device
                val pairedServer = PairedServerStore.selectPreferredRecord(PairedServerStore.loadAll(context))
                if (pairedServer != null) {
                    BondedVpnService.start(context, pairedServer.id, runInBackground = false)
                    logI("VPN connect requested for device: ${pairedServer.id}")
                } else {
                    logE("No paired servers available for VPN connection")
                }
            }
            "com.bonded.bonded_app.TEST_VPN_DISCONNECT" -> {
                logI(">>> Requesting VPN Disconnect")
                BondedVpnService.stop(context)
                logI("VPN disconnect requested")
            }
            "com.bonded.bonded_app.TEST_DNS" -> {
                val host = intent.getStringExtra("host") ?: DEFAULT_DNS_HOST
                val expectedIp =
                        intent.getStringExtra("expected_ip")
                                ?: if (host == DEFAULT_DNS_HOST) DEFAULT_DNS_EXPECTED_IP else null
                testDnsResolution(host, expectedIp)
            }
            "com.bonded.bonded_app.TEST_TCP" -> {
                val host = intent.getStringExtra("host") ?: "example.com"
                val port = intent.getIntExtra("port", 443)
                testTcpConnection(host, port)
            }
            "com.bonded.bonded_app.TEST_HTTP" -> {
                val url = intent.getStringExtra("url") ?: "https://example.com"
                testHttpConnection(url)
            }
            "com.bonded.bonded_app.TEST_HTTP_CODINGWELL" -> {
                testCodingwellConnection()
            }
            "com.bonded.bonded_app.TEST_PROTOCOL_STRESS" -> {
                ProtocolStressTester.run(
                        context = context,
                        config =
                                ProtocolStressConfig(
                                        dnsHost = intent.getStringExtra("host") ?: "cloudflare.com",
                                        dnsResolver = intent.getStringExtra("resolver")
                                                        ?: "1.1.1.1",
                                        httpUrl = intent.getStringExtra("http_url")
                                                        ?: "http://httpforever.com/",
                                        httpsUrl = intent.getStringExtra("https_url")
                                                        ?: "https://example.com/",
                                        http3Url = intent.getStringExtra("http3_url")
                                                        ?: "https://cloudflare-quic.com/",
                                        rounds = intent.getIntExtra("rounds", 5),
                                ),
                        logI = ::logI,
                        logD = ::logD,
                        logW = ::logW,
                        logE = ::logE,
                )
            }
            "com.bonded.bonded_app.TEST_ALL" -> {
                testVpnStatus()
                testDnsResolution(DEFAULT_DNS_HOST, DEFAULT_DNS_EXPECTED_IP)
                testLoopbackTcpConnection()
                testLoopbackHttpConnection()
            }
            else -> {
                logW("Unknown action: ${intent.action}")
            }
        }

        logI("=== Test Complete ===")
    }

    private fun testVpnStatus() {
        logI(">>> VPN Status Test")
        val isRunning = BondedVpnService.isRunning()
        val snapshot = BondedVpnService.getSessionSnapshot()

        logI("VPN running=$isRunning")
        if (snapshot == null) {
            logI("Session snapshot=<none>")
            return
        }

        val state = snapshot["state"]
        val outboundPackets = snapshot["outboundPackets"]
        val inboundPackets = snapshot["inboundPackets"]
        val outboundBytes = snapshot["outboundBytes"]
        val inboundBytes = snapshot["inboundBytes"]
        val pathCount = snapshot["networkPathCount"]
        val lastError = snapshot["lastError"]

        logI(
                "Session state=$state, paths=$pathCount, out=$outboundPackets/$outboundBytes B, in=$inboundPackets/$inboundBytes B, lastError=$lastError"
        )
    }

    private fun testVpnPrepared(context: Context) {
        logI(">>> VPN Prepared Test")
        val prepareIntent = VpnService.prepare(context)
        val prepared = (prepareIntent == null)
        logI("VPN prepared=$prepared")
        if (!prepared) {
            logW("VpnService.prepare() returned non-null intent; user consent is required/revoked.")
        }
    }

    private fun testDnsResolution(host: String, expectedIp: String? = null): Thread {
        logI(">>> DNS Resolution Test for: $host")
        return thread {
            try {
                val startMs = System.currentTimeMillis()
                logD("Starting DNS lookup at ${System.currentTimeMillis()}")

                val addresses = InetAddress.getAllByName(host)
                val elapsedMs = System.currentTimeMillis() - startMs

                logI("✓ DNS resolved '$host' to ${addresses.size} address(es) in ${elapsedMs}ms")
                addresses.forEach { addr ->
                    logI("  - ${addr.javaClass.simpleName}: ${addr.hostAddress}")
                }

                if (!expectedIp.isNullOrBlank()) {
                    val matchesExpected = addresses.any { it.hostAddress == expectedIp }
                    if (matchesExpected) {
                        logI("✓ DNS expected IP matched: $expectedIp")
                    } else {
                        val resolved = addresses.joinToString(",") { it.hostAddress }
                        logE(
                                "✗ DNS expected IP mismatch for '$host': expected=$expectedIp resolved=$resolved"
                        )
                    }
                }
            } catch (e: Exception) {
                logE("✗ DNS resolution failed for '$host': ${e.message}", e)
            }
        }
    }

    private fun testTcpConnection(host: String, port: Int): Thread {
        logI(">>> TCP Connection Test to $host:$port")
        if (port == 8080) {
            logE(
                    "Port 8080 is Bonded NaiveTCP auth and is blocked for raw TEST_TCP probes. Use another port (e.g. 80/443/8081)."
            )
            return thread {}
        }
        return thread {
            var socket: Socket? = null
            try {
                val startMs = System.currentTimeMillis()
                logD("Starting TCP connection at ${System.currentTimeMillis()}")

                // Create socket with explicit timeout
                val socket = Socket()
                socket.connect(java.net.InetSocketAddress(host, port), 10000) // 10s connect timeout

                val elapsedMs = System.currentTimeMillis() - startMs

                logI("✓ TCP connection established to $host:$port in ${elapsedMs}ms")
                logI("  Local: ${socket.localAddress.hostAddress}:${socket.localPort}")
                logI("  Remote: ${socket.inetAddress.hostAddress}:${socket.port}")
            } catch (e: Exception) {
                logE("✗ TCP connection failed to $host:$port: ${e.message}", e)
            } finally {
                try {
                    socket?.close()
                } catch (_: Exception) {}
            }
        }
    }

    private fun testHttpConnection(urlString: String): Thread {
        logI(">>> HTTP Connection Test to $urlString")
        return thread {
            try {
                val startMs = System.currentTimeMillis()
                logD("Starting HTTP request at ${System.currentTimeMillis()}")

                val url = URL(urlString)
                val connection = url.openConnection()
                connection.connectTimeout = 10000 // 10s timeout
                connection.readTimeout = 10000

                var responseCode: Int? = null
                var responseMessage: String? = null
                if (connection is java.net.HttpURLConnection) {
                    responseCode = connection.responseCode
                    responseMessage = connection.responseMessage
                }

                val elapsedMs = System.currentTimeMillis() - startMs

                logI("✓ HTTP connection successful to $urlString in ${elapsedMs}ms")

                if (responseCode != null) {
                    logI("  HTTP $responseCode: $responseMessage")
                }
            } catch (e: Exception) {
                logE("✗ HTTP connection failed to $urlString: ${e.message}", e)
            }
        }
    }

    private fun testCodingwellConnection(): Thread {
        val candidates =
                listOf(
                        "https://codingwell.net",
                        "https://www.codingwell.net",
                        "https://example.com",
                )

        logI(">>> Codingwell HTTPS Test (with fallback)")
        return thread {
            var lastError: String? = null
            for ((index, urlString) in candidates.withIndex()) {
                try {
                    val startMs = System.currentTimeMillis()
                    logD("Attempt ${index + 1}/${candidates.size}: $urlString")

                    val connection = URL(urlString).openConnection()
                    connection.connectTimeout = 10000
                    connection.readTimeout = 10000

                    var responseCode: Int? = null
                    var responseMessage: String? = null
                    if (connection is java.net.HttpURLConnection) {
                        responseCode = connection.responseCode
                        responseMessage = connection.responseMessage
                    }

                    val elapsedMs = System.currentTimeMillis() - startMs
                    logI("✓ HTTPS connection successful to $urlString in ${elapsedMs}ms")
                    if (responseCode != null) {
                        logI("  HTTP $responseCode: $responseMessage")
                    }
                    if (urlString != candidates.first()) {
                        logW(
                                "Primary codingwell endpoint unavailable; succeeded using fallback: $urlString"
                        )
                    }
                    return@thread
                } catch (e: Exception) {
                    lastError = e.message
                    logW("Attempt failed for $urlString: ${e.message}")
                }
            }

            logE("✗ Codingwell HTTPS test failed for all endpoints. Last error: $lastError")
        }
    }

    private fun testLoopbackTcpConnection(): Thread {
        logI(">>> Loopback TCP Connection Test")
        return thread {
            var server: ServerSocket? = null
            var client: Socket? = null
            try {
                val startMs = System.currentTimeMillis()
                server = ServerSocket(0)
                val port = server.localPort

                val acceptThread = thread {
                    try {
                        server.accept().use { accepted ->
                            accepted.getOutputStream().write(byteArrayOf(0x42))
                            accepted.getOutputStream().flush()
                        }
                    } catch (_: Exception) {}
                }

                client = Socket()
                client.connect(InetSocketAddress("127.0.0.1", port), 3000)
                client.getInputStream().read()
                val elapsedMs = System.currentTimeMillis() - startMs
                logI("✓ Loopback TCP connection established in ${elapsedMs}ms (port=$port)")
                acceptThread.join(1000)
            } catch (e: Exception) {
                logE("✗ Loopback TCP connection failed: ${e.message}", e)
            } finally {
                try {
                    client?.close()
                } catch (_: Exception) {}
                try {
                    server?.close()
                } catch (_: Exception) {}
            }
        }
    }

    private fun testLoopbackHttpConnection(): Thread {
        logI(">>> Loopback HTTP Connection Test")
        return thread {
            var server: ServerSocket? = null
            var client: Socket? = null
            try {
                val startMs = System.currentTimeMillis()
                server = ServerSocket(0)
                val port = server.localPort

                val serverThread = thread {
                    try {
                        server.accept().use { socket ->
                            val writer = OutputStreamWriter(socket.getOutputStream())
                            writer.write("HTTP/1.1 200 OK\\r\\n")
                            writer.write("Content-Length: 2\\r\\n")
                            writer.write("Connection: close\\r\\n")
                            writer.write("\\r\\n")
                            writer.write("OK")
                            writer.flush()
                        }
                    } catch (e: Exception) {
                        logE("Loopback HTTP server side failed: ${e.message}", e)
                    }
                }

                client = Socket()
                client.connect(InetSocketAddress("127.0.0.1", port), 3000)
                client.soTimeout = 3000

                val reader = BufferedReader(InputStreamReader(client.getInputStream()))
                val statusLine = reader.readLine() ?: ""
                val responseCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

                val elapsedMs = System.currentTimeMillis() - startMs
                logI(
                        "✓ Loopback HTTP connection successful in ${elapsedMs}ms (HTTP $responseCode, port=$port)"
                )
                serverThread.join(1000)
            } catch (e: Exception) {
                logE("✗ Loopback HTTP connection failed: ${e.message}", e)
            } finally {
                try {
                    client?.close()
                } catch (_: Exception) {}
                try {
                    server?.close()
                } catch (_: Exception) {}
            }
        }
    }
}
