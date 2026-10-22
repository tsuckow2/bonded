package com.bonded.bonded_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import kotlin.concurrent.thread

class NetworkTestForegroundService : Service() {
    companion object {
        const val ACTION_RUN = "com.bonded.bonded_app.NETWORK_TEST_RUN"
        const val EXTRA_TEST_ACTION = "test_action"
        const val EXTRA_HOST = "host"
        const val EXTRA_EXPECTED_IP = "expected_ip"
        const val EXTRA_URL = "url"
        const val EXTRA_PORT = "port"
        const val EXTRA_RESOLVER = "resolver"
        const val EXTRA_HTTP_URL = "http_url"
        const val EXTRA_HTTPS_URL = "https_url"
        const val EXTRA_HTTP3_URL = "http3_url"
        const val EXTRA_ROUNDS = "rounds"

        private const val CHANNEL_ID = "bonded_network_tests"
        private const val NOTIFICATION_ID = 1002
        private const val DEFAULT_DNS_HOST = "charter.codingwell.net"
        private const val DEFAULT_DNS_EXPECTED_IP = "97.115.185.254"
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action != ACTION_RUN) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }

        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Running network test"))

        val testAction = intent.getStringExtra(EXTRA_TEST_ACTION)
        if (testAction.isNullOrBlank()) {
            logE("Foreground test request missing test action")
            stopSelfResult(startId)
            return START_NOT_STICKY
        }

        thread {
            try {
                runAction(testAction, intent)
            } catch (e: Exception) {
                logE("Foreground test execution failed: ${e.message}", e)
            } finally {
                logI("=== Foreground Service Test Complete ===")
                stopSelfResult(startId)
            }
        }

        return START_NOT_STICKY
    }

    private fun runAction(action: String, intent: Intent) {
        logI("=== Foreground Service Action: $action ===")
        when (action) {
            "com.bonded.bonded_app.TEST_VPN_PREPARED" -> testVpnPrepared()
            "com.bonded.bonded_app.TEST_VPN_STATUS" -> testVpnStatus()
            "com.bonded.bonded_app.TEST_VPN_CONNECT" -> testVpnConnect()
            "com.bonded.bonded_app.TEST_VPN_DISCONNECT" -> testVpnDisconnect()
            "com.bonded.bonded_app.TEST_DNS" -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: DEFAULT_DNS_HOST
                val expectedIp =
                        intent.getStringExtra(EXTRA_EXPECTED_IP)
                                ?: if (host == DEFAULT_DNS_HOST) DEFAULT_DNS_EXPECTED_IP else null
                testDnsResolution(host, expectedIp)
            }
            "com.bonded.bonded_app.TEST_TCP" -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: "example.com"
                val port = intent.getIntExtra(EXTRA_PORT, 443)
                testTcpConnection(host, port)
            }
            "com.bonded.bonded_app.TEST_HTTP" -> {
                val url = intent.getStringExtra(EXTRA_URL) ?: "https://example.com"
                testHttpConnection(url)
            }
            "com.bonded.bonded_app.TEST_HTTP_CODINGWELL" -> testCodingwellConnection()
            "com.bonded.bonded_app.TEST_PROTOCOL_STRESS" -> {
                ProtocolStressTester.run(
                        context = this,
                        config =
                                ProtocolStressConfig(
                                        dnsHost = intent.getStringExtra(EXTRA_HOST)
                                                        ?: "cloudflare.com",
                                        dnsResolver = intent.getStringExtra(EXTRA_RESOLVER)
                                                        ?: "1.1.1.1",
                                        httpUrl = intent.getStringExtra(EXTRA_HTTP_URL)
                                                        ?: "http://httpforever.com/",
                                        httpsUrl = intent.getStringExtra(EXTRA_HTTPS_URL)
                                                        ?: "https://example.com/",
                                        http3Url = intent.getStringExtra(EXTRA_HTTP3_URL)
                                                        ?: "https://cloudflare-quic.com/",
                                        rounds = intent.getIntExtra(EXTRA_ROUNDS, 5),
                                ),
                        logI = ::logI,
                        logD = ::logD,
                        logW = ::logW,
                        logE = ::logE,
                )
            }
            "com.bonded.bonded_app.TEST_UDP_PROBE" -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: "charter.codingwell.net"
                val port = intent.getIntExtra(EXTRA_PORT, 443)
                UdpProbeTester.run(
                        host = host,
                        port = port,
                        logI = ::logI,
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
            else -> logW("Unknown foreground test action: $action")
        }
    }

    private fun logI(message: String) {
        android.util.Log.i("NetworkTest", message)
        NetworkTestReceiver.appendServiceLog("I", message)
    }

    private fun logD(message: String) {
        android.util.Log.d("NetworkTest", message)
        NetworkTestReceiver.appendServiceLog("D", message)
    }

    private fun logW(message: String) {
        android.util.Log.w("NetworkTest", message)
        NetworkTestReceiver.appendServiceLog("W", message)
    }

    private fun logE(message: String, error: Throwable? = null) {
        if (error != null) {
            android.util.Log.e("NetworkTest", message, error)
        } else {
            android.util.Log.e("NetworkTest", message)
        }
        val detail =
                if (error == null) message
                else "$message | ${error::class.java.simpleName}: ${error.message}"
        NetworkTestReceiver.appendServiceLog("E", detail)
    }

    private fun testVpnPrepared() {
        logI(">>> VPN Prepared Test")
        val prepared = VpnService.prepare(this) == null
        logI("VPN prepared=$prepared")
        if (!prepared) {
            logW("VpnService.prepare() returned non-null intent; user consent is required/revoked.")
        }
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

    private fun testVpnConnect() {
        logI(">>> Requesting VPN Connect")
        val pairedServer = PairedServerStore.selectPreferredRecord(PairedServerStore.loadAll(this))
        if (pairedServer != null) {
            BondedVpnService.start(this, pairedServer.id, runInBackground = false)
            logI("VPN connect requested for device: ${pairedServer.id}")
        } else {
            logE("No paired servers available for VPN connection")
        }
    }

    private fun testVpnDisconnect() {
        logI(">>> Requesting VPN Disconnect")
        BondedVpnService.stop(this)
        logI("VPN disconnect requested")
    }

    private fun testDnsResolution(host: String, expectedIp: String?) {
        logI(">>> DNS Resolution Test for: $host")
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

    private fun testTcpConnection(host: String, port: Int) {
        logI(">>> TCP Connection Test to $host:$port")
        if (port == 8080) {
            logE(
                    "Port 8080 is Bonded NaiveTCP auth and is blocked for raw TEST_TCP probes. Use another port (e.g. 80/443/8081)."
            )
            return
        }
        var socket: Socket? = null
        try {
            val startMs = System.currentTimeMillis()
            logD("Starting TCP connection at ${System.currentTimeMillis()}")
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), 10000)
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

    private fun testHttpConnection(urlString: String) {
        logI(">>> HTTP Connection Test to $urlString")
        try {
            val startMs = System.currentTimeMillis()
            logD("Starting HTTP request at ${System.currentTimeMillis()}")
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
            logI("✓ HTTP connection successful to $urlString in ${elapsedMs}ms")
            if (responseCode != null) {
                logI("  HTTP $responseCode: $responseMessage")
            }
        } catch (e: Exception) {
            logE("✗ HTTP connection failed to $urlString: ${e.message}", e)
        }
    }

    private fun testCodingwellConnection() {
        val candidates =
                listOf(
                        "https://codingwell.net",
                        "https://www.codingwell.net",
                        "https://example.com",
                )
        logI(">>> Codingwell HTTPS Test (with fallback)")
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
                return
            } catch (e: Exception) {
                lastError = e.message
                logW("Attempt failed for $urlString: ${e.message}")
            }
        }
        logE("✗ Codingwell HTTPS test failed for all endpoints. Last error: $lastError")
    }

    private fun testLoopbackTcpConnection() {
        logI(">>> Loopback TCP Connection Test")
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

    private fun testLoopbackHttpConnection() {
        logI(">>> Loopback HTTP Connection Test")
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

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        val existing = manager.getNotificationChannel(CHANNEL_ID)
        if (existing != null) return

        val channel =
                NotificationChannel(
                                CHANNEL_ID,
                                "Network Diagnostics",
                                NotificationManager.IMPORTANCE_LOW,
                        )
                        .apply {
                            description = "Foreground execution for Bonded network diagnostic tests"
                        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(content: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("Bonded Network Test")
                .setContentText(content)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build()
    }
}
