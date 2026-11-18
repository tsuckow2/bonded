package com.bonded.bonded_app

import android.app.Activity
import android.content.Intent
import android.net.wifi.WifiManager
import android.net.VpnService
import android.os.Bundle
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * Transparent activity for ADB-driven VPN control during debugging.
 * Runs entirely headless — it performs the requested action, logs the result,
 * and finishes immediately.  No UI is displayed.
 *
 * Usage:
 *   # Connect VPN (first paired server)
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action connect
 *
 *   # Connect VPN (specific device)
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action connect --es device_id "<uuid>"
 *
 *   # Disconnect VPN
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action disconnect
 *
 *   # Print current session snapshot to logcat
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action status
 *
 *   # Listen for one UDP packet and log the result
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action udp_listen --ei port 59555 --ei timeout_ms 20000
 *
 *   # Send one UDP packet and log the result
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action udp_send --es target_ip 192.168.1.250 --ei port 59555 --es message test
 *
 *   # Log Wi-Fi identity plus route/neighbor state toward a peer
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action peer_info --es target_ip 192.168.1.250
 *
 *   # Listen for one TCP connection without the VPN running
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action tcp_listen --es bind_ip 192.168.1.250 --ei port 59570 --ei timeout_ms 20000
 *
 *   # Connect once to a peer TCP listener without the VPN running
 *   adb shell am start -n com.bonded.bonded_app/.DebugVpnActivity \
 *       --es action tcp_connect --es bind_ip 192.168.1.140 --es target_ip 192.168.1.250 --ei port 59570 --es message hello
 *
 * All output is logged under the "DebugVPN" tag.
 */
class DebugVpnActivity : Activity() {

    companion object {
        private const val TAG = "DebugVPN"
        private const val REQUEST_VPN_PERMISSION = 1001
        private const val EXTRA_ACTION = "action"
        private const val EXTRA_DEVICE_ID = "device_id"
        private const val EXTRA_PORT = "port"
        private const val EXTRA_TIMEOUT_MS = "timeout_ms"
        private const val EXTRA_TARGET_IP = "target_ip"
        private const val EXTRA_MESSAGE = "message"
        private const val EXTRA_PROTECT = "protect"
        private const val EXTRA_BIND_IP = "bind_ip"
    }

    // Held across the permission grant round-trip.
    private var pendingDeviceId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val action = intent?.getStringExtra(EXTRA_ACTION)?.lowercase()?.trim()
        log("Received action='$action'")

        when (action) {
            "connect" -> {
                val deviceId = intent.getStringExtra(EXTRA_DEVICE_ID)
                    ?: resolveFirstPairedDeviceId()

                if (deviceId == null) {
                    logError("No paired servers found — pair a server first")
                    finish()
                    return
                }

                pendingDeviceId = deviceId
                startVpnWithPermissionCheck(deviceId)
            }

            "disconnect" -> {
                log("Stopping VPN")
                BondedVpnService.stop(this)
                log("VPN stop requested")
                finish()
            }

            "status" -> {
                logStatus()
                finish()
            }

            "udp_listen" -> {
                startUdpListenProbe(intent)
                finish()
            }

            "udp_send" -> {
                startUdpSendProbe(intent)
                finish()
            }

            "peer_info" -> {
                logPeerInfo(intent)
                finish()
            }

            "tcp_listen" -> {
                startTcpListenProbe(intent)
                finish()
            }

            "tcp_connect" -> {
                startTcpConnectProbe(intent)
                finish()
            }

            "tcp_connect_network" -> {
                startTcpConnectViaTrackedNetworkProbe(intent)
                finish()
            }

            null, "" -> {
                logError("No 'action' extra provided. Use --es action connect|disconnect|status|udp_listen|udp_send|peer_info|tcp_listen|tcp_connect|tcp_connect_network")
                finish()
            }

            else -> {
                logError("Unknown action '$action'. Use connect, disconnect, status, udp_listen, udp_send, peer_info, tcp_listen, tcp_connect, or tcp_connect_network")
                finish()
            }
        }
    }

    private fun startVpnWithPermissionCheck(deviceId: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            // Permission already granted — start immediately.
            log("VPN permission already granted; starting VPN for device=$deviceId")
            BondedVpnService.start(this, deviceId, runInBackground = true)
            log("VPN start requested")
            finish()
        } else {
            // Need user to approve VPN permission (shows system dialog).
            log("Requesting VPN permission for device=$deviceId (system dialog will appear)")
            startActivityForResult(prepareIntent, REQUEST_VPN_PERMISSION)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != REQUEST_VPN_PERMISSION) {
            finish()
            return
        }

        val deviceId = pendingDeviceId
        pendingDeviceId = null

        if (resultCode == RESULT_OK && deviceId != null) {
            log("VPN permission granted; starting VPN for device=$deviceId")
            BondedVpnService.start(this, deviceId, runInBackground = true)
            log("VPN start requested")
        } else {
            logError("VPN permission denied or cancelled (resultCode=$resultCode)")
        }

        finish()
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private fun resolveFirstPairedDeviceId(): String? {
        // UI-selected record first, then newest peer-share record,
        // then newest record (via AppSettingsStore.selectedRecord).
        val server = AppSettingsStore.selectedRecord(this)
        if (server != null) {
            log("Using preferred paired server: id=${server.id} addr=${server.publicAddress} peerShareEnabled=${server.peerShareEnabled}")
        }
        return server?.id
    }

    private fun logStatus() {
        val running = BondedVpnService.isRunning()
        log("VPN running=$running")

        // Dump all paired servers so we can verify the stored public key.
        val servers = PairedServerStore.loadAll(this)
        if (servers.isEmpty()) {
            log("No paired servers stored")
        } else {
            servers.forEachIndexed { i, s ->
                log("Paired server[$i]: id=${s.id} addr=${s.publicAddress} identity=${s.serverIdentityPublicKey.take(20)}…")
            }
        }

        val snapshot = BondedVpnService.getSessionSnapshot() ?: run {
            log("No session snapshot available")
            return
        }

        log(buildString {
            append("state=${snapshot["state"]}")
            append("  server=${snapshot["serverAddress"]}")
            append("  activeTransport=${snapshot["activeTransport"]}")
            append("  transportCount=${snapshot["transportCount"]}")
            append("  peerRelayCount=${snapshot["peerRelayCount"]}")
            append("  networkPathCount=${snapshot["networkPathCount"]}")
            append("  networkBindAddresses=${snapshot["networkBindAddresses"]}")
            append("  networkPathSummaries=${snapshot["networkPathSummaries"]}")
            append("  out=${snapshot["outboundPackets"]}/${snapshot["outboundBytes"]}B")
            append("  in=${snapshot["inboundPackets"]}/${snapshot["inboundBytes"]}B")
            val err = snapshot["lastError"]
            if (err != null) append("  lastError=$err")
        })
    }

    private fun startUdpListenProbe(intent: Intent) {
        val port = intent.getIntExtra(EXTRA_PORT, 59555)
        val timeoutMs = intent.getIntExtra(EXTRA_TIMEOUT_MS, 20_000)
        val protect = intent.getBooleanExtra(EXTRA_PROTECT, true)
        val bindIp = intent.getStringExtra(EXTRA_BIND_IP)?.trim().orEmpty()

        thread(name = "debug-udp-listen", isDaemon = true) {
            try {
                DatagramSocket(null).use { socket ->
                    val bindAddress = if (bindIp.isEmpty()) {
                        InetSocketAddress(port)
                    } else {
                        InetSocketAddress(InetAddress.getByName(bindIp), port)
                    }
                    socket.bind(bindAddress)
                    socket.soTimeout = timeoutMs
                    log(
                        "UDP listen probe bound local=${socket.localAddress.hostAddress}:${socket.localPort} requestedBind=${if (bindIp.isEmpty()) "*" else bindIp}:$port protect=$protect timeoutMs=$timeoutMs"
                    )
                    if (protect) {
                        val protected = BondedVpnService.protectDatagramSocketForDebug(socket)
                        log("UDP listen probe protect(datagramSocket) -> $protected")
                    }

                    val buffer = ByteArray(2048)
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val payload = String(packet.data, 0, packet.length, Charsets.UTF_8)
                    log(
                        "UDP listen probe received ${packet.length}B from ${packet.address.hostAddress}:${packet.port} payload=$payload"
                    )
                }
            } catch (e: Exception) {
                logError("UDP listen probe failed: ${e.message}")
            }
        }
    }

    private fun startUdpSendProbe(intent: Intent) {
        val targetIp = intent.getStringExtra(EXTRA_TARGET_IP)?.trim().orEmpty()
        if (targetIp.isEmpty()) {
            logError("udp_send requires --es target_ip")
            return
        }

        val port = intent.getIntExtra(EXTRA_PORT, 59555)
        val message = intent.getStringExtra(EXTRA_MESSAGE) ?: "bonded-udp-probe"
        val protect = intent.getBooleanExtra(EXTRA_PROTECT, true)
        val bindIp = intent.getStringExtra(EXTRA_BIND_IP)?.trim().orEmpty()

        thread(name = "debug-udp-send", isDaemon = true) {
            try {
                DatagramSocket(null).use { socket ->
                    if (bindIp.isEmpty()) {
                        socket.bind(InetSocketAddress(0))
                    } else {
                        socket.bind(InetSocketAddress(InetAddress.getByName(bindIp), 0))
                    }
                    log(
                        "UDP send probe bound local=${socket.localAddress.hostAddress}:${socket.localPort} requestedBind=${if (bindIp.isEmpty()) "*" else bindIp}"
                    )
                    if (protect) {
                        val protected = BondedVpnService.protectDatagramSocketForDebug(socket)
                        log("UDP send probe protect(datagramSocket) -> $protected")
                    }

                    val payload = message.toByteArray(Charsets.UTF_8)
                    val packet = DatagramPacket(
                        payload,
                        payload.size,
                        InetAddress.getByName(targetIp),
                        port,
                    )
                    socket.send(packet)
                    log("UDP send probe sent ${payload.size}B to $targetIp:$port payload=$message")
                }
            } catch (e: Exception) {
                logError("UDP send probe failed: ${e.message}")
            }
        }
    }

    private fun logPeerInfo(intent: Intent) {
        val targetIp = intent.getStringExtra(EXTRA_TARGET_IP)?.trim().orEmpty()
        log("VPN running=${BondedVpnService.isRunning()}")
        logWifiInfo()
        if (targetIp.isNotEmpty()) {
            logShell("route to $targetIp", "ip route get $targetIp")
            logShell("neighbor $targetIp", "ip neigh show $targetIp dev wlan0")
        }
    }

    private fun startTcpListenProbe(intent: Intent) {
        val port = intent.getIntExtra(EXTRA_PORT, 59570)
        val timeoutMs = intent.getIntExtra(EXTRA_TIMEOUT_MS, 20_000)
        val bindIp = intent.getStringExtra(EXTRA_BIND_IP)?.trim().orEmpty()

        thread(name = "debug-tcp-listen", isDaemon = true) {
            try {
                ServerSocket().use { server ->
                    val bindAddress = if (bindIp.isEmpty()) {
                        InetSocketAddress(port)
                    } else {
                        InetSocketAddress(InetAddress.getByName(bindIp), port)
                    }
                    server.bind(bindAddress)
                    server.soTimeout = timeoutMs
                    log(
                        "TCP listen probe bound local=${server.inetAddress.hostAddress}:${server.localPort} requestedBind=${if (bindIp.isEmpty()) "*" else bindIp}:$port timeoutMs=$timeoutMs"
                    )

                    server.accept().use { socket ->
                        val reader = socket.getInputStream().bufferedReader()
                        val writer = PrintWriter(socket.getOutputStream(), true)
                        val message = reader.readLine() ?: ""
                        log(
                            "TCP listen probe accepted remote=${socket.inetAddress.hostAddress}:${socket.port} local=${socket.localAddress.hostAddress}:${socket.localPort} message=$message"
                        )
                        writer.println("ack:$message")
                    }
                }
            } catch (e: Exception) {
                logError("TCP listen probe failed: ${e.message}")
            }
        }
    }

    private fun startTcpConnectProbe(intent: Intent) {
        val targetIp = intent.getStringExtra(EXTRA_TARGET_IP)?.trim().orEmpty()
        if (targetIp.isEmpty()) {
            logError("tcp_connect requires --es target_ip")
            return
        }

        val port = intent.getIntExtra(EXTRA_PORT, 59570)
        val timeoutMs = intent.getIntExtra(EXTRA_TIMEOUT_MS, 5_000)
        val bindIp = intent.getStringExtra(EXTRA_BIND_IP)?.trim().orEmpty()
        val message = intent.getStringExtra(EXTRA_MESSAGE) ?: "bonded-tcp-probe"

        thread(name = "debug-tcp-connect", isDaemon = true) {
            try {
                Socket().use { socket ->
                    val bindAddress = if (bindIp.isEmpty()) {
                        InetSocketAddress(0)
                    } else {
                        InetSocketAddress(InetAddress.getByName(bindIp), 0)
                    }
                    socket.bind(bindAddress)
                    log(
                        "TCP connect probe bound local=${socket.localAddress.hostAddress}:${socket.localPort} requestedBind=${if (bindIp.isEmpty()) "*" else bindIp}"
                    )
                    socket.connect(InetSocketAddress(InetAddress.getByName(targetIp), port), timeoutMs)
                    log(
                        "TCP connect probe connected remote=${socket.inetAddress.hostAddress}:${socket.port} local=${socket.localAddress.hostAddress}:${socket.localPort}"
                    )

                    val writer = PrintWriter(socket.getOutputStream(), true)
                    val reader = socket.getInputStream().bufferedReader()
                    writer.println(message)
                    val response = reader.readLine() ?: ""
                    log("TCP connect probe received response=$response")
                }
            } catch (e: Exception) {
                logError("TCP connect probe failed: ${e.message}")
            }
        }
    }

        private fun startTcpConnectViaTrackedNetworkProbe(intent: Intent) {
            val targetIp = intent.getStringExtra(EXTRA_TARGET_IP)?.trim().orEmpty()
            if (targetIp.isEmpty()) {
                logError("tcp_connect_network requires --es target_ip")
                return
            }

            val bindIp = intent.getStringExtra(EXTRA_BIND_IP)?.trim().orEmpty()
            if (bindIp.isEmpty()) {
                logError("tcp_connect_network requires --es bind_ip")
                return
            }

            val port = intent.getIntExtra(EXTRA_PORT, 443)
            val timeoutMs = intent.getIntExtra(EXTRA_TIMEOUT_MS, 5_000)
            val message = intent.getStringExtra(EXTRA_MESSAGE) ?: "bonded-tcp-probe"

            thread(name = "debug-tcp-connect-network", isDaemon = true) {
                val manager = AndroidNetworkPathManager(applicationContext) {}
                try {
                    manager.start()
                    manager.connectTcpViaTrackedNetwork(bindIp, targetIp, port, timeoutMs).use { socket ->
                        log(
                            "TCP tracked-network connect connected remote=${socket.inetAddress.hostAddress}:${socket.port} local=${socket.localAddress.hostAddress}:${socket.localPort} requestedBind=$bindIp"
                        )

                        val writer = PrintWriter(socket.getOutputStream(), true)
                        val reader = socket.getInputStream().bufferedReader()
                        writer.println(message)
                        val response = reader.readLine() ?: ""
                        log("TCP tracked-network connect received response=$response")
                    }
                } catch (e: Exception) {
                    logError("TCP tracked-network connect failed: ${e.message}")
                } finally {
                    manager.stop()
                }
            }
        }

    private fun logWifiInfo() {
        val wifiManager = applicationContext.getSystemService(WIFI_SERVICE) as? WifiManager
        val info = wifiManager?.connectionInfo
        if (info == null) {
            log("Wi-Fi info unavailable")
            return
        }

        log(
            "Wi-Fi info ssid=${sanitizeWifiField(info.ssid)} bssid=${sanitizeWifiField(info.bssid)} ip=${intToIpv4(info.ipAddress)} freq=${info.frequency}MHz rssi=${info.rssi} link=${info.linkSpeed}Mbps"
        )
    }

    private fun logShell(label: String, command: String) {
        try {
            val process = ProcessBuilder("sh", "-c", command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use(BufferedReader::readText).trim()
            val exitCode = process.waitFor()
            log("shell[$label] exit=$exitCode output=${if (output.isEmpty()) "<empty>" else output}")
        } catch (e: Exception) {
            logError("shell[$label] failed: ${e.message}")
        }
    }

    private fun sanitizeWifiField(value: String?): String {
        return value?.trim()?.trim('"').takeUnless { it.isNullOrEmpty() || it == "<unknown ssid>" }
            ?: "<unknown>"
    }

    private fun intToIpv4(value: Int): String {
        if (value == 0) {
            return "0.0.0.0"
        }
        return listOf(
            value and 0xff,
            value shr 8 and 0xff,
            value shr 16 and 0xff,
            value shr 24 and 0xff,
        ).joinToString(".")
    }

    private fun log(msg: String) {
        android.util.Log.i(TAG, msg)
    }

    private fun logError(msg: String) {
        android.util.Log.e(TAG, msg)
    }
}
