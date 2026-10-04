package com.bonded.bonded_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.annotation.Keep
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.ArrayDeque
import kotlin.concurrent.thread
import org.json.JSONArray
import org.json.JSONObject

data class SessionSnapshot(
        val state: String,
        val serverAddress: String,
    val activeTransport: String,
    val transportCount: Int,
    val peerRelayCount: Int,
        val outboundPackets: Long,
        val inboundPackets: Long,
        val outboundBytes: Long,
        val inboundBytes: Long,
        val connectedAtMs: Long,
        val lastError: String?,
)

class BondedVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetIoThread: Thread? = null
    private var inboundDrainThread: Thread? = null
    private var sessionMonitorThread: Thread? = null
    private var networkPathManager: AndroidNetworkPathManager? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var activeDeviceId: String? = null

    @Volatile private var packetIoRunning = false

    @Volatile private var nativeTunFdWriteAvailable = false

    @Volatile private var nativeProcessingAvailable = nativeLoaded

    @Volatile private var nativeAvailabilityReported = false

    @Volatile private var sessionMonitorRunning = false

    @Volatile private var sessionStartupInProgress = false

    @Volatile private var networkRebindInProgress = false

    @Volatile private var sessionRecoveryInProgress = false

    @Volatile private var lastRecoveryAttemptMs = 0L

    private val pendingOutboundLock = Any()
    private val pendingOutboundPackets = ArrayDeque<ByteArray>()

    private var lastEmittedSessionState: String? = null
    private var lastNetworkBindingSignature: String = ""
    // Server address with hostname pre-resolved to IP before VPN captures DNS traffic.
    // Cached across recovery attempts so native code never needs in-tunnel DNS resolution.
    private var cachedServerAddress: String? = null

    @Volatile private var shutdownInProgress = false

    override fun onCreate() {
        super.onCreate()
        activeInstance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            android.util.Log.i("BondedVPN", "Received ACTION_STOP; shutting down VPN now")
            shutdownVpnNow()
            stopSelf()
            return START_NOT_STICKY
        }

        val runInBackground = intent?.getBooleanExtra(EXTRA_RUN_IN_BACKGROUND, false) == true
        activeDeviceId = intent?.getStringExtra(EXTRA_DEVICE_ID)

        if (activeDeviceId.isNullOrBlank()) {
            emitEvent("error", "Missing paired device ID for VPN startup")
            stopSelf()
            return START_NOT_STICKY
        }

        val pairedServer = PairedServerStore.findById(this, activeDeviceId!!)
        if (pairedServer == null) {
            emitEvent("error", "No paired server found for device $activeDeviceId")
            stopSelf()
            return START_NOT_STICKY
        }

        backgroundRunning = runInBackground
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ensureNotificationChannel()
            val notification = buildForegroundNotification()
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                            NOTIFICATION_ID,
                            notification,
                            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                    )
                } else {
                    startForeground(NOTIFICATION_ID, notification)
                }
            } catch (e: Exception) {
                android.util.Log.e("BondedVPN", "startForeground failed: ${e.message}", e)
                emitEvent("error", "Foreground startup warning: ${e.message}")
            }
        }

        // Pre-resolve the server hostname to an IP address while DNS is still unaffected
        // by the VPN. Once VPN is active, all DNS queries route through the TUN interface
        // which creates a bootstrapping deadlock (VPN not connected → can't forward DNS →
        // can't connect to VPN server). Caching the resolved IP here breaks that cycle.
        cachedServerAddress = resolveServerAddressEarly(pairedServer.publicAddress)
        android.util.Log.i("BondedVPN", "Cached server address: $cachedServerAddress")

        sessionStartupInProgress = true
        val pathManager = ensureNetworkPathManager()
        val networkPathCount = pathManager.start()
        val bindAddresses = pathManager.activeBindAddresses()
        setActiveNetworkBindings(bindAddresses, pathManager.activePathSummaries())
        acquireMulticastLockIfNeeded()

        if (vpnInterface == null) {
            try {
                android.util.Log.d(
                        "BondedVPN",
                        "Establishing VPN interface: address=10.8.0.2/32, mtu=1420, route=0.0.0.0/0"
                )
                val builder =
                        Builder()
                                .setSession("Bonded")
                                .setMtu(1420)
                                .addAddress("10.8.0.2", 32)
                                .addRoute("0.0.0.0", 0)
                                .addDnsServer("8.8.8.8")
                                .addDnsServer("1.1.1.1")

                // Keep the app process itself outside the VPN so control-plane sockets
                // (session establishment, pairing, health probes) are never captured.
                // This makes startup resilient even when per-socket protect(fd) fails.
                // Don't do this. It causes problems if we want to route some traffic through the
                // VPN
                // try {
                //     builder.addDisallowedApplication(packageName)
                //     android.util.Log.i(
                //             "BondedVPN",
                //             "Added disallowed application for VPN bypass: $packageName"
                //     )
                // } catch (e: PackageManager.NameNotFoundException) {
                //     android.util.Log.w(
                //             "BondedVPN",
                //             "Failed to add disallowed application $packageName: ${e.message}"
                //     )
                // }

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    throw IllegalStateException(
                            "VpnService.Builder.establish() returned null (VPN permission missing or revoked)",
                    )
                }
                android.util.Log.d("BondedVPN", "VPN interface established successfully")
                // Mark service running as soon as TUN exists so status checks reflect
                // VPN establishment even if later session/foreground steps degrade.
                running = vpnInterface != null
            } catch (e: Exception) {
                android.util.Log.e("BondedVPN", "Failed to establish VPN: ${e.message}", e)
                emitEvent("error", "Failed to establish VPN: ${e.message}")
                stopSelf()
                return START_NOT_STICKY
            }
        }

        if (!startNativeSession(pairedServer, networkPathCount, bindAddresses)) {
            sessionStartupInProgress = false
            emitEvent("error", "Failed to start native VPN session")
            stopSelf()
            return START_NOT_STICKY
        }
        sessionStartupInProgress = false

        running = running || (vpnInterface != null)
        startPacketIoLoopIfNeeded()
        startSessionMonitorIfNeeded()
        emitEvent(
                "started",
                if (backgroundRunning) {
                    "VPN started in background"
                } else {
                    "VPN started"
                },
        )
        return START_STICKY
    }

    override fun onDestroy() {
        if (activeInstance === this) {
            activeInstance = null
        }
        shutdownVpnNow()
        super.onDestroy()
    }

    private fun shutdownVpnNow() {
        if (shutdownInProgress) {
            return
        }
        shutdownInProgress = true

        stopPacketIoLoop()
        stopSessionMonitor()
        networkPathManager?.stop()
        networkPathManager = null
        lastNetworkBindingSignature = ""
        sessionStartupInProgress = false
        networkRebindInProgress = false
        sessionRecoveryInProgress = false
        lastRecoveryAttemptMs = 0L
        synchronized(pendingOutboundLock) { pendingOutboundPackets.clear() }
        cachedServerAddress = null
        releaseMulticastLock()
        stopNativeSession()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
        activeDeviceId = null
        if (backgroundRunning) {
            stopForeground(true)
        }
        running = false
        backgroundRunning = false
        emitEvent("stopped", "VPN stopped")

        shutdownInProgress = false
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val manager = getSystemService(NotificationManager::class.java)
        val channel =
                NotificationChannel(
                        NOTIFICATION_CHANNEL_ID,
                        "Bonded VPN",
                        NotificationManager.IMPORTANCE_LOW,
                )
        channel.description = "Background VPN status"
        manager.createNotificationChannel(channel)
    }

    private fun buildForegroundNotification(): Notification {
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setContentTitle("Bonded VPN")
                .setContentText("VPN is running in the background")
                .setSmallIcon(R.mipmap.ic_launcher)
                .setOngoing(true)
                .build()
    }

    private fun acquireMulticastLockIfNeeded() {
        if (multicastLock?.isHeld == true) {
            return
        }

        try {
            val wifiManager = applicationContext.getSystemService(WIFI_SERVICE) as? WifiManager
            val lock = wifiManager?.createMulticastLock("bonded:peer-share") ?: return
            lock.setReferenceCounted(false)
            lock.acquire()
            multicastLock = lock
            android.util.Log.i("BondedVPN", "Acquired Wi-Fi multicast lock for peer discovery")
        } catch (e: Exception) {
            android.util.Log.w("BondedVPN", "Failed to acquire multicast lock: ${e.message}")
        }
    }

    private fun releaseMulticastLock() {
        val lock = multicastLock ?: return
        try {
            if (lock.isHeld) {
                lock.release()
                android.util.Log.i("BondedVPN", "Released Wi-Fi multicast lock")
            }
        } catch (e: Exception) {
            android.util.Log.w("BondedVPN", "Failed to release multicast lock: ${e.message}")
        }
        multicastLock = null
    }

    private fun startPacketIoLoopIfNeeded() {
        val pfd = vpnInterface ?: return
        if (packetIoThread?.isAlive == true) {
            return
        }

        packetIoRunning = true
        nativeTunFdWriteAvailable = configureNativeTunFd(pfd)
        if (nativeTunFdWriteAvailable) {
            android.util.Log.i(
                "BondedVPN",
                "Native TUN fd handoff enabled; inbound packets will be written directly by Rust"
            )
        } else {
            android.util.Log.w(
                "BondedVPN",
                "Native TUN fd handoff unavailable; using legacy inbound JNI polling"
            )
        }

        // Outbound thread: reads raw IP packets from TUN and hands them to native.
        packetIoThread =
                thread(name = "bonded-vpn-outbound", start = true) {
                    val input = FileInputStream(pfd.fileDescriptor)
                    val buffer = ByteArray(32767)
                    try {
                        while (packetIoRunning) {
                            val readBytes = input.read(buffer)
                            if (readBytes <= 0) {
                                continue
                            }

                            processOutboundPacket(buffer, readBytes)
                        }
                    } catch (e: Exception) {
                        android.util.Log.e(
                                "BondedVPN",
                                "VPN outbound loop exception: ${e.message}",
                                e
                        )
                        if (packetIoRunning) {
                            emitEvent("error", "VPN outbound loop stopped: ${e.message}")
                        }
                    } finally {
                        try {
                            input.close()
                        } catch (_: Exception) {}
                    }
                }

        if (!nativeTunFdWriteAvailable) {
            // Fallback path: keep legacy inbound polling if native fd handoff fails.
            inboundDrainThread =
                    thread(name = "bonded-vpn-inbound", start = true) {
                        val output = FileOutputStream(pfd.fileDescriptor)
                        try {
                            while (packetIoRunning) {
                                val inbound = pollInboundPacket()
                                if (inbound == null || inbound.isEmpty()) {
                                    // If nothing was available, sleep briefly to avoid busy-spinning.
                                    Thread.sleep(INBOUND_IDLE_SLEEP_MS)
                                    continue
                                }

                                output.write(inbound)
                                output.flush()
                            }
                        } catch (_: InterruptedException) {
                            // Normal shutdown signal.
                        } catch (e: Exception) {
                            android.util.Log.e(
                                    "BondedVPN",
                                    "VPN inbound drain exception: ${e.message}",
                                    e
                            )
                            if (packetIoRunning) {
                                emitEvent("error", "VPN inbound drain stopped: ${e.message}")
                            }
                        } finally {
                            try {
                                output.close()
                            } catch (_: Exception) {}
                        }
                    }
        }
    }

    private fun stopPacketIoLoop() {
        packetIoRunning = false
        packetIoThread?.interrupt()
        packetIoThread = null
        inboundDrainThread?.interrupt()
        inboundDrainThread = null
        try {
            nativeSetTunFd(-1)
        } catch (_: UnsatisfiedLinkError) {}
        nativeTunFdWriteAvailable = false
    }

    private fun startSessionMonitorIfNeeded() {
        if (sessionMonitorThread?.isAlive == true) {
            return
        }

        sessionMonitorRunning = true
        sessionMonitorThread =
                thread(name = "bonded-session-monitor", start = true) {
                    var monitorTick = 0L
                    while (sessionMonitorRunning) {
                        val snapshot = getNativeSessionSnapshot()
                        if (snapshot != null) {
                            updateSessionSnapshot(snapshot)
                            monitorTick += 1
                            if (monitorTick % 5L == 0L) {
                                android.util.Log.i(
                                        "BondedVPN",
                                        "Native snapshot: state=${snapshot.state}, outbound=${snapshot.outboundPackets}/${snapshot.outboundBytes}B, inbound=${snapshot.inboundPackets}/${snapshot.inboundBytes}B, lastError=${snapshot.lastError}",
                                )
                            }
                        }

                        try {
                            Thread.sleep(1000)
                        } catch (_: InterruptedException) {
                            return@thread
                        }
                    }
                }
    }

    private fun stopSessionMonitor() {
        sessionMonitorRunning = false
        sessionMonitorThread?.interrupt()
        sessionMonitorThread = null
        updateSessionSnapshot(null)
        lastEmittedSessionState = null
    }

    private fun getNativeSessionSnapshot(): SessionSnapshot? {
        return try {
            nativeGetSessionSnapshot()?.let(::parseSessionSnapshot)
        } catch (_: UnsatisfiedLinkError) {
            null
        } catch (e: Exception) {
            emitEvent("error", "Failed to read native session status: ${e.message}")
            null
        }
    }

    private fun parseSessionSnapshot(raw: String): SessionSnapshot? {
        return try {
            val json = JSONObject(raw)
            SessionSnapshot(
                    state = json.optString("state", "unknown"),
                    serverAddress = json.optString("serverAddress", ""),
                    activeTransport = json.optString("activeTransport", "Unknown"),
                    transportCount = json.optInt("transportCount", 0),
                    peerRelayCount = json.optInt("peerRelayCount", 0),
                    outboundPackets = json.optLong("outboundPackets", 0),
                    inboundPackets = json.optLong("inboundPackets", 0),
                    outboundBytes = json.optLong("outboundBytes", 0),
                    inboundBytes = json.optLong("inboundBytes", 0),
                    connectedAtMs = json.optLong("connectedAtMs", 0),
                    lastError =
                            json.optString("lastError").takeIf { it.isNotBlank() && it != "null" },
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun updateSessionSnapshot(snapshot: SessionSnapshot?) {
        setSessionSnapshot(snapshot)
        val state = snapshot?.state ?: return

        // Emit state-change events only on transitions to avoid spam.
        if (state != lastEmittedSessionState) {
            lastEmittedSessionState = state
            when (state) {
                "connected" -> {
                    sessionRecoveryInProgress = false
                    emitEvent("session_status", "Session connected")
                }
                "connecting" -> emitEvent("session_status", "Connecting to server")
                "error" -> emitEvent("error", snapshot.lastError ?: "Native session error")
                "stopped" -> emitEvent("session_status", "Session stopped")
            }
        }

        // Attempt recovery every poll cycle while in error, not just on first transition.
        // Without this, a fast-failing recovery (state stays at "error") silently stops
        // retrying because the subsequent identical state is ignored by the transition check.
        if (state == "error") {
            attemptSessionRecovery(snapshot.lastError)
        }
    }

    private fun attemptSessionRecovery(lastError: String?) {
        if (shutdownInProgress) {
            return
        }

        if (sessionStartupInProgress || networkRebindInProgress || sessionRecoveryInProgress) {
            return
        }

        val nowMs = System.currentTimeMillis()
        if ((nowMs - lastRecoveryAttemptMs) < RECOVERY_COOLDOWN_MS) {
            return
        }

        val deviceId = activeDeviceId ?: return
        val server = PairedServerStore.findById(this, deviceId) ?: return
        val manager = networkPathManager ?: return
        val pathCount = manager.activePathCount()
        val bindAddresses = manager.activeBindAddresses()

        sessionRecoveryInProgress = true
        lastRecoveryAttemptMs = nowMs
        thread(name = "bonded-session-recovery", start = true) {
            if (shutdownInProgress) {
                sessionRecoveryInProgress = false
                return@thread
            }

            android.util.Log.w(
                    "BondedVPN",
                    "Attempting native session recovery after error: ${lastError ?: "unknown"}",
            )

            stopNativeSession()
            val restarted = startNativeSession(server, pathCount, bindAddresses)
            if (restarted) {
                emitEvent("session_status", "Native session recovered")
                android.util.Log.i("BondedVPN", "Native session recovery succeeded")
            } else {
                emitEvent("error", "Native session recovery failed")
                android.util.Log.e("BondedVPN", "Native session recovery failed")
            }

            sessionRecoveryInProgress = false
        }
    }

    private fun processOutboundPacket(buffer: ByteArray, length: Int) {
        val packet = buffer.copyOf(length)

        if (!nativeProcessingAvailable) {
            if (!nativeAvailabilityReported) {
                emitEvent("packet_io", "Native packet processing unavailable; packets are dropped")
                nativeAvailabilityReported = true
            }
            return
        }

        try {
            flushPendingOutboundPackets(MAX_PENDING_FLUSH_PER_CYCLE)
            val queued = tryQueueOutboundPacket(packet)
            if (!queued) {
                enqueuePendingOutboundPacket(packet)
                android.util.Log.w(
                        "BondedVPN",
                        "Native queue unavailable; buffered outbound packet (packet type: ${describePacket(packet)}, pending=${pendingOutboundSize()})",
                )
            }
        } catch (_: UnsatisfiedLinkError) {
            nativeProcessingAvailable = false
            android.util.Log.e(
                    "BondedVPN",
                    "Native packet symbols unavailable; packets are dropped"
            )
            emitEvent("packet_io", "Native packet symbols unavailable; packets are dropped")
        } catch (e: Exception) {
            android.util.Log.e("BondedVPN", "Native packet processing failed: ${e.message}", e)
            emitEvent("error", "Native packet processing failed: ${e.message}")
        }
    }

    private fun pollInboundPacket(): ByteArray? {
        if (!nativeProcessingAvailable) {
            return null
        }

        return try {
            val packet = nativePollTunInbound()
            packet
        } catch (_: UnsatisfiedLinkError) {
            nativeProcessingAvailable = false
            android.util.Log.e("BondedVPN", "Native inbound polling unavailable")
            emitEvent("packet_io", "Native inbound polling unavailable")
            null
        } catch (e: Exception) {
            android.util.Log.e("BondedVPN", "Native inbound polling failed: ${e.message}", e)
            emitEvent("error", "Native inbound polling failed: ${e.message}")
            null
        }
    }

    private fun configureNativeTunFd(pfd: ParcelFileDescriptor): Boolean {
        return try {
            val result = nativeSetTunFd(pfd.fd)
            if (!result) {
                emitEvent("packet_io", "Native TUN fd handoff failed; using polling fallback")
            }
            result
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (e: Exception) {
            android.util.Log.e("BondedVPN", "Native TUN fd handoff failed: ${e.message}", e)
            emitEvent("packet_io", "Native TUN fd handoff failed: ${e.message}")
            false
        }
    }

    private fun describePacket(packet: ByteArray): String {
        if (packet.isEmpty()) return "empty"
        if (packet.size < 1) return "too-short"

        val version = (packet[0].toInt() shr 4) and 0x0F
        if (version == 4 && packet.size >= 20) {
            val protocol = packet[9].toInt() and 0xFF
            val src =
                    "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}.${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
            val dst =
                    "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}.${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"
            return "IPv4(proto=$protocol,$src->$dst)"
        } else if (version == 6) {
            return "IPv6"
        }

        return "unknown(v=$version)"
    }

    private external fun nativeHandleTunOutbound(packet: ByteArray): Boolean

    private external fun nativeSetTunFd(fd: Int): Boolean

    private external fun nativePollTunInbound(): ByteArray?

    private external fun nativeGetSessionSnapshot(): String?

    private external fun nativeStartSession(
            serverAddress: String,
            resolvedServerAddress: String,
            serverIdentityPublicKey: String,
            protocolCsv: String,
            pathCount: Int,
            bindAddressesJson: String,
            peerShareEnabled: Boolean,
            peerShareBindAddress: String,
            peerShareAdvertiseIp: String,
            peerShareMaxConsumers: Int,
            peerShareRelayBandwidthKbps: Long,
            storageDir: String,
    ): Boolean

    private external fun nativeStopSession()

    // Resolve a "host:port" address to "ip:port" using system DNS, before the VPN is
    // active. Returns the original string unchanged on any error or if already an IP.
    private fun resolveServerAddressEarly(rawAddress: String): String {
        android.util.Log.i("BondedVPN", "resolveServerAddressEarly() called with: $rawAddress")
        val lastColon = rawAddress.lastIndexOf(':')
        if (lastColon < 0) {
            android.util.Log.w("BondedVPN", "No colon found in address, returning as-is")
            return rawAddress
        }
        val host = rawAddress.substring(0, lastColon)
        val port = rawAddress.substring(lastColon + 1)
        android.util.Log.d("BondedVPN", "Extracted host=$host, port=$port")
        // Already an IPv4 literal — no resolution needed.
        if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
            android.util.Log.d("BondedVPN", "Host is already IPv4 literal, no resolution needed")
            return rawAddress
        }
        // IPv6 literal in brackets (e.g. "[::1]") — no resolution needed.
        if (host.startsWith('[')) {
            android.util.Log.d("BondedVPN", "Host is IPv6 literal, no resolution needed")
            return rawAddress
        }
        return try {
            android.util.Log.d(
                    "BondedVPN",
                    "Attempting DNS resolution for host: $host (this may take a moment)"
            )
            // Run DNS lookup on a background thread to avoid ANR and ensure it completes
            // even if the main thread has other work. Use a timeout to fail gracefully.
            var result = rawAddress
            val resolved =
                    try {
                        // Try to resolve with a short timeout
                        val futureHost =
                                java.util.concurrent.FutureTask {
                                    try {
                                        android.util.Log.d(
                                                "BondedVPN",
                                                "FutureTask: calling InetAddress.getAllByName($host)"
                                        )
                                        InetAddress.getAllByName(host)
                                    } catch (e: Exception) {
                                        android.util.Log.w(
                                                "BondedVPN",
                                                "FutureTask: InetAddress.getAllByName failed: ${e.message}"
                                        )
                                        throw e
                                    }
                                }
                        val thread = Thread(futureHost, "bonded-dns-resolve")
                        thread.start()
                        try {
                            // Wait up to 5 seconds for DNS resolution
                            val addresses = futureHost.get(5, java.util.concurrent.TimeUnit.SECONDS)
                            android.util.Log.d(
                                    "BondedVPN",
                                    "Resolved to ${addresses.size} address(es)"
                            )
                            addresses.forEach { addr ->
                                android.util.Log.d(
                                        "BondedVPN",
                                        "  - ${addr.javaClass.simpleName}: ${addr.hostAddress}"
                                )
                            }
                            addresses.filterIsInstance<Inet4Address>().firstOrNull()
                                    ?: addresses.firstOrNull()
                        } catch (e: java.util.concurrent.TimeoutException) {
                            android.util.Log.w(
                                    "BondedVPN",
                                    "DNS resolution timed out after 5 seconds for $host"
                            )
                            null
                        }
                    } catch (e: Exception) {
                        android.util.Log.w("BondedVPN", "Failed to resolve $host: ${e.message}", e)
                        null
                    }

            if (resolved != null && resolved.hostAddress != null) {
                result = "${resolved.hostAddress}:$port"
                android.util.Log.i("BondedVPN", "Pre-resolved $host -> $result")
            } else {
                android.util.Log.w(
                        "BondedVPN",
                        "Could not resolve $host, using original: $rawAddress"
                )
            }
            result
        } catch (e: Exception) {
            android.util.Log.e(
                    "BondedVPN",
                    "Unexpected error in resolveServerAddressEarly: ${e.message}",
                    e
            )
            rawAddress
        }
    }

    private fun startNativeSession(
            server: PairedServerRecord,
            pathCount: Int,
            bindAddresses: List<String>,
    ): Boolean {
        if (shutdownInProgress || vpnInterface == null) {
            android.util.Log.i(
                    "BondedVPN",
                    "Skipping native session start because VPN shutdown is in progress",
            )
            return false
        }

        return try {
            // Use the pre-resolved IP address if available so native code never needs to
            // perform DNS resolution inside an active VPN (which would route through TUN).
            val resolvedServerAddr = cachedServerAddress ?: server.publicAddress
            val protocolCsv = server.supportedProtocols.joinToString(",")
            val bindAddressesJson = JSONArray(bindAddresses).toString()
            android.util.Log.i(
                    "BondedVPN",
                    "Starting native session: server=${server.publicAddress}, resolved=$resolvedServerAddr, protocols=$protocolCsv, pathCount=$pathCount, bindAddresses=$bindAddressesJson",
            )
            val started =
                    nativeStartSession(
                            server.publicAddress,
                            resolvedServerAddr,
                            server.serverIdentityPublicKey,
                            protocolCsv,
                            pathCount,
                            bindAddressesJson,
                            server.peerShareEnabled,
                            server.peerShareBindAddress,
                            server.peerShareAdvertiseIp,
                            server.peerShareMaxConsumers,
                            server.peerShareRelayBandwidthKbps,
                            filesDir.absolutePath,
                    )
            android.util.Log.i("BondedVPN", "nativeStartSession returned: $started")
            if (started) {
                lastNetworkBindingSignature = bindAddressesJson
                flushPendingOutboundPackets(MAX_PENDING_FLUSH_ON_SESSION_START)
            }
            started
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    private fun tryQueueOutboundPacket(packet: ByteArray): Boolean {
        return nativeHandleTunOutbound(packet)
    }

    private fun enqueuePendingOutboundPacket(packet: ByteArray) {
        synchronized(pendingOutboundLock) {
            if (pendingOutboundPackets.size >= MAX_PENDING_OUTBOUND_PACKETS) {
                pendingOutboundPackets.removeFirst()
            }
            pendingOutboundPackets.addLast(packet)
        }
    }

    private fun pendingOutboundSize(): Int {
        synchronized(pendingOutboundLock) {
            return pendingOutboundPackets.size
        }
    }

    private fun flushPendingOutboundPackets(maxPackets: Int) {
        var flushed = 0
        while (flushed < maxPackets) {
            val next =
                    synchronized(pendingOutboundLock) {
                        if (pendingOutboundPackets.isEmpty()) {
                            null
                        } else {
                            pendingOutboundPackets.removeFirst()
                        }
                    }
                            ?: return

            if (!tryQueueOutboundPacket(next)) {
                synchronized(pendingOutboundLock) { pendingOutboundPackets.addFirst(next) }
                return
            }

            flushed++
        }
    }

    private fun ensureNetworkPathManager(): AndroidNetworkPathManager {
        return networkPathManager
                ?: AndroidNetworkPathManager(this) { count ->
                val manager = networkPathManager
                val bindAddresses = manager?.activeBindAddresses().orEmpty()
                val summaries = manager?.activePathSummaries().orEmpty()
                    setActiveNetworkPathCount(count)
                setActiveNetworkBindings(bindAddresses, summaries)
                emitEvent(
                    "network_paths",
                    "Active network paths: $count, bindAddresses=${JSONArray(bindAddresses).toString()}, summaries=${JSONArray(summaries).toString()}"
                )
                    handleNetworkPathChange(count)
                }
                        .also { manager -> networkPathManager = manager }
    }

    private fun handleNetworkPathChange(count: Int) {
        if (shutdownInProgress) {
            return
        }

        if (sessionStartupInProgress || networkRebindInProgress) {
            return
        }

        val deviceId = activeDeviceId ?: return
        val manager = networkPathManager ?: return
        val bindAddresses = manager.activeBindAddresses()
        val pathSummaries = manager.activePathSummaries()
        setActiveNetworkBindings(bindAddresses, pathSummaries)
        val bindingSignature = JSONArray(bindAddresses).toString()
        if (bindingSignature == lastNetworkBindingSignature) {
            return
        }

        val server = PairedServerStore.findById(this, deviceId) ?: return
        networkRebindInProgress = true
        thread(name = "bonded-network-path-restart", start = true) {
            if (shutdownInProgress) {
                networkRebindInProgress = false
                return@thread
            }

            stopNativeSession()
            if (startNativeSession(server, count, bindAddresses)) {
                emitEvent(
                        "network_paths",
                        "Rebound VPN session across ${bindAddresses.size.coerceAtLeast(count)} network path(s); bindAddresses=${JSONArray(bindAddresses).toString()}, summaries=${JSONArray(pathSummaries).toString()}"
                )
            } else {
                emitEvent("error", "Failed to rebind VPN session after network change")
            }
            networkRebindInProgress = false
        }
    }

    private fun stopNativeSession() {
        try {
            nativeStopSession()
        } catch (_: UnsatisfiedLinkError) {}
    }

    // Called from Rust/JNI to protect socket FDs from VPN capture.
    @Keep
    fun protectSocketForNative(fd: Int): Boolean {
        return try {
            val protected = protect(fd)
            android.util.Log.i("BondedVPN", "protect(fd=$fd) returned $protected")
            protected
        } catch (e: Exception) {
            android.util.Log.e("BondedVPN", "protect(fd=$fd) threw ${e.message}", e)
            false
        }
    }

    @Keep
    fun bindSocketToNetworkForNative(fd: Int, bindAddress: String): Boolean {
        val manager = networkPathManager ?: return false
        return try {
            val bound = manager.bindSocketToTrackedNetwork(fd, bindAddress)
            android.util.Log.i(
                "BondedVPN",
                "bindSocketToNetworkForNative(fd=$fd, bindAddress=$bindAddress) returned $bound"
            )
            bound
        } catch (e: Exception) {
            android.util.Log.e(
                "BondedVPN",
                "bindSocketToNetworkForNative(fd=$fd, bindAddress=$bindAddress) threw ${e.message}",
                e
            )
            false
        }
    }

    companion object {
        private const val ACTION_START = "com.bonded.bonded_app.vpn.START"
        private const val ACTION_STOP = "com.bonded.bonded_app.vpn.STOP"
        private const val EXTRA_DEVICE_ID = "device_id"
        private const val EXTRA_RUN_IN_BACKGROUND = "run_in_background"
        private const val NOTIFICATION_CHANNEL_ID = "bonded_vpn_background"
        private const val NOTIFICATION_ID = 1001
        private const val INBOUND_IDLE_SLEEP_MS = 1L
        private const val MAX_PENDING_OUTBOUND_PACKETS = 256
        private const val MAX_PENDING_FLUSH_PER_CYCLE = 16
        private const val MAX_PENDING_FLUSH_ON_SESSION_START = 128
        private const val RECOVERY_COOLDOWN_MS = 5000L

        private var nativeLoaded = false

        init {
            try {
                System.loadLibrary("bonded_ffi")
                nativeLoaded = true
            } catch (_: UnsatisfiedLinkError) {
                nativeLoaded = false
            }
        }

        @Volatile private var running = false

        @Volatile private var backgroundRunning = false

        @Volatile private var activeInstance: BondedVpnService? = null

        @Volatile private var statusListener: ((String, String?) -> Unit)? = null

        @Volatile private var lastSessionSnapshot: SessionSnapshot? = null

        @Volatile private var activeNetworkPathCount: Int = 1

        @Volatile private var activeNetworkBindAddresses: List<String> = emptyList()

        @Volatile private var activeNetworkPathSummaries: List<String> = emptyList()

        fun start(context: Context, deviceId: String, runInBackground: Boolean = false) {
            val intent =
                    Intent(context, BondedVpnService::class.java)
                            .setAction(ACTION_START)
                            .putExtra(EXTRA_DEVICE_ID, deviceId)
                            .putExtra(EXTRA_RUN_IN_BACKGROUND, runInBackground)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, BondedVpnService::class.java).setAction(ACTION_STOP)
            try {
                context.startService(intent)
            } catch (_: Exception) {}
            try {
                context.stopService(Intent(context, BondedVpnService::class.java))
            } catch (_: Exception) {}
        }

        fun isRunning(): Boolean = running

        fun isBackgroundRunning(): Boolean = running && backgroundRunning

        fun protectDatagramSocketForDebug(socket: DatagramSocket): Boolean {
            val service = activeInstance ?: return false
            return try {
                val protected = service.protect(socket)
                android.util.Log.i("BondedVPN", "protect(datagramSocket) returned $protected")
                protected
            } catch (e: Exception) {
                android.util.Log.e("BondedVPN", "protect(datagramSocket) threw ${e.message}", e)
                false
            }
        }

        fun getSessionSnapshot(): Map<String, Any?>? {
            val snapshot = lastSessionSnapshot ?: return null
            return mapOf(
                    "state" to snapshot.state,
                    "serverAddress" to snapshot.serverAddress,
                    "activeTransport" to snapshot.activeTransport,
                    "transportCount" to snapshot.transportCount,
                    "peerRelayCount" to snapshot.peerRelayCount,
                    "outboundPackets" to snapshot.outboundPackets,
                    "inboundPackets" to snapshot.inboundPackets,
                    "outboundBytes" to snapshot.outboundBytes,
                    "inboundBytes" to snapshot.inboundBytes,
                    "connectedAtMs" to snapshot.connectedAtMs,
                    "lastError" to snapshot.lastError,
                    "networkPathCount" to activeNetworkPathCount,
                    "networkBindAddresses" to activeNetworkBindAddresses,
                    "networkPathSummaries" to activeNetworkPathSummaries,
            )
        }

        fun setStatusListener(listener: ((String, String?) -> Unit)?) {
            statusListener = listener
        }

        private fun setSessionSnapshot(snapshot: SessionSnapshot?) {
            lastSessionSnapshot = snapshot
        }

        private fun setActiveNetworkPathCount(count: Int) {
            activeNetworkPathCount = count
        }

        private fun setActiveNetworkBindings(bindAddresses: List<String>, summaries: List<String>) {
            activeNetworkBindAddresses = bindAddresses
            activeNetworkPathSummaries = summaries
        }

        private fun emitEvent(type: String, message: String?) {
            statusListener?.invoke(type, message)
        }
    }
}
