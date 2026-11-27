package com.bonded.bonded_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import androidx.annotation.Keep
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
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
        /** Bytes relayed for others, consumer -> server. */
        val relayedUpBytes: Long,
        /** Bytes relayed for others, server -> consumer. */
        val relayedDownBytes: Long,
        /** Peers this device is currently providing for (4.91):
         * one entry per served consumer with its relayed totals.
         * Empty when peer-share never provided. */
        val relayedPeers: List<RelayedPeerStat> = emptyList(),
        /** Session heartbeat PINGs sent by the native worker (all
         * paths, all ticks). Wakeup accounting for the profiler. */
        val heartbeatPingsSent: Long = 0,
        /** Path-supervisor re-dial attempts (one per due path per
         * supervisor wakeup). Wakeup accounting for the profiler. */
        val supervisorRedialAttempts: Long = 0,
        /** Relay pump tasks started / ended (one per accepted leg).
         * Wakeup accounting for the profiler. */
        val relayTasksStarted: Long = 0,
        val relayTasksEnded: Long = 0,
        val connectedAtMs: Long,
        val lastError: String?,
        val peerShareError: String? = null,
        val paths: List<SessionPathStat> = emptyList(),
        val interception: InterceptionWarning? = null,
)

/** A server-identity failure (possible interception) from the native
 * snapshot, attributed to the connection that presented bad credentials. */
data class InterceptionWarning(
        /** Path index of the offending connection; null when the failure
         * came from the pre-session identity gate. */
        val pathIndex: Int?,
        val detail: String,
        val atMs: Long,
)

/** One peer this device is serving as a peer-share provider for
 * (4.91): consumer device key + relayed byte totals (up = consumer
 * -> server, down = server -> consumer). One entry per served peer;
 * a consumer with several provider paths holds one entry with its
 * combined traffic. */
data class RelayedPeerStat(
        /** Consumer device key (base64). */
        val peerId: String,
        val upBytes: Long,
        val downBytes: Long,
)

/** Per-path stats from the native snapshot (transport-vec order). */
data class SessionPathStat(
        /** Supervisor path index; null for peer-relay transports. */
        val pathIndex: Int?,
        val kind: String,
        val active: Boolean,
        /** Debug-paused via long-press: still connected, but outbound
         * assignment treats the path as last resort. */
        val paused: Boolean = false,
        val outboundBytes: Long,
        val inboundBytes: Long,
        /** Socket-level bytes for this path (wire counters from the
         * transport, incl. QUIC/TLS framing overhead). Null when the
         * transport cannot observe them. Read by the 4.41 overhead
         * diagnostic's wire rows. */
        val wireTxBytes: Long? = null,
        val wireRxBytes: Long? = null,
        val lastRttMs: Long,
        /** "IP:port" source address the server sees for this path, or null. */
        val serverSeenAddress: String?,
        /** ASN org name the server resolved for this path's public
         * egress address (4.107), e.g. "GOOGLE - Google LLC", or
         * null when the server holds no name for the address. */
        val networkAsnOrg: String? = null,
        /** PTR hostname the server resolved for this path's public
         * egress address (4.107), or null when there is none. */
        val networkPtr: String? = null,
        /** Provider device key for peer-relay transports; null for direct transports. */
        val peerId: String? = null,
        /** QUIC PING frames sent on this path's connection (quinn
         * frame_tx.ping, cumulative). Null when the transport cannot
         * observe them (WebSocketTls); a re-dialed path restarts
         * from zero. Wakeup accounting for the profiler. */
        val quicPingFrames: Long? = null,
        /** QUIC packets lost / bytes lost / packets sent on this
         * path's connection (quinn `path.lost_packets` /
         * `path.lost_bytes` / `path.sent_packets`, cumulative). Null
         * when the transport cannot observe loss — only QUIC counts
         * it (a lost QUIC packet is retransmitted by quinn, so
         * `lost_packets` is effectively the retransmit count). Loss
         * rate = lost / sent; no rate while sent is zero. A
         * re-dialed path restarts from zero. */
        val quicLostPackets: Long? = null,
        val quicLostBytes: Long? = null,
        val quicSentPackets: Long? = null,
)

/** Parse the native snapshot's per-path stats (transport-vec order).
 * Top-level (not a [BondedVpnService] member) so the parse is
 * unit-testable (plan 4.48): the service class cannot be instantiated
 * in a local unit test, and this function only touches org.json.
 * Null JSON values become null fields; missing keys default the
 * same way (see [SessionPathStat]). */
internal fun parseSessionPaths(array: JSONArray?): List<SessionPathStat> {
    if (array == null) return emptyList()
    val paths = ArrayList<SessionPathStat>(array.length())
    for (i in 0 until array.length()) {
        val item = array.optJSONObject(i) ?: continue
        paths.add(
                SessionPathStat(
                        pathIndex =
                                if (item.isNull("pathIndex")) null
                                else item.optInt("pathIndex", -1).takeIf { it >= 0 },
                        kind = item.optString("kind", "Unknown"),
                        active = item.optBoolean("active", false),
                        paused = item.optBoolean("paused", false),
                        outboundBytes = item.optLong("outboundBytes", 0),
                        inboundBytes = item.optLong("inboundBytes", 0),
                        wireTxBytes =
                                if (item.isNull("wireTxBytes")) null
                                else item.optLong("wireTxBytes", 0),
                        wireRxBytes =
                                if (item.isNull("wireRxBytes")) null
                                else item.optLong("wireRxBytes", 0),
                        lastRttMs = item.optLong("lastRttMs", 0),
                        serverSeenAddress =
                                if (item.isNull("serverSeenAddress")) null
                                else item.optString("serverSeenAddress").takeIf { it.isNotEmpty() },
                        networkAsnOrg =
                                if (item.isNull("networkAsnOrg")) null
                                else item.optString("networkAsnOrg").takeIf { it.isNotEmpty() },
                        networkPtr =
                                if (item.isNull("networkPtr")) null
                                else item.optString("networkPtr").takeIf { it.isNotEmpty() },
                        peerId =
                                if (item.isNull("peerId")) null
                                else item.optString("peerId").takeIf { it.isNotEmpty() },
                        quicPingFrames =
                                if (item.isNull("quicPingFrames")) null
                                else item.optLong("quicPingFrames", 0),
                        quicLostPackets =
                                if (item.isNull("quicLostPackets")) null
                                else item.optLong("quicLostPackets", 0),
                        quicLostBytes =
                                if (item.isNull("quicLostBytes")) null
                                else item.optLong("quicLostBytes", 0),
                        quicSentPackets =
                                if (item.isNull("quicSentPackets")) null
                                else item.optLong("quicSentPackets", 0),
                )
        )
    }
    return paths
}

/** Parse the native snapshot's per-served-peer stats (4.91).
 * Top-level alongside [parseSessionPaths] so the parse is
 * unit-testable. Entries without a peer id are skipped; missing
 * keys default to zero. */
internal fun parseRelayedPeers(array: JSONArray?): List<RelayedPeerStat> {
    if (array == null) return emptyList()
    val peers = ArrayList<RelayedPeerStat>(array.length())
    for (i in 0 until array.length()) {
        val item = array.optJSONObject(i) ?: continue
        val peerId = item.optString("peerId").takeIf { it.isNotEmpty() } ?: continue
        peers.add(
                RelayedPeerStat(
                        peerId = peerId,
                        upBytes = item.optLong("upBytes", 0),
                        downBytes = item.optLong("downBytes", 0),
                )
        )
    }
    return peers
}

/** Serialize one per-path stat for the Dart side
 * ([BondedVpnService.getSessionSnapshot]). Top-level alongside
 * [parseSessionPaths] so the forward is unit-testable. */
internal fun sessionPathStatToMap(path: SessionPathStat): Map<String, Any?> =
        mapOf(
                "pathIndex" to path.pathIndex,
                "kind" to path.kind,
                "active" to path.active,
                "paused" to path.paused,
                "outboundBytes" to path.outboundBytes,
                "inboundBytes" to path.inboundBytes,
                "wireTxBytes" to path.wireTxBytes,
                "wireRxBytes" to path.wireRxBytes,
                "lastRttMs" to path.lastRttMs,
                "serverSeenAddress" to path.serverSeenAddress,
                "networkAsnOrg" to path.networkAsnOrg,
                "networkPtr" to path.networkPtr,
                "peerId" to path.peerId,
                "quicPingFrames" to path.quicPingFrames,
                "quicLostPackets" to path.quicLostPackets,
                "quicLostBytes" to path.quicLostBytes,
                "quicSentPackets" to path.quicSentPackets,
        )

/** Serialize one per-served-peer stat for the Dart side (4.91).
 * Top-level alongside [sessionPathStatToMap] so the forward is
 * unit-testable. */
internal fun relayedPeerStatToMap(peer: RelayedPeerStat): Map<String, Any?> =
        mapOf(
                "peerId" to peer.peerId,
                "upBytes" to peer.upBytes,
                "downBytes" to peer.downBytes,
        )

class BondedVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetIoThread: Thread? = null
    private var inboundDrainThread: Thread? = null
    private var sessionMonitorThread: Thread? = null
    private var networkPathManager: AndroidNetworkPathManager? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var peerDiscoveryWindow: PeerDiscoveryWindowScheduler? = null
    private var activeDeviceId: String? = null

    /** Battery profiler (plan 4.46): samples on the session
     * monitor's existing tick. Created in onCreate so the history
     * survives session restarts within one service lifetime. */
    private var batteryProfiler: BatteryProfiler? = null

    /** Whether peer sharing is enabled for the current session's
     * server record — the profiler's peer-sharing tag. Set at
     * session start; false when no session is running. */
    private var peerShareEnabledForSession: Boolean = false

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

    // Serializes network path-set updates: the flag check + pending
    // set (callback side) and the pending take (startup side) share
    // this lock so a change arriving during session startup is never
    // lost between the flag clear and the drain.
    private val pathUpdateLock = Any()
    @Volatile private var pendingPathUpdate: List<String>? = null

    private var lastEmittedSessionState: String? = null
    private var lastNetworkBindingSignature: String = ""
    // Server address with hostname pre-resolved to IP before VPN captures DNS traffic.
    // Cached across recovery attempts so native code never needs in-tunnel DNS resolution.
    // @Volatile: read on the recovery thread and the session-monitor thread, written on
    // the start thread and the DNS-refresh thread (4.116).
    @Volatile private var cachedServerAddress: String? = null

    // DNS refresh outside a dead tunnel (4.116): the resolved dial
    // target the live session was started with. The monitor thread
    // compares it against fresh lookups; a refresh rewrites it
    // (and the cached + persisted copies) so the next re-dial and
    // the next session (re)start both target the new IP.
    private var lastResolvedServerAddr: String? = null
    private val dnsRefreshDecider = DnsRefreshDecider()
    @Volatile private var dnsRefreshInFlight = false

    // DNS refresh outside a dead tunnel (4.116): whether this
    // service lifetime has EVER had a connected session. Latched
    // from any snapshot reporting connected, cleared only on full
    // shutdown. It must be sticky, not the snapshot's
    // `connectedAtMs`: the error/recovery path restarts the native
    // session every ~66 s while the tunnel is dead, and every
    // restart zeroes the snapshot's connectedAtMs — gating the
    // refresh on the instantaneous value blocks it forever in
    // exactly the case it exists for (found live on the 6a,
    // 2026-11-27).
    private var hasEverConnected = false

    @Volatile private var shutdownInProgress = false

    // Display interactivity for native idle pacing (4.58): the
    // peer-share browse/advertise loops slow down while the session
    // is idle with the screen off. ACTION_SCREEN_ON/OFF are not
    // delivered to manifest receivers, so this is registered on the
    // running service; the current state is pushed at every session
    // start from PowerManager. A missed push only costs pacing
    // precision, never connectivity.
    private val displayReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_ON -> pushDisplayInteractive(true)
                Intent.ACTION_SCREEN_OFF -> pushDisplayInteractive(false)
            }
        }
    }

    private fun pushDisplayInteractive(interactive: Boolean) {
        try {
            nativeSetDisplayInteractive(interactive)
        } catch (_: UnsatisfiedLinkError) {
        }
    }

    // Device idle mode (Doze) for native idle behavior (4.77):
    // the worker forces the heartbeat idle cadence, defers
    // diagnostics uploads, and pauses peer-share advertising and
    // relay attempts while dozing. ACTION_DEVICE_IDLE_MODE_CHANGED
    // fires on Doze entry/exit; the current state is pushed at
    // every session start from PowerManager, like the display
    // state above. A missed push only costs idle precision, never
    // connectivity.
    private val dozeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED) {
                val powerManager =
                        context?.getSystemService(Context.POWER_SERVICE) as? PowerManager
                pushDeviceIdleMode(powerManager?.isDeviceIdleMode ?: false)
            }
        }
    }

    private fun pushDeviceIdleMode(idle: Boolean) {
        try {
            nativeSetDeviceIdleMode(idle)
        } catch (_: UnsatisfiedLinkError) {
        }
    }

    override fun onCreate() {
        super.onCreate()
        activeInstance = this
        if (batteryProfiler == null) {
            batteryProfiler = BatteryProfiler(applicationContext)
        }
        val displayFilter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        // API 33+ requires the export flag on a dynamic receiver;
        // the screen broadcasts are system-only, so not-exported.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(displayReceiver, displayFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(displayReceiver, displayFilter)
        }
        // Doze changes are system-only too, so not-exported.
        val dozeFilter = IntentFilter().apply {
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(dozeReceiver, dozeFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(dozeReceiver, dozeFilter)
        }
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
        // Persist only genuine resolutions (an IP-literal result), never the
        // hostname fallback, so TUN-up restarts can fall back to a dialable
        // address via the record (see startNativeSession's precedence).
        val freshResolution = cachedServerAddress
        if (!freshResolution.isNullOrBlank() && freshResolution != pairedServer.publicAddress) {
            PairedServerStore.updateLastResolvedAddress(this, pairedServer.id, freshResolution)
        }

        sessionStartupInProgress = true
        val pathManager = ensureNetworkPathManager()
        val networkPathCount = pathManager.start()
        val bindAddresses = pathManager.activeBindAddresses()
        setActiveNetworkBindings(bindAddresses, pathManager.activePathSummaries())
        // Battery: the multicast lock keeps the Wi-Fi driver awake for
        // every multicast frame on the LAN, not just Bonded's. Hold it
        // only when peer sharing is actually enabled for this server —
        // peer discovery is the only thing that needs it, and the peer
        // runtime only starts when the flag is on. With peer sharing
        // off, no lock is held for the whole session. When on, the lock
        // follows the windowed schedule (10s per UTC minute + bursts +
        // sweeps) instead of being held continuously.
        if (pairedServer.peerShareEnabled) {
            startPeerDiscoveryWindow()
        }
        peerShareEnabledForSession = pairedServer.peerShareEnabled

        if (vpnInterface == null) {
            try {
                android.util.Log.d(
                        "BondedVPN",
                        "Establishing VPN interface: address=10.8.0.2/32 + fd00:10:8::2/128, mtu=1420, route=0.0.0.0/0 + ::/0"
                )
                val builder =
                        Builder()
                                .setSession("Bonded")
                                .setMtu(1420)
                                .addAddress("10.8.0.2", 32)
                                // IPv6 capture, fail-closed: an IPv6
                                // address on the TUN plus IPv6 routes, so
                                // IPv6 traffic enters the tunnel instead
                                // of bypassing the VPN on the physical
                                // network. The server does not forward
                                // IPv6 today — captured v6 packets are
                                // dropped at the server ingest gate — so
                                // captured v6 fails rather than leaks, and
                                // dual-stack clients fall back to IPv4
                                // through the tunnel. The ULA mirrors the
                                // IPv4 numbering: gateway fd00:10:8::1,
                                // this client fd00:10:8::2.
                                .addAddress("fd00:10:8::2", 128)
                if (AppSettingsStore.allowLocalTraffic(this)) {
                    // Local traffic mode: route everything EXCEPT the
                    // subnets this device is directly attached to. The
                    // physical interfaces keep their own connected routes,
                    // which win by longest-prefix match, so LAN traffic
                    // never enters the TUN. Builder has no exclusion API,
                    // hence the complement CIDR set. Routes are fixed at
                    // establish time: joining a new network needs a
                    // reconnect before its subnet is excluded.
                    val localSubnets = connectedIpv4Subnets()
                    val routes = excludeSubnets(localSubnets)
                    for (route in routes) {
                        builder.addRoute(route.toAddressString(), route.prefix)
                    }
                    // Same complement for IPv6: attached v6 subnets stay
                    // local, everything else is captured into the TUN
                    // (and dropped at the server gate, fail-closed).
                    val localV6Subnets = connectedIpv6Subnets()
                    val v6Routes = excludeIpv6Subnets(localV6Subnets)
                    for (route in v6Routes) {
                        builder.addRoute(route.toAddressString(), route.prefix)
                    }
                    android.util.Log.i(
                            "BondedVPN",
                            "Local traffic mode: ${localSubnets.size} local subnets excluded, ${routes.size} routes added; IPv6: ${localV6Subnets.size} local subnets excluded, ${v6Routes.size} routes added",
                    )
                } else {
                    builder.addRoute("0.0.0.0", 0)
                    builder.addRoute("::", 0)
                }
                // DNS goes through the tunnel to the bonded server itself,
                // which resolves with its own resolvers. No public fallback
                // is added on purpose: a fallback would leak queries around
                // the server whenever tunnel DNS is slow or down.
                builder.addDnsServer("10.8.0.1")

                // User-chosen app exclusions: these apps bypass the VPN
                // entirely. This is NOT the reverted own-package exclusion
                // above — our own package is never in this list (the
                // channel filters it out), so control-plane traffic stays
                // routable. Uninstalled packages are skipped silently.
                for (pkg in AppSettingsStore.excludedAppPackages(this)) {
                    if (pkg == packageName) continue
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (e: PackageManager.NameNotFoundException) {
                        android.util.Log.w(
                                "BondedVPN",
                                "Skipping excluded app that is not installed: $pkg",
                        )
                    }
                }

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
        drainPendingPathUpdate()

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
        try {
            unregisterReceiver(displayReceiver)
        } catch (_: IllegalArgumentException) {
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
        // Battery profiler: flush the open hour's aggregates so the
        // history survives the shutdown (raw samples are not kept).
        batteryProfiler?.persistAggregates()
        peerShareEnabledForSession = false
        networkPathManager?.stop()
        networkPathManager = null
        lastNetworkBindingSignature = ""
        sessionStartupInProgress = false
        networkRebindInProgress = false
        sessionRecoveryInProgress = false
        lastRecoveryAttemptMs = 0L
        synchronized(pendingOutboundLock) { pendingOutboundPackets.clear() }
        cachedServerAddress = null
        hasEverConnected = false
        stopPeerDiscoveryWindow()
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
                .setSmallIcon(R.drawable.ic_notification)
                .setOngoing(true)
                .build()
    }

    /**
     * Connected IPv4 subnets of the physical networks, for local-traffic
     * mode. Every attached subnet counts as local — including the
     * cellular interface's carrier range, which holds no internet
     * destinations anyway. The TUN itself is not listed yet at establish
     * time, so the tunnel's own 10.8.0.0/24 is never excluded.
     */
    private fun connectedIpv4Subnets(): List<Ipv4Cidr> {
        val manager =
                getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                        ?: return emptyList()
        val subnets = mutableListOf<Ipv4Cidr>()
        for (network in manager.allNetworks) {
            val props =
                    try {
                        manager.getLinkProperties(network)
                    } catch (_: Exception) {
                        null
                    }
                            ?: continue
            for (linkAddress in props.linkAddresses) {
                val inet = linkAddress.address
                if (inet is Inet4Address && !inet.isLoopbackAddress) {
                    subnets.add(Ipv4Cidr.fromBytes(inet.address, linkAddress.prefixLength))
                }
            }
        }
        return subnets
    }

    /**
     * IPv6 mirror of [connectedIpv4Subnets]: every attached non-loopback
     * IPv6 prefix, so local-traffic mode can exclude it from the IPv6
     * capture. The TUN itself is not listed yet at establish time, so
     * the tunnel's own fd00:10:8::/64 is never excluded.
     */
    private fun connectedIpv6Subnets(): List<Ipv6Cidr> {
        val manager =
                getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                        ?: return emptyList()
        val subnets = mutableListOf<Ipv6Cidr>()
        for (network in manager.allNetworks) {
            val props =
                    try {
                        manager.getLinkProperties(network)
                    } catch (_: Exception) {
                        null
                    }
                            ?: continue
            for (linkAddress in props.linkAddresses) {
                val inet = linkAddress.address
                if (inet is Inet6Address && !inet.isLoopbackAddress) {
                    subnets.add(Ipv6Cidr.fromBytes(inet.address, linkAddress.prefixLength))
                }
            }
        }
        return subnets
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

    private fun startPeerDiscoveryWindow() {
        val scheduler =
            peerDiscoveryWindow
                ?: PeerDiscoveryWindowScheduler(
                        acquire = { acquireMulticastLockIfNeeded() },
                        release = { releaseMulticastLock() },
                    )
                    .also { peerDiscoveryWindow = it }
        scheduler.start()
    }

    private fun stopPeerDiscoveryWindow() {
        peerDiscoveryWindow?.stop()
        peerDiscoveryWindow = null
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
                    // Poll the TUN fd before each read. The fd is
                    // non-blocking, so a bare read() returns at once
                    // when no packet is queued and this loop spins at
                    // a full core — the 2026-11-17 thread sampler
                    // caught bonded-vpn-outb at 92–93% of the app's
                    // CPU while the VPN carried ~20 MB in 11 h.
                    // Os.poll() parks the thread in the kernel until
                    // a packet is readable; the 1 s timeout bounds
                    // the shutdown latency in case the fd stays open
                    // after packetIoRunning flips. This is correct
                    // whether the fd is non-blocking or read()
                    // returns 0 spuriously: a spurious POLLIN just
                    // costs one more poll, and a read after POLLIN
                    // on a blocking fd cannot spin.
                    val pollFd = StructPollfd()
                    pollFd.fd = pfd.fileDescriptor
                    pollFd.events = OsConstants.POLLIN.toShort()
                    try {
                        while (packetIoRunning) {
                            val ready =
                                    try {
                                        Os.poll(
                                                arrayOf(pollFd),
                                                OUTBOUND_POLL_TIMEOUT_MS
                                        )
                                    } catch (e: ErrnoException) {
                                        if (e.errno == OsConstants.EINTR) {
                                            continue
                                        }
                                        android.util.Log.e(
                                                "BondedVPN",
                                                "VPN outbound poll failed: ${e.message}",
                                                e
                                        )
                                        break
                                    }
                            if (ready <= 0) {
                                // Timeout: re-check packetIoRunning.
                                continue
                            }
                            if (isTunFdDead(pollFd.revents)) {
                                android.util.Log.w(
                                        "BondedVPN",
                                        "VPN outbound poll: TUN fd closed (revents=${pollFd.revents})"
                                )
                                break
                            }
                            if ((pollFd.revents.toInt() and OsConstants.POLLIN) == 0) {
                                continue
                            }
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
            startInboundDrainThreadIfNeeded(pfd)
        }
    }

    private fun startInboundDrainThreadIfNeeded(pfd: ParcelFileDescriptor) {
        if (inboundDrainThread?.isAlive == true) {
            return
        }
        inboundDrainThread =
                thread(name = "bonded-vpn-inbound", start = true) {
                    val output = FileOutputStream(pfd.fileDescriptor)
                    // True when this thread exits because the native
                    // fd handoff took over mid-session (as opposed to
                    // shutdown). In that case the stream must NOT be
                    // closed: it wraps the live TUN fd, which the
                    // outbound thread still reads from — closing it
                    // would break the session. The ParcelFileDescriptor
                    // still owns the fd and closes it at shutdown.
                    var handoffTakeover = false
                    try {
                        while (packetIoRunning) {
                            val inbound = pollInboundPacket()
                            if (inbound == null || inbound.isEmpty()) {
                                // Queue empty. If the native fd handoff
                                // has since succeeded, new packets go
                                // straight to the TUN fd and this queue
                                // will stay empty — exit instead of
                                // spinning on the 1ms poll forever
                                // after a successful re-handoff. A
                                // later handoff failure restarts this
                                // thread via
                                // startInboundDrainThreadIfNeeded.
                                if (nativeTunFdWriteAvailable) {
                                    android.util.Log.i(
                                        "BondedVPN",
                                        "Inbound drain exiting: native TUN fd handoff active, queue drained"
                                    )
                                    handoffTakeover = true
                                    break
                                }
                                // If nothing was available, sleep briefly to avoid busy-spinning.
                                Thread.sleep(INBOUND_IDLE_SLEEP_MS)
                                continue
                            }

                            // No flush() here: FileOutputStream is
                            // unbuffered, so every write already goes
                            // straight to the fd and flush() is a
                            // no-op. Writes also cannot be batched:
                            // TUN writes are packet-atomic, so each
                            // packet needs its own write syscall.
                            output.write(inbound)
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
                        if (!handoffTakeover) {
                            try {
                                output.close()
                            } catch (_: Exception) {}
                        }
                    }
                }
    }

    // Re-run the TUN-fd handoff after a native session restart (session
    // recovery or network rebind). The TUN belongs to this service and
    // outlives individual native sessions; unless the fd is handed over
    // again, a restarted worker cannot write inbound packets directly and
    // they queue natively with nobody draining them — the recovered
    // session then looks connected but passes no downlink traffic
    // (2026-10-18). If the handoff fails, fall back to the drain thread.
    private fun rehandoffTunFdAfterSessionRestart() {
        val pfd = vpnInterface ?: return
        nativeTunFdWriteAvailable = configureNativeTunFd(pfd)
        if (!nativeTunFdWriteAvailable) {
            startInboundDrainThreadIfNeeded(pfd)
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
        // Fast cadence for the first minute after start even with no
        // UI poll yet (auto-connect on boot, tile/widget refresh),
        // then follow actual UI demand (see below).
        val monitorStartedAtMs = SystemClock.elapsedRealtime()
        sessionMonitorThread =
                thread(name = "bonded-session-monitor", start = true) {
                    var monitorTick = 0L
                    // Idle detection for the background cadence
                    // (4.58): traffic is the snapshot's inbound +
                    // outbound bytes; the screen state comes from
                    // PowerManager, read once here (the service
                    // outlives the monitor thread). While idle with
                    // the screen off the monitor sleeps 60 s instead
                    // of 30 s — the battery profiler samples on this
                    // tick, so its sample rate halves in that state
                    // (accepted: the profiler's idle segmentation
                    // already treats 60 s as the idle threshold).
                    val powerManager =
                            getSystemService(Context.POWER_SERVICE) as? PowerManager
                    var lastTrafficBytes = -1L
                    var lastTrafficAtMs = monitorStartedAtMs
                    while (sessionMonitorRunning) {
                        val snapshot = getNativeSessionSnapshot()
                        if (snapshot != null) {
                            updateSessionSnapshot(snapshot)
                            // Battery profiler (plan 4.46): sample on
                            // this existing tick — no new timers or
                            // wakeups. The profiler reads BatteryManager
                            // / PowerManager / /proc and tags the sample
                            // with the session context; a failure inside
                            // sample() degrades that sample, never this
                            // loop.
                            sampleBatteryProfile(snapshot)
                            // DNS refresh outside a dead tunnel
                            // (4.116): when every transport has been
                            // down for 3 minutes the frozen dial
                            // target is stale DNS until proven
                            // otherwise. Runs on this existing tick;
                            // the lookup itself is a background thread.
                            maybeRefreshServerDns(snapshot)
                            monitorTick += 1
                            if (monitorTick % 5L == 0L) {
                                android.util.Log.i(
                                        "BondedVPN",
                                        "Native snapshot: state=${snapshot.state}, outbound=${snapshot.outboundPackets}/${snapshot.outboundBytes}B, inbound=${snapshot.inboundPackets}/${snapshot.inboundBytes}B, lastError=${snapshot.lastError}",
                                )
                            }
                            val trafficBytes =
                                    snapshot.inboundBytes + snapshot.outboundBytes
                            if (trafficBytes != lastTrafficBytes) {
                                lastTrafficBytes = trafficBytes
                                lastTrafficAtMs = SystemClock.elapsedRealtime()
                            }
                        }

                        // Adaptive poll (battery): the snapshot is only
                        // serialized when the UI is actually asking for
                        // it. The UI polls getVpnSessionStatus every
                        // second while visible, which refreshes
                        // lastUiStatusRequestMs; with no UI demand for
                        // 5 s, back off to 30 s between serializations.
                        // State-change events (tile/widget refresh,
                        // error recovery) still fire on the next poll —
                        // up to 30 s late in the background, which is
                        // acceptable when nobody is watching. The
                        // data plane is independent of this thread.
                        // Idle with the screen off (4.58): 60 s —
                        // the first minute after start is still fast
                        // (uiActive covers it), and a screen-on or
                        // traffic restores the faster cadence on the
                        // next tick.
                        val nowMs = SystemClock.elapsedRealtime()
                        val uiActive = nowMs - lastUiStatusRequestMs < 5_000 ||
                                nowMs - monitorStartedAtMs < 60_000
                        val screenOn = powerManager?.isInteractive ?: true
                        val idle = !screenOn && nowMs - lastTrafficAtMs >= 60_000
                        try {
                            Thread.sleep(
                                    if (uiActive) 1_000
                                    else if (idle) 60_000
                                    else 30_000
                            )
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

    /** One battery-profiler sample from a fresh native snapshot.
     * Runs on the session-monitor thread, on its existing tick. */
    private fun sampleBatteryProfile(snapshot: SessionSnapshot) {
        val profiler = batteryProfiler ?: return
        try {
            profiler.sample(
                    snapshot = snapshot,
                    peerSharing = peerShareEnabledForSession,
                    batterySaver = AppSettingsStore.batterySaver(this),
                    networkSummaries = activeNetworkPathSummaries,
                    networkCallbacks =
                            networkPathManager?.callbackInvocationCount() ?: 0,
                    mdnsWindows = peerDiscoveryWindow?.windowsOpenedCount() ?: 0,
            )
        } catch (e: Exception) {
            android.util.Log.w("BondedVPN", "battery profile sample failed: ${e.message}")
        }
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
                    relayedUpBytes = json.optLong("relayedUpBytes", 0),
                    relayedDownBytes = json.optLong("relayedDownBytes", 0),
                    relayedPeers = parseRelayedPeers(json.optJSONArray("relayedPeers")),
                    heartbeatPingsSent = json.optLong("heartbeatPingsSent", 0),
                    supervisorRedialAttempts = json.optLong("supervisorRedialAttempts", 0),
                    relayTasksStarted = json.optLong("relayTasksStarted", 0),
                    relayTasksEnded = json.optLong("relayTasksEnded", 0),
                    connectedAtMs = json.optLong("connectedAtMs", 0),
                    lastError =
                            json.optString("lastError").takeIf { it.isNotBlank() && it != "null" },
                    peerShareError =
                            json.optString("peerShareError")
                                    .takeIf { it.isNotBlank() && it != "null" },
                    paths = parseSessionPaths(json.optJSONArray("paths")),
                    interception =
                            json.optJSONObject("interception")?.let { warning ->
                                InterceptionWarning(
                                        pathIndex =
                                                if (warning.isNull("pathIndex")) null
                                                else warning.optInt("pathIndex", -1)
                                                        .takeIf { it >= 0 },
                                        detail = warning.optString("detail", ""),
                                        atMs = warning.optLong("atMs", 0),
                                )
                            },
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
            // Keep the Quick Settings tile and the home-screen widget in
            // step with the session without either polling.
            try {
                BondedTileService.requestRefresh(this)
                BondedWidgetProvider.refreshAll(this)
            } catch (_: Exception) {}
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

        // A server-identity failure cannot be fixed by reconnecting: the
        // paired record's server key no longer matches the server that
        // answers. Retrying would loop forever and flap the error banner;
        // the user must re-pair. The prefix is the canonical message set by
        // the native client (server_identity_failure in bonded-client).
        if (lastError?.contains("Server identity verification failed") == true) {
            android.util.Log.e(
                    "BondedVPN",
                    "Session recovery skipped: server identity verification failed; re-pairing is required",
            )
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
                rehandoffTunFdAfterSessionRestart()
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
        if (!nativeProcessingAvailable) {
            if (!nativeAvailabilityReported) {
                emitEvent("packet_io", "Native packet processing unavailable; packets are dropped")
                nativeAvailabilityReported = true
            }
            return
        }

        try {
            flushPendingOutboundPackets(MAX_PENDING_FLUSH_PER_CYCLE)
            // Fast path: hand the shared read buffer straight to
            // native with its length — native copies synchronously
            // during the call, so no JVM copy is needed. Only the
            // pending queue needs its own copy, because it holds the
            // packet past this call while the buffer is reused for
            // the next read.
            val queued = tryQueueOutboundPacket(buffer, length)
            if (!queued) {
                val packet = buffer.copyOf(length)
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

    private external fun nativeHandleTunOutbound(packet: ByteArray, length: Int): Boolean

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
            diagnosticsUploadEnabled: Boolean,
            diagnosticsUploadPeriodSecs: Long,
            appVersionCode: Long,
            batterySaver: Boolean,
            cellularBindAddressesJson: String,
            trafficRulesJson: String,
    ): Boolean

    private external fun nativeUpdateTrafficRules(trafficRulesJson: String): Boolean

    private external fun nativeUpdatePathGrades(pathGradesJson: String): Boolean

    private external fun nativeStopSession()

    private external fun nativePausePath(pathIndex: Int, paused: Boolean): Boolean

    private external fun nativeResetPath(pathIndex: Int): Boolean

    private external fun nativeRefreshServerAddress(resolvedServerAddress: String): Boolean

    private external fun nativeSetDisplayInteractive(interactive: Boolean): Boolean
    private external fun nativeSetDeviceIdleMode(idle: Boolean): Boolean

    private external fun nativeUpdatePaths(
            bindAddressesJson: String,
            cellularBindAddressesJson: String,
    ): Boolean

    // Resolve a "host:port" address to "ip:port" using system DNS, before the VPN is
    // active. Returns the original string unchanged on any error or if already an IP.
    private fun appVersionCode(): Long {
        return try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0).versionCode.toLong()
        } catch (_: Exception) {
            0
        }
    }

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

    /** DNS refresh outside a dead tunnel (4.116). Called on the
     * session-monitor thread's existing tick; the lookup itself
     * runs on a background thread so this never blocks the tick.
     *
     * The trigger lives in [DnsRefreshDecider]: a session that
     * previously connected, with zero transports up for 3 minutes,
     * whose server address is a hostname. On a refresh decision the
     * hostname is re-resolved over a `protect()`ed socket (see
     * [lookupServerAddressOutsideTunnel]) and, when the answer
     * differs from the frozen dial target:
     * - the cached + persisted + in-memory dial targets are
     *   rewritten FIRST, so any concurrent or later session
     *   (re)start uses the fresh IP even if the live session is
     *   already gone (the worker may have exited and Kotlin's
     *   recovery loop may restart it at any moment);
     * - the live worker is handed the fresh address via
     *   [nativeRefreshServerAddress], which swaps its config and
     *   makes the path supervisor re-dial at once (multi-path
     *   sessions). A `false` return only means no session is
     *   running — the persisted address covers the next start.
     * A lookup that returns the frozen address, or fails outright,
     * changes nothing: the client keeps dialing the frozen IP. */
    private fun maybeRefreshServerDns(snapshot: SessionSnapshot) {
        // Latch ever-connected here, on the monitor tick: any
        // snapshot reporting a connected session (or a non-zero
        // connectedAtMs from the session that reached it) arms the
        // refresh for the rest of this service lifetime, across the
        // native session restarts that zero connectedAtMs.
        if (snapshot.state == "connected" || snapshot.connectedAtMs > 0L) {
            hasEverConnected = true
        }
        val decision =
                dnsRefreshDecider.evaluate(
                        transportCount = snapshot.transportCount,
                        everConnected = hasEverConnected,
                        serverAddress = snapshot.serverAddress,
                        frozenAddress = lastResolvedServerAddr,
                        nowMs = SystemClock.elapsedRealtime(),
                )
        val frozen = (decision as? DnsRefreshDecision.Refresh)?.frozenAddress ?: return
        if (dnsRefreshInFlight) {
            return
        }
        val deviceId = activeDeviceId ?: return
        dnsRefreshInFlight = true
        thread(name = "bonded-dns-refresh", start = true) {
            try {
                val fresh = lookupServerAddressOutsideTunnel(snapshot.serverAddress)
                when {
                    fresh == null -> {
                        android.util.Log.w(
                                "BondedVPN",
                                "DNS refresh: lookup failed for ${snapshot.serverAddress}; keeping frozen $frozen",
                        )
                        // The decider's cooldown already covers the
                        // next attempt; nothing else to do.
                    }
                    fresh == frozen -> {
                        android.util.Log.i(
                                "BondedVPN",
                                "DNS refresh: address unchanged ($fresh); backing off",
                        )
                        dnsRefreshDecider.noteSameAddress(SystemClock.elapsedRealtime())
                    }
                    else -> applyRefreshedAddress(fresh, frozen, deviceId)
                }
            } catch (e: Exception) {
                android.util.Log.w("BondedVPN", "DNS refresh failed: ${e.message}")
            } finally {
                dnsRefreshInFlight = false
            }
        }
    }

    /** Apply a fresh server address: rewrite the cached +
     * persisted + in-memory dial targets FIRST (so any concurrent
     * or later session (re)start uses the fresh IP even if the live
     * session is already gone), then hand it to the live worker
     * for an immediate re-dial. Shared by the monitor trigger and
     * the diagnostic forced refresh — a forced refresh is
     * indistinguishable downstream. */
    private fun applyRefreshedAddress(fresh: String, frozen: String, deviceId: String) {
        android.util.Log.i(
                "BondedVPN",
                "DNS refresh: server address $frozen -> $fresh",
        )
        cachedServerAddress = fresh
        lastResolvedServerAddr = fresh
        PairedServerStore.updateLastResolvedAddress(this, deviceId, fresh)
        val pushed =
                try {
                    nativeRefreshServerAddress(fresh)
                } catch (_: UnsatisfiedLinkError) {
                    false
                }
        android.util.Log.i(
                "BondedVPN",
                "DNS refresh: nativeRefreshServerAddress($fresh) = $pushed",
        )
        dnsRefreshDecider.noteRefreshed(SystemClock.elapsedRealtime())
        emitEvent(
                "session_status",
                "Server address refreshed to $fresh",
        )
    }

    /** Diagnostic forced refresh (4.116, adb only — see
     * `VpnControlReceiver.TEST_DNS_REFRESH`): run the refresh path
     * outside the decider, so the lookup and the mutation can be
     * exercised live without staging a dead tunnel. With [address]
     * ("ip:port") the address is pushed straight into the live
     * session (mutation test); without it the active server is
     * re-resolved over the protected socket and the answer applied
     * (lookup test). Returns false when there is no active device,
     * no frozen address to compare against, a refresh is already
     * in flight, or a supplied address is malformed (it is
     * validated here because [applyRefreshedAddress] persists
     * before the worker re-validates). */
    private fun runTestDnsRefresh(address: String?): Boolean {
        val deviceId = activeDeviceId ?: return false
        val frozen = lastResolvedServerAddr ?: return false
        if (address != null && !isValidRefreshAddress(address)) {
            android.util.Log.w(
                    "BondedVPN",
                    "DNS refresh (test): rejecting malformed address $address",
            )
            return false
        }
        if (dnsRefreshInFlight) {
            return false
        }
        dnsRefreshInFlight = true
        thread(name = "bonded-dns-refresh", start = true) {
            try {
                val fresh: String? =
                        if (address != null) {
                            address
                        } else {
                            val server =
                                    PairedServerStore.findById(this, deviceId)
                            if (server == null) {
                                android.util.Log.w(
                                        "BondedVPN",
                                        "DNS refresh (test): no paired server for $deviceId",
                                )
                                null
                            } else {
                                lookupServerAddressOutsideTunnel(server.publicAddress)
                            }
                        }
                when {
                    fresh == null -> {
                        android.util.Log.w(
                                "BondedVPN",
                                "DNS refresh (test): lookup failed; keeping frozen $frozen",
                        )
                    }
                    fresh == frozen -> {
                        android.util.Log.i(
                                "BondedVPN",
                                "DNS refresh (test): address unchanged ($fresh); backing off",
                        )
                        dnsRefreshDecider.noteSameAddress(SystemClock.elapsedRealtime())
                    }
                    else -> applyRefreshedAddress(fresh, frozen, deviceId)
                }
            } catch (e: Exception) {
                android.util.Log.w("BondedVPN", "DNS refresh (test) failed: ${e.message}")
            } finally {
                dnsRefreshInFlight = false
            }
        }
        return true
    }

    /** Re-resolve a "host:port" server address to "ip:port" using
     * DNS queries sent OUTSIDE the tunnel. Returns null on any
     * failure (nothing to resolve, no resolver answered, malformed
     * response) — the caller keeps the frozen address.
     *
     * The queries go over a `DatagramSocket` passed through
     * `VpnService.protect()` first: after the TUN comes up Android
     * routes DNS through it, and an unprotected query would hang
     * in the dead tunnel. If `protect()` refuses the socket the
     * lookup aborts outright — it never sends unprotected. Each
     * resolver gets one attempt with a 2 s timeout, at most 3
     * resolvers, so one lookup costs ~6 s worst case on its
     * background thread.
     *
     * Resolver order: the non-VPN networks' own DNS servers first
     * (from `ConnectivityManager` link properties — on home Wi-Fi
     * that is the router, which knows the LAN and the ISP's view;
     * on cellular it is the carrier's resolver), then the public
     * fallbacks 8.8.8.8 and 1.1.1.1, which answer from any network.
     * The VPN network itself is excluded: its link properties
     * carry the in-tunnel DNS (10.8.0.1), which is dead by
     * definition here. */
    private fun lookupServerAddressOutsideTunnel(rawAddress: String): String? {
        val lastColon = rawAddress.lastIndexOf(':')
        if (lastColon < 0) {
            return null
        }
        val host = rawAddress.substring(0, lastColon)
        val port = rawAddress.substring(lastColon + 1)
        if (host.isBlank() || isIpLiteralAddress(rawAddress)) {
            return null
        }
        val queryId = (SystemClock.elapsedRealtimeNanos() and 0xFFFF).toInt()
        val query = buildDnsQuery(host, queryId) ?: return null
        for (resolver in dnsResolverAddresses()) {
            val response = queryDnsOverProtectedUdp(query, resolver) ?: continue
            val address = parseDnsResponse(response, queryId) ?: continue
            val ip = address.hostAddress ?: continue
            return "$ip:$port"
        }
        return null
    }

    /** Resolver addresses for the outside-tunnel lookup, in try
     * order, capped at [DNS_REFRESH_MAX_RESOLVERS]: the
     * non-VPN networks' DNS servers (at most 2), then 8.8.8.8 and
     * 1.1.1.1. An IP literal never needs a lookup, so `getByName`
     * on the fallbacks cannot do DNS itself. */
    private fun dnsResolverAddresses(): List<InetAddress> {
        val system =
                try {
                    val manager =
                            getSystemService(Context.CONNECTIVITY_SERVICE)
                                    as? ConnectivityManager
                    manager?.allNetworks
                            ?.flatMap { network ->
                                val capabilities =
                                        manager.getNetworkCapabilities(network)
                                if (capabilities?.hasTransport(
                                                NetworkCapabilities.TRANSPORT_VPN
                                        ) == true
                                ) {
                                    emptyList()
                                } else {
                                    manager.getLinkProperties(network)
                                            ?.dnsServers
                                            .orEmpty()
                                }
                            }
                            ?.distinct()
                            ?.take(2)
                } catch (_: Exception) {
                    null
                }
                        .orEmpty()
        val fallbacks =
                listOf("8.8.8.8", "1.1.1.1").mapNotNull { literal ->
                    runCatching { InetAddress.getByName(literal) }.getOrNull()
                }
        return (system + fallbacks).distinct().take(DNS_REFRESH_MAX_RESOLVERS)
    }

    /** One DNS query over a protected UDP socket: `protect()` the
     * socket before sending (abort and return null if it refuses),
     * send the query, wait at most [DNS_REFRESH_ATTEMPT_TIMEOUT_MS]
     * for the reply. Returns the raw response bytes, or null on any
     * failure (protect refused, send failed, timeout, truncated). */
    private fun queryDnsOverProtectedUdp(
            query: ByteArray,
            resolver: InetAddress,
    ): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            socket.soTimeout = DNS_REFRESH_ATTEMPT_TIMEOUT_MS
            if (!protect(socket)) {
                android.util.Log.w(
                        "BondedVPN",
                        "DNS refresh: protect() refused the DNS socket; aborting lookup",
                )
                return null
            }
            socket.send(DatagramPacket(query, query.size, resolver, 53))
            val buffer = ByteArray(512)
            val reply = DatagramPacket(buffer, buffer.size)
            socket.receive(reply)
            reply.data.copyOf(reply.length)
        } catch (e: Exception) {
            android.util.Log.d(
                    "BondedVPN",
                    "DNS refresh: query to $resolver failed: ${e.message}",
            )
            null
        } finally {
            socket?.close()
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
            // Use a pre-resolved IP address if available so native code never needs to
            // perform DNS resolution inside an active VPN (which would route through TUN).
            // Precedence: this start's fresh early resolution; then the record's
            // persisted last-good resolution (the only source available to restarts
            // that run while the TUN is up — recovery, network rebind, debug starts —
            // where DNS is unreachable); then the raw configured address.
            // (2026-10-17: restarts that skipped early resolution handed the native
            // worker the bare hostname with the TUN up; every protocol attempt then
            // timed out and the session could never recover on its own.)
            val freshCachedAddress = cachedServerAddress
            val resolvedServerAddr =
                    when {
                        !freshCachedAddress.isNullOrBlank() &&
                                freshCachedAddress != server.publicAddress -> freshCachedAddress
                        server.lastResolvedAddress.isNotBlank() -> server.lastResolvedAddress
                        else -> freshCachedAddress ?: server.publicAddress
                    }
            // DNS refresh (4.116): remember the dial target this
            // start uses, so the monitor thread can compare it
            // against fresh lookups and spot a moved record.
            lastResolvedServerAddr = resolvedServerAddr
            val protocolCsv = server.supportedProtocols.joinToString(",")
            val bindAddressesJson = JSONArray(bindAddresses).toString()
            android.util.Log.i(
                    "BondedVPN",
                    "Starting native session: server=${server.publicAddress}, id=${server.id}, peerShareEnabled=${server.peerShareEnabled}, diagnosticsUploadEnabled=${server.diagnosticsUploadEnabled}, diagnosticsUploadPeriodSecs=${server.diagnosticsUploadPeriodSecs}, resolved=$resolvedServerAddr, protocols=$protocolCsv, pathCount=$pathCount, bindAddresses=$bindAddressesJson",
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
                            server.diagnosticsUploadEnabled,
                            server.diagnosticsUploadPeriodSecs,
                            appVersionCode(),
                            AppSettingsStore.batterySaver(this),
                            JSONArray(
                                    networkPathManager?.cellularBindAddresses()
                                            .orEmpty()
                            ).toString(),
                            AppSettingsStore.trafficRulesJson(this),
                    )
            android.util.Log.i("BondedVPN", "nativeStartSession returned: $started")
            if (started) {
                lastNetworkBindingSignature = bindAddressesJson
                // Idle pacing (4.58): the screen receiver only fires
                // on changes, so push the current state now — a
                // session (re)started with the screen already off
                // must pace from the first tick.
                val powerManager =
                        getSystemService(Context.POWER_SERVICE) as? PowerManager
                pushDisplayInteractive(powerManager?.isInteractive ?: true)
                // Doze (4.77): the receiver only fires on changes,
                // so push the current state now — a session
                // (re)started while already dozing must idle from
                // the first tick. isDeviceIdleMode is API 23+; below
                // that the device never dozes, so there is nothing
                // to push (the receiver's broadcast does not exist
                // there either).
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    pushDeviceIdleMode(powerManager?.isDeviceIdleMode ?: false)
                }
                flushPendingOutboundPackets(MAX_PENDING_FLUSH_ON_SESSION_START)
            }
            started
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    private fun tryQueueOutboundPacket(packet: ByteArray, length: Int): Boolean {
        return nativeHandleTunOutbound(packet, length)
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

            if (!tryQueueOutboundPacket(next, next.size)) {
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

        val deviceId = activeDeviceId ?: return
        val manager = networkPathManager ?: return
        // A path change is a new LAN: give peer discovery a 30s
        // continuous burst so a peer on the new network is found
        // without waiting for the next window. No-op when the window
        // scheduler is not running (peer sharing off).
        peerDiscoveryWindow?.burst()
        // Re-read the current list inside the lock (never the
        // callback's snapshot): rapid callbacks serialize here, and
        // the last one to run always sends the freshest list, so the
        // worker's final state matches reality even if callbacks
        // arrived out of order.
        synchronized(pathUpdateLock) {
            val bindAddresses = manager.activeBindAddresses()
            val pathSummaries = manager.activePathSummaries()
            setActiveNetworkBindings(bindAddresses, pathSummaries)
            val bindingSignature = JSONArray(bindAddresses).toString()
            if (bindingSignature == lastNetworkBindingSignature) {
                return
            }
            if (sessionStartupInProgress) {
                // The worker isn't listening yet; park the change
                // for the drain that runs when startup completes.
                pendingPathUpdate = bindAddresses
                return
            }
            // Surgical update first: the live worker adds/removes
            // only the changed paths, keeping surviving transports
            // (e.g. the cellular QUIC connection when Wi-Fi dies)
            // exactly as they are — no session restart, no TUN
            // re-handoff.
            if (updatePaths(bindAddresses)) {
                lastNetworkBindingSignature = bindingSignature
                emitEvent(
                        "network_paths",
                        "Updated VPN paths; bindAddresses=${JSONArray(bindAddresses).toString()}, summaries=${JSONArray(pathSummaries).toString()}"
                )
                return
            }
            // No live worker to update (or its channel is closed):
            // fall back to the full stop/start rebind.
            if (networkRebindInProgress) {
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
                    rehandoffTunFdAfterSessionRestart()
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
    }

    /** Applies a path-set change parked during session startup, if
     * it still differs from what startup just bound. Called right
     * after `sessionStartupInProgress` clears, so a callback racing
     * the drain either parked its change (found here) or took the
     * normal update path (flag already clear). */
    private fun drainPendingPathUpdate() {
        val pending = synchronized(pathUpdateLock) {
            pendingPathUpdate.also { pendingPathUpdate = null }
        } ?: return
        val signature = JSONArray(pending).toString()
        if (signature == lastNetworkBindingSignature) {
            return
        }
        if (updatePaths(pending)) {
            lastNetworkBindingSignature = signature
            emitEvent(
                    "network_paths",
                    "Updated VPN paths after startup; bindAddresses=$signature"
            )
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
        private const val OUTBOUND_POLL_TIMEOUT_MS = 1000
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

        // Monotonic timestamp (ms) of the last time the Flutter UI asked
        // for the session snapshot via getSessionSnapshot(). The session
        // monitor thread reads this as its foreground signal: it polls
        // the native snapshot every second while the UI is asking, and
        // backs off to 30 s when the UI has been quiet for 5 s.
        @Volatile private var lastUiStatusRequestMs: Long = 0

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

        /** Debug path control (long-press on a path row). False when
         * no service instance or no session is running. */
        fun pausePath(pathIndex: Int, paused: Boolean): Boolean {
            val service = activeInstance ?: return false
            return try {
                service.nativePausePath(pathIndex, paused)
            } catch (_: Exception) {
                false
            }
        }

        fun resetPath(pathIndex: Int): Boolean {
            val service = activeInstance ?: return false
            return try {
                service.nativeResetPath(pathIndex)
            } catch (_: Exception) {
                false
            }
        }

        /** Diagnostic forced DNS refresh (4.116, adb only): push
         * [address] ("ip:port") straight into the live session, or
         * re-resolve the active server over the protected socket
         * when null. False when no service instance or session is
         * running, a refresh is already in flight, or a supplied
         * address is malformed. */
        fun testDnsRefresh(address: String?): Boolean {
            val service = activeInstance ?: return false
            return try {
                service.runTestDnsRefresh(address)
            } catch (_: Exception) {
                false
            }
        }

        /** Surgical path-set update (an interface appeared or
         * vanished). False when no service instance or no session
         * is running — the caller falls back to a full restart. */
        fun updatePaths(bindAddresses: List<String>): Boolean {
            val service = activeInstance ?: return false
            return try {
                service.nativeUpdatePaths(
                        JSONArray(bindAddresses).toString(),
                        JSONArray(
                                service.networkPathManager?.cellularBindAddresses()
                                        .orEmpty()
                        ).toString(),
                )
            } catch (_: Exception) {
                false
            }
        }

        /** Live traffic-rules update (4.51): hands the running Rust
         * session a new rule table without restarting it. False when
         * no service instance is running — the stored table applies
         * on next connect. */
        fun updateTrafficRules(trafficRulesJson: String): Boolean {
            val service = activeInstance ?: return false
            return try {
                service.nativeUpdateTrafficRules(trafficRulesJson)
            } catch (_: Exception) {
                false
            }
        }

        /** Live per-transport grades update (4.52): hands the running
         * Rust session the Dart grader's current grades (JSON array,
         * one entry per transport vec index, null when a path has no
         * grade yet) without restarting it. False when no service
         * instance is running — the worker then ranks best transport
         * on RTT/loss until the next push. The Kotlin side is a
         * string passthrough, like the rule table: it never parses
         * the JSON. */
        fun updatePathGrades(pathGradesJson: String): Boolean {
            val service = activeInstance ?: return false
            return try {
                service.nativeUpdatePathGrades(pathGradesJson)
            } catch (_: Exception) {
                false
            }
        }

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
            // Record the demand even when no snapshot exists yet: the
            // UI is asking, so the monitor must stay on fast cadence.
            lastUiStatusRequestMs = SystemClock.elapsedRealtime()
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
                    "relayedUpBytes" to snapshot.relayedUpBytes,
                    "relayedDownBytes" to snapshot.relayedDownBytes,
                    "relayedPeers" to snapshot.relayedPeers.map(::relayedPeerStatToMap),
                    "heartbeatPingsSent" to snapshot.heartbeatPingsSent,
                    "relayTasksStarted" to snapshot.relayTasksStarted,
                    "relayTasksEnded" to snapshot.relayTasksEnded,
                    "connectedAtMs" to snapshot.connectedAtMs,
                    "lastError" to snapshot.lastError,
                    "peerShareError" to snapshot.peerShareError,
                    "interception" to
                            snapshot.interception?.let { warning ->
                                mapOf<String, Any?>(
                                        "pathIndex" to warning.pathIndex,
                                        "detail" to warning.detail,
                                        "atMs" to warning.atMs,
                                )
                            },
                    "networkPathCount" to activeNetworkPathCount,
                    "networkBindAddresses" to activeNetworkBindAddresses,
                    "networkPathSummaries" to activeNetworkPathSummaries,
                    "paths" to snapshot.paths.map(::sessionPathStatToMap),
            )
        }

        /** Battery profile for the Diagnostics screen (plan 4.46).
         * Live rates + persisted aggregates while the service runs;
         * aggregates only (from the persisted file) when it does not.
         * Null only when there is no data at all yet. */
        fun getBatteryProfile(context: Context): Map<String, Any?>? {
            val service = activeInstance
            if (service != null) {
                return service.batteryProfiler?.profileForUi()
            }
            val aggregates = BatteryProfiler.loadPersistedAggregates(context)
            if (aggregates.isEmpty()) return null
            return mapOf(
                    "live" to false,
                    "chargeCounterAvailable" to null,
                    "windowMs" to BatteryProfileMath.HOUR_MS,
                    "windowSamples" to 0,
                    "windowStartMs" to null,
                    "mahPerHour" to null,
                    "cpuMsPerHour" to null,
                    "wakeupsPerHour" to null,
                    "currentUa" to null,
                    "capacityPct" to null,
                    "segments" to emptyMap<String, Double?>(),
                    "segmentSamples" to emptyMap<String, Int>(),
                    "totalSamples" to 0,
                    "aggregates" to
                            aggregates.map { agg ->
                                mapOf<String, Any?>(
                                        "hourStartMs" to agg.hourStartMs,
                                        "samples" to agg.sampleCount,
                                        "mahPerHour" to agg.mahPerHour,
                                        "cpuMsPerHour" to agg.cpuMsPerHour,
                                        "wakeupsPerHour" to agg.wakeupsPerHour,
                                        "segments" to agg.segments,
                                )
                            },
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

// Poll revents classification for the outbound TUN loop (4.78):
// POLLERR / POLLHUP / POLLNVAL mean the TUN fd is dead and the
// loop must exit; anything else (POLLIN, or 0 on a spurious wake)
// means the fd is still alive. The dead mask is a parameter
// because the unit-test android.jar stubs OsConstants fields to 0 —
// production passes the default (real OsConstants on device) and
// the test passes the literal Linux poll(2) mask.
internal fun isTunFdDead(
        revents: Short,
        deadMask: Int = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
): Boolean {
    return (revents.toInt() and deadMask) != 0
}
