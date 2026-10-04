package com.bonded.bonded_app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedReader
import java.io.InputStreamReader
import java.time.Instant
import java.util.UUID

class MainActivity : FlutterActivity() {
    private val channelName = "bonded/native"
    private val backgroundEventsChannelName = "bonded/background-events"
    private var backgroundEventSink: EventChannel.EventSink? = null
    private var pendingVpnStartResult: MethodChannel.Result? = null
    private var pendingRunInBackground = false
    private var pendingDeviceId: String? = null

    companion object {
        private const val REQUEST_CODE_VPN_PREPARE = 2001
        private const val EXTRA_ADB_ACTION = "adb_action"
        private const val EXTRA_SERVER_ADDRESS = "server_address"
        private const val EXTRA_BOOTSTRAP_SERVER_ADDRESS = "bootstrap_server_address"
        private const val EXTRA_SERVER_PUBLIC_KEY = "server_public_key"
        private const val EXTRA_SERVER_IDENTITY_PUBLIC_KEY = "server_identity_public_key"
        private const val EXTRA_INVITE_TOKEN = "invite_token"
        private const val EXTRA_DEVICE_ID = "device_id"
        private const val EXTRA_SUPPORTED_PROTOCOLS = "supported_protocols"
        private const val EXTRA_PEER_SHARE_ENABLED = "peer_share_enabled"
        private const val EXTRA_PEER_SHARE_BIND_ADDRESS = "peer_share_bind_address"
        private const val EXTRA_PEER_SHARE_ADVERTISE_IP = "peer_share_advertise_ip"
        private var nativeLoaded = false

        init {
            try {
                System.loadLibrary("bonded_ffi")
                nativeLoaded = true
            } catch (_: UnsatisfiedLinkError) {
                nativeLoaded = false
            }
        }
    }

    private external fun nativeApiVersion(): Int
    private external fun nativeRedeemInviteToken(
            serverAddress: String,
            serverIdentityPublicKey: String,
            inviteToken: String,
            storageDir: String,
    ): Boolean

    private external fun nativeLastError(): String?

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleAdbIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAdbIntent(intent)
    }

    private fun handleAdbIntent(intent: Intent?) {
        val action = intent?.getStringExtra(EXTRA_ADB_ACTION)?.trim()?.lowercase() ?: return

        when (action) {
            "pair" -> {
                val serverAddress = intent.getStringExtra(EXTRA_SERVER_ADDRESS)?.trim().orEmpty()
                val bootstrapServerAddress =
                    intent.getStringExtra(EXTRA_BOOTSTRAP_SERVER_ADDRESS)
                        ?.trim()
                        ?.takeIf { it.isNotEmpty() }
                        ?: serverAddress
                val serverIdentityPublicKey =
                    intent.getStringExtra(EXTRA_SERVER_IDENTITY_PUBLIC_KEY)
                        ?.trim()
                        ?.takeIf { it.isNotEmpty() }
                        ?: intent.getStringExtra(EXTRA_SERVER_PUBLIC_KEY)?.trim().orEmpty()
                val inviteToken = intent.getStringExtra(EXTRA_INVITE_TOKEN)?.trim().orEmpty()
                val deviceId =
                        intent.getStringExtra(EXTRA_DEVICE_ID)?.trim()?.takeIf { it.isNotEmpty() }
                                ?: UUID.randomUUID().toString()
                val supportedProtocols =
                        intent.getStringExtra(EXTRA_SUPPORTED_PROTOCOLS)
                                ?.split(',')
                                ?.map(String::trim)
                                ?.filter(String::isNotEmpty)
                                ?: emptyList()
                val peerShareEnabled = intent.getBooleanExtra(EXTRA_PEER_SHARE_ENABLED, false)
                val peerShareBindAddress =
                    intent.getStringExtra(EXTRA_PEER_SHARE_BIND_ADDRESS)?.trim().orEmpty()
                val peerShareAdvertiseIp =
                    intent.getStringExtra(EXTRA_PEER_SHARE_ADVERTISE_IP)?.trim().orEmpty()

                if (serverAddress.isEmpty() || serverIdentityPublicKey.isEmpty() || inviteToken.isEmpty()) {
                    android.util.Log.e(
                            "BondedMain",
                            "ADB pair failed: server_address, server_public_key, and invite_token are required",
                    )
                    finish()
                    return
                }

                val redeemed =
                    redeemInviteTokenNative(serverAddress, serverIdentityPublicKey, inviteToken)
                if (!redeemed.first) {
                    android.util.Log.e(
                            "BondedMain",
                            "ADB pair failed: ${redeemed.second ?: "unknown error"}",
                    )
                    finish()
                    return
                }

        savePairedServer(
            deviceId,
            bootstrapServerAddress,
            serverIdentityPublicKey,
            supportedProtocols,
            peerShareEnabled,
            peerShareBindAddress,
            peerShareAdvertiseIp,
        )
                android.util.Log.i(
                        "BondedMain",
            "ADB pair succeeded: deviceId=$deviceId redeemServer=$serverAddress bootstrapServer=$bootstrapServerAddress protocols=$supportedProtocols peerShareEnabled=$peerShareEnabled",
                )
                finish()
            }

            else -> {
                android.util.Log.w("BondedMain", "Ignoring unknown adb_action=$action")
            }
        }
    }

    private fun redeemInviteTokenNative(
            serverAddress: String,
                serverIdentityPublicKey: String,
            inviteToken: String,
    ): Pair<Boolean, String?> {
        android.util.Log.i(
                "BondedMain",
                "Redeeming invite token via native runtime for server=$serverAddress tokenLength=${inviteToken.length}",
        )

        var failureReason: String? = null
        val redeemed =
                try {
                    nativeRedeemInviteToken(
                            serverAddress,
                            serverIdentityPublicKey,
                            inviteToken,
                            filesDir.absolutePath,
                    )
                } catch (_: UnsatisfiedLinkError) {
                    failureReason = "Native library is unavailable (UnsatisfiedLinkError)"
                    false
                } catch (t: Throwable) {
                    failureReason = "${t::class.java.simpleName}: ${t.message ?: "unknown error"}"
                    android.util.Log.e("BondedMain", "nativeRedeemInviteToken threw", t)
                    false
                }

        if (redeemed) {
            return true to null
        }

        val nativeDetail =
                try {
                    nativeLastError()
                } catch (_: Throwable) {
                    null
                }
        val message =
                if (failureReason != null) {
                    "Failed to redeem invite token via native runtime: $failureReason"
                } else if (!nativeDetail.isNullOrBlank()) {
                    "Failed to redeem invite token via native runtime: $nativeDetail"
                } else {
                    "Failed to redeem invite token via native runtime"
                }
        android.util.Log.e("BondedMain", message)
        return false to message
    }

    private fun savePairedServer(
            deviceId: String,
            publicAddress: String,
            serverIdentityPublicKey: String,
            supportedProtocols: List<String>,
            peerShareEnabled: Boolean = false,
            peerShareBindAddress: String = "",
            peerShareAdvertiseIp: String = "",
            peerShareMaxConsumers: Int = 4,
            peerShareRelayBandwidthKbps: Long = 0,
    ) {
        PairedServerStore.save(
                this,
                PairedServerRecord(
                        id = deviceId,
                        publicAddress = publicAddress,
                    serverIdentityPublicKey = serverIdentityPublicKey,
                        supportedProtocols = supportedProtocols,
                peerShareEnabled = peerShareEnabled,
                peerShareBindAddress = peerShareBindAddress,
                peerShareAdvertiseIp = peerShareAdvertiseIp,
                peerShareMaxConsumers = peerShareMaxConsumers,
                peerShareRelayBandwidthKbps = peerShareRelayBandwidthKbps,
                        pairedAt = Instant.now().toString(),
                ),
        )
    }

    private fun startVpnWithPermissionFlow(
            deviceId: String,
            runInBackground: Boolean,
            result: MethodChannel.Result,
    ) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            BondedVpnService.start(this, deviceId, runInBackground = runInBackground)
            result.success("started")
            return
        }

        if (pendingVpnStartResult != null) {
            result.error(
                    "vpn_permission_pending",
                    "VPN permission request already in progress",
                    null
            )
            return
        }

        pendingVpnStartResult = result
        pendingRunInBackground = runInBackground
        pendingDeviceId = deviceId
        startActivityForResult(prepareIntent, REQUEST_CODE_VPN_PREPARE)
    }

    private fun readClientLogs(maxLines: Int): List<String> {
        val cap = maxLines.coerceIn(50, 2000)
        return try {
            val process =
                    ProcessBuilder("logcat", "-d", "-t", cap.toString())
                            .redirectErrorStream(true)
                            .start()

            val lines = mutableListOf<String>()
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                var line: String? = reader.readLine()
                while (line != null) {
                    if (line.contains("BondedVPN") ||
                                    line.contains("bonded-ffi") ||
                                    line.contains("bonded-client") ||
                                    line.contains("Heartbeat") ||
                                    line.contains("bonded_server") ||
                                    line.contains("bonded")
                    ) {
                        lines.add(line)
                    }
                    line = reader.readLine()
                }
            }
            process.waitFor()

            if (lines.size > cap) {
                lines.takeLast(cap)
            } else {
                lines
            }
        } catch (e: Exception) {
            listOf("Failed to read client logs: ${e.message}")
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != REQUEST_CODE_VPN_PREPARE) {
            return
        }

        val pendingResult = pendingVpnStartResult
        val deviceId = pendingDeviceId
        pendingVpnStartResult = null
        pendingDeviceId = null

        if (pendingResult == null || deviceId == null) {
            return
        }

        if (resultCode == Activity.RESULT_OK) {
            BondedVpnService.start(this, deviceId, runInBackground = pendingRunInBackground)
            pendingResult.success("started")
        } else {
            pendingResult.error("permission_denied", "VPN permission denied", null)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
                .setMethodCallHandler { call, result ->
                    when (call.method) {
                        "getClientLogs" -> {
                            val args = call.arguments as? Map<*, *>
                            val maxLines = (args?.get("maxLines") as? Number)?.toInt() ?: 500
                            result.success(readClientLogs(maxLines))
                        }
                        "getNetworkTestLogs" -> {
                            result.success(NetworkTestReceiver.getBufferedLogs())
                        }
                        "clearNetworkTestLogs" -> {
                            NetworkTestReceiver.clearBufferedLogs()
                            result.success(null)
                        }
                        "runNetworkTest" -> {
                            val args = call.arguments as? Map<*, *>
                            val action = args?.get("action") as? String
                            if (action.isNullOrBlank()) {
                                result.error("invalid_args", "action is required", null)
                            } else {
                                try {
                                    val intent =
                                            Intent(this, NetworkTestForegroundService::class.java)
                                                    .setAction(
                                                            NetworkTestForegroundService.ACTION_RUN
                                                    )
                                                    .putExtra(
                                                            NetworkTestForegroundService
                                                                    .EXTRA_TEST_ACTION,
                                                            action
                                                    )
                                    (args["host"] as? String)?.let {
                                        intent.putExtra(NetworkTestForegroundService.EXTRA_HOST, it)
                                    }
                                    (args["expected_ip"] as? String)?.let {
                                        intent.putExtra(
                                                NetworkTestForegroundService.EXTRA_EXPECTED_IP,
                                                it
                                        )
                                    }
                                    (args["url"] as? String)?.let {
                                        intent.putExtra(NetworkTestForegroundService.EXTRA_URL, it)
                                    }
                                    (args["resolver"] as? String)?.let {
                                        intent.putExtra(
                                                NetworkTestForegroundService.EXTRA_RESOLVER,
                                                it
                                        )
                                    }
                                    (args["http_url"] as? String)?.let {
                                        intent.putExtra(
                                                NetworkTestForegroundService.EXTRA_HTTP_URL,
                                                it
                                        )
                                    }
                                    (args["https_url"] as? String)?.let {
                                        intent.putExtra(
                                                NetworkTestForegroundService.EXTRA_HTTPS_URL,
                                                it
                                        )
                                    }
                                    (args["http3_url"] as? String)?.let {
                                        intent.putExtra(
                                                NetworkTestForegroundService.EXTRA_HTTP3_URL,
                                                it
                                        )
                                    }
                                    (args["port"] as? Int)?.let {
                                        intent.putExtra(NetworkTestForegroundService.EXTRA_PORT, it)
                                    }
                                    (args["rounds"] as? Int)?.let {
                                        intent.putExtra(
                                                NetworkTestForegroundService.EXTRA_ROUNDS,
                                                it
                                        )
                                    }
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                                        startForegroundService(intent)
                                    } else {
                                        startService(intent)
                                    }
                                    result.success("sent")
                                } catch (e: Exception) {
                                    result.error("service_start_failed", e.message, null)
                                }
                            }
                        }
                        "getNativeApiVersion" -> {
                            if (!nativeLoaded) {
                                result.success(-1)
                                return@setMethodCallHandler
                            }

                            try {
                                result.success(nativeApiVersion())
                            } catch (_: UnsatisfiedLinkError) {
                                result.success(-1)
                            }
                        }
                        "getVpnStatus" -> {
                            result.success(BondedVpnService.isRunning())
                        }
                        "getVpnSessionStatus" -> {
                            result.success(BondedVpnService.getSessionSnapshot())
                        }
                        "startVpnService" -> {
                            val args = call.arguments as? Map<*, *>
                            val deviceId = args?.get("deviceId") as? String
                            if (deviceId.isNullOrBlank()) {
                                result.error("missing_device_id", "deviceId is required", null)
                            } else {
                                startVpnWithPermissionFlow(
                                        deviceId,
                                        runInBackground = false,
                                        result = result
                                )
                            }
                        }
                        "startBackgroundVpn" -> {
                            val args = call.arguments as? Map<*, *>
                            val deviceId = args?.get("deviceId") as? String
                            if (deviceId.isNullOrBlank()) {
                                result.error("missing_device_id", "deviceId is required", null)
                            } else {
                                startVpnWithPermissionFlow(
                                        deviceId,
                                        runInBackground = true,
                                        result = result
                                )
                            }
                        }
                        "redeemInviteToken" -> {
                            val args = call.arguments as? Map<*, *>
                            val serverAddress = args?.get("serverAddress") as? String
                            val serverIdentityPublicKey =
                                (args?.get("serverIdentityPublicKey") as? String)
                                    ?: (args?.get("serverPublicKey") as? String)
                            val inviteToken = args?.get("inviteToken") as? String

                            if (serverAddress.isNullOrBlank() ||
                                            serverIdentityPublicKey.isNullOrBlank() ||
                                            inviteToken.isNullOrBlank()
                            ) {
                                result.error(
                                        "invalid_args",
                                        "serverAddress, serverIdentityPublicKey, and inviteToken are required",
                                        null
                                )
                            } else {
                                val redeemed =
                                    redeemInviteTokenNative(
                                        serverAddress,
                                        serverIdentityPublicKey,
                                        inviteToken,
                                    )
                                if (!redeemed.first) {
                                    result.error(
                                            "pairing_failed",
                                        redeemed.second,
                                            mapOf(
                                                    "serverAddress" to serverAddress,
                                                    "tokenLength" to inviteToken.length,
                                            "nativeDetail" to nativeLastError(),
                                            ),
                                    )
                                } else {
                                    result.success(UUID.randomUUID().toString())
                                }
                            }
                        }
                        "storePairedServer" -> {
                            val args = call.arguments as? Map<*, *>
                            val deviceId = args?.get("deviceId") as? String
                            val publicAddress = args?.get("publicAddress") as? String
                            val serverIdentityPublicKey =
                                (args?.get("serverIdentityPublicKey") as? String)
                                    ?: (args?.get("serverPublicKey") as? String)
                            val supportedProtocols =
                                    (args?.get("supportedProtocols") as? List<*>)?.mapNotNull {
                                        it as? String
                                    }
                                            ?: emptyList()
                                val peerShareEnabled = args?.get("peerShareEnabled") as? Boolean ?: false
                                val peerShareBindAddress =
                                    (args?.get("peerShareBindAddress") as? String)?.trim().orEmpty()
                                val peerShareAdvertiseIp =
                                    (args?.get("peerShareAdvertiseIp") as? String)?.trim().orEmpty()
                                val peerShareMaxConsumers =
                                    (args?.get("peerShareMaxConsumers") as? Number)?.toInt() ?: 4
                                val peerShareRelayBandwidthKbps =
                                    (args?.get("peerShareRelayBandwidthKbps") as? Number)?.toLong() ?: 0

                            if (deviceId.isNullOrBlank() ||
                                            publicAddress.isNullOrBlank() ||
                                            serverIdentityPublicKey.isNullOrBlank()
                            ) {
                                result.error(
                                        "invalid_args",
                                        "deviceId, publicAddress, and serverIdentityPublicKey are required",
                                        null
                                )
                            } else {
                                    savePairedServer(
                                        deviceId,
                                        publicAddress,
                                        serverIdentityPublicKey,
                                        supportedProtocols,
                                        peerShareEnabled,
                                        peerShareBindAddress,
                                        peerShareAdvertiseIp,
                                        peerShareMaxConsumers,
                                        peerShareRelayBandwidthKbps,
                                    )
                                result.success(null)
                            }
                        }
                        "getPairedServers" -> {
                            val servers =
                                    PairedServerStore.loadAll(this).map { server ->
                                        mapOf(
                                                "id" to server.id,
                                                "publicAddress" to server.publicAddress,
                                            "serverIdentityPublicKey" to server.serverIdentityPublicKey,
                                                "serverPublicKey" to server.serverPublicKey,
                                                "supportedProtocols" to server.supportedProtocols,
                                                "peerShareEnabled" to server.peerShareEnabled,
                                                "peerShareBindAddress" to server.peerShareBindAddress,
                                                "peerShareAdvertiseIp" to server.peerShareAdvertiseIp,
                                                "peerShareMaxConsumers" to server.peerShareMaxConsumers,
                                                "peerShareRelayBandwidthKbps" to server.peerShareRelayBandwidthKbps,
                                                "pairedAt" to server.pairedAt,
                                        )
                                    }
                            result.success(servers)
                        }
                        "updatePairedServer" -> {
                            val args = call.arguments as? Map<*, *>
                            val deviceId = args?.get("deviceId") as? String
                            val publicAddress = args?.get("publicAddress") as? String
                            val serverIdentityPublicKey =
                                (args?.get("serverIdentityPublicKey") as? String)
                                    ?: (args?.get("serverPublicKey") as? String)
                            val supportedProtocols =
                                    (args?.get("supportedProtocols") as? List<*>)?.mapNotNull {
                                        it as? String
                                    }
                                            ?: emptyList()
                                val peerShareEnabled = args?.get("peerShareEnabled") as? Boolean ?: false
                                val peerShareBindAddress =
                                    (args?.get("peerShareBindAddress") as? String)?.trim().orEmpty()
                                val peerShareAdvertiseIp =
                                    (args?.get("peerShareAdvertiseIp") as? String)?.trim().orEmpty()
                                val peerShareMaxConsumers =
                                    (args?.get("peerShareMaxConsumers") as? Number)?.toInt() ?: 4
                                val peerShareRelayBandwidthKbps =
                                    (args?.get("peerShareRelayBandwidthKbps") as? Number)?.toLong() ?: 0

                            val existing = deviceId?.let { PairedServerStore.findById(this, it) }
                            if (deviceId.isNullOrBlank() ||
                                            publicAddress.isNullOrBlank() ||
                                            serverIdentityPublicKey.isNullOrBlank() ||
                                            existing == null
                            ) {
                                result.error(
                                        "invalid_args",
                                        "existing deviceId, publicAddress, and serverIdentityPublicKey are required",
                                        null
                                )
                            } else {
                                PairedServerStore.save(
                                        this,
                                        PairedServerRecord(
                                                id = deviceId,
                                                publicAddress = publicAddress,
                                            serverIdentityPublicKey = serverIdentityPublicKey,
                                                supportedProtocols = supportedProtocols,
                                            peerShareEnabled = peerShareEnabled,
                                            peerShareBindAddress = peerShareBindAddress,
                                            peerShareAdvertiseIp = peerShareAdvertiseIp,
                                            peerShareMaxConsumers = peerShareMaxConsumers,
                                            peerShareRelayBandwidthKbps = peerShareRelayBandwidthKbps,
                                                pairedAt = existing.pairedAt,
                                        ),
                                )
                                result.success(null)
                            }
                        }
                        "deletePairedServer" -> {
                            val args = call.arguments as? Map<*, *>
                            val deviceId = args?.get("deviceId") as? String
                            if (deviceId.isNullOrBlank()) {
                                result.error("invalid_args", "deviceId is required", null)
                            } else {
                                PairedServerStore.delete(this, deviceId)
                                result.success(null)
                            }
                        }
                        "stopVpnService" -> {
                            BondedVpnService.stop(this)
                            result.success("stopped")
                        }
                        "stopBackgroundVpn" -> {
                            BondedVpnService.stop(this)
                            result.success("stopped")
                        }
                        "isBackgroundVpnRunning" -> {
                            result.success(BondedVpnService.isBackgroundRunning())
                        }
                        else -> result.notImplemented()
                    }
                }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, backgroundEventsChannelName)
                .setStreamHandler(
                        object : EventChannel.StreamHandler {
                            override fun onListen(
                                    arguments: Any?,
                                    events: EventChannel.EventSink?
                            ) {
                                backgroundEventSink = events
                                BondedVpnService.setStatusListener { type, message ->
                                    runOnUiThread {
                                        backgroundEventSink?.success(
                                                mapOf(
                                                        "type" to type,
                                                        "message" to message,
                                                ),
                                        )
                                    }
                                }
                            }

                            override fun onCancel(arguments: Any?) {
                                BondedVpnService.setStatusListener(null)
                                backgroundEventSink = null
                            }
                        },
                )
    }
}
