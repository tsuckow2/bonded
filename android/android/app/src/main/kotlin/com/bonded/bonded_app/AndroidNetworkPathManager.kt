package com.bonded.bonded_app

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.InetSocketAddress
import java.net.Socket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

data class NetworkPathBinding(
        val transport: Int,
        val bindAddress: String?,
        // Suspension state: Android/telephony has parked this network's
        // data (typical for cellular while wifi is the validated default).
        // It still advertises INTERNET and keeps its addresses, so without
        // this flag it looks exactly like a usable path while its packets
        // go nowhere. (Exposed by Android only in negative form, as the
        // absence of NET_CAPABILITY_NOT_SUSPENDED.) Suspended paths stay
        // tracked — so the state flip back is observed — but are not
        // advertised as dialable.
        val suspended: Boolean = false,
        // NET_CAPABILITY_VALIDATED at last resolution; recorded for
        // diagnostics (summaries/logs), not a dialability gate: validation
        // flaps during every network join and gating on it would churn the
        // session.
        val validated: Boolean = true,
)

class AndroidNetworkPathManager(
        context: Context,
        private val onPathCountChanged: (Int) -> Unit,
) {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)

    private val trackedNetworks = linkedMapOf<Network, NetworkPathBinding>()
    private val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private var running = false

    fun start(): Int {
        if (connectivityManager == null) {
            onPathCountChanged(1)
            return 1
        }

        if (!running) {
            running = true
            refreshTrackedNetworks()
            registerTransportRequest(NetworkCapabilities.TRANSPORT_WIFI)
            registerTransportRequest(NetworkCapabilities.TRANSPORT_CELLULAR)
            registerTransportRequest(NetworkCapabilities.TRANSPORT_ETHERNET)
            notifyPathCountChanged()
        }

        return activePathCount()
    }

    fun stop() {
        if (!running || connectivityManager == null) {
            trackedNetworks.clear()
            running = false
            return
        }

        callbacks.forEach { callback ->
            try {
                connectivityManager.unregisterNetworkCallback(callback)
            } catch (_: Exception) {}
        }
        callbacks.clear()
        trackedNetworks.clear()
        running = false
        notifyPathCountChanged()
    }

    fun activePathCount(): Int {
        // Only advertise paths we can actually bind. Otherwise Rust will try to
        // create an extra path with no bind address, which collapses back onto
        // the default network instead of using a second interface.
        return activeBindAddresses().size.coerceIn(1, 2)
    }

    fun activeBindAddresses(limit: Int = 2): List<String> {
        val dialable =
                trackedNetworks
                        .values
                        .filter { binding -> !binding.suspended }
                        .sortedBy { binding -> transportPriority(binding.transport) }
                        .mapNotNull { binding -> binding.bindAddress }
                        .distinct()
        if (dialable.isNotEmpty()) {
            return dialable.take(limit)
        }
        // Every tracked path is suspended. Advertising nothing would start
        // the session with no bind addresses at all (an unbound default-
        // network dial); a suspended path is the only candidate left, so
        // fall back to it rather than to nothing.
        return trackedNetworks
                .values
                .sortedBy { binding -> transportPriority(binding.transport) }
                .mapNotNull { binding -> binding.bindAddress }
                .distinct()
                .take(limit)
    }

    fun activePathSummaries(limit: Int = 4): List<String> {
        return trackedNetworks
                .values
                .sortedBy { binding -> transportPriority(binding.transport) }
                .map { binding ->
                    val transportName =
                            when (binding.transport) {
                                NetworkCapabilities.TRANSPORT_WIFI -> "wifi"
                                NetworkCapabilities.TRANSPORT_CELLULAR -> "cellular"
                                NetworkCapabilities.TRANSPORT_ETHERNET -> "ethernet"
                                else -> "unknown"
                            }
                    val stateMarks = buildString {
                        if (binding.suspended) append("(suspended)")
                        if (!binding.validated) append("(unvalidated)")
                    }
                    "$transportName:${binding.bindAddress ?: "<no-bind-address>"}$stateMarks"
                }
                .distinct()
                .take(limit)
    }

    // Resolve the tracked network for a bind address handed over at session
    // start. The session's snapshot address can go stale mid-session: the
    // tracked entry's picked bind address may change (CLAT interface appears,
    // IPv6 renumbering) while the snapshot address is still assigned to the
    // same network. Fall back to address ownership — the tracked network
    // whose CURRENT addresses contain the requested one — before giving up;
    // giving up leaves the socket on the default network, which silently
    // turns a "cellular" transport into a wifi one (or a failure).
    private fun findTrackedNetwork(bindAddress: String): Map.Entry<Network, NetworkPathBinding>? {
        val entries =
                trackedNetworks.entries.sortedBy { entry ->
                    transportPriority(entry.value.transport)
                }
        entries.firstOrNull { entry -> entry.value.bindAddress == bindAddress }?.let {
            return it
        }
        val owner =
                entries.firstOrNull { entry ->
                    val linkProperties =
                            connectivityManager?.getLinkProperties(entry.key)
                                    ?: return@firstOrNull false
                    collectBindAddresses(linkProperties).contains(bindAddress)
                }
        if (owner != null) {
            Log.i(
                "BondedVPN",
                "findTrackedNetwork(bindAddress=$bindAddress) resolved via current address ownership to ${owner.value.transport} (tracked bind=${owner.value.bindAddress})",
            )
        }
        return owner
    }

    fun bindSocketToTrackedNetwork(fd: Int, bindAddress: String): Boolean {
        val entry = findTrackedNetwork(bindAddress)

        if (entry == null) {
            Log.w(
                "BondedVPN",
                "bindSocketToTrackedNetwork(fd=$fd, bindAddress=$bindAddress) found no matching tracked network; tracked=${activePathSummaries(limit = 8)}",
            )
            return false
        }

        var parcelFd: ParcelFileDescriptor? = null
        return try {
            parcelFd = ParcelFileDescriptor.fromFd(fd)
            entry.key.bindSocket(parcelFd.fileDescriptor)
            parcelFd.detachFd()
            true
        } catch (e: Exception) {
            Log.e(
                "BondedVPN",
                "bindSocketToTrackedNetwork(fd=$fd, bindAddress=$bindAddress, tracked=${activePathSummaries(limit = 8)}) failed: ${e.message}",
                e,
            )
            false
        } finally {
            try {
                parcelFd?.close()
            } catch (_: Exception) {
                // Ignore cleanup failure; the raw socket fd remains owned by the caller.
            }
        }
    }

    fun connectTcpViaTrackedNetwork(
            bindAddress: String,
            targetIp: String,
            port: Int,
            timeoutMs: Int,
    ): Socket {
        val entry =
                findTrackedNetwork(bindAddress)
                        ?: error("No tracked network for bindAddress=$bindAddress; tracked=${activePathSummaries(limit = 8)}")

        return entry.key.socketFactory.createSocket().apply {
            bind(InetSocketAddress(bindAddress, 0))
            connect(InetSocketAddress(targetIp, port), timeoutMs)
        }
    }

    private fun registerTransportRequest(transportType: Int) {
        val manager = connectivityManager ?: return
        val callback =
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        trackNetwork(network)
                    }

                    override fun onCapabilitiesChanged(
                            network: Network,
                            networkCapabilities: NetworkCapabilities
                    ) {
                        trackNetwork(network, networkCapabilities)
                    }

                    override fun onLinkPropertiesChanged(
                            network: Network,
                            linkProperties: LinkProperties
                    ) {
                        // Address churn without a capability event — the
                        // CLAT interface appearing seconds after the network
                        // registers, IPv6 renumbering, an address being
                        // withdrawn — must re-resolve the bind address now,
                        // not at the next unrelated capability change.
                        trackNetwork(network)
                    }

                    override fun onLost(network: Network) {
                        trackedNetworks.remove(network)
                        notifyPathCountChanged()
                    }
                }

        val request =
                NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .addTransportType(transportType)
                        .build()

        try {
            manager.requestNetwork(request, callback)
            callbacks.add(callback)
        } catch (_: Exception) {}
    }

    private fun refreshTrackedNetworks() {
        val manager = connectivityManager ?: return
        trackedNetworks.clear()
        manager.allNetworks.forEach { network -> trackNetwork(network) }
    }

    private fun trackNetwork(network: Network, capabilities: NetworkCapabilities? = null) {
        val resolvedCapabilities =
                capabilities ?: connectivityManager?.getNetworkCapabilities(network) ?: return

        // Never path through a VPN network — including this app's own TUN
        // once it is up: its reported transports can mirror the underlying
        // network and would otherwise be classified as a second wifi path.
        if (resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                        !resolvedCapabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_INTERNET
                        )
        ) {
            if (trackedNetworks.remove(network) != null) {
                notifyPathCountChanged()
            }
            return
        }

        val transport =
                when {
                    resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                        NetworkCapabilities.TRANSPORT_WIFI
                    }
                    resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                        NetworkCapabilities.TRANSPORT_CELLULAR
                    }
                    resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> {
                        NetworkCapabilities.TRANSPORT_ETHERNET
                    }
                    else -> return
                }

        // Suspension is exposed only negatively: a suspended network lacks
        // NET_CAPABILITY_NOT_SUSPENDED (which was added in API 28).
        val suspended =
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        !resolvedCapabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED
                        )
        val validated =
                resolvedCapabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED
                )

        val binding =
                NetworkPathBinding(
                        transport = transport,
                        bindAddress = resolveBindAddress(network),
                        suspended = suspended,
                        validated = validated,
                )
        // Notify only on an actual change: capability callbacks fire for
        // many reasons that do not alter the path set, and every notify can
        // restart the session downstream. A suspension flip changes the
        // binding (and drops the address from activeBindAddresses), so it
        // still propagates as a path-set change with a restart + re-dial.
        if (trackedNetworks[network] != binding) {
            trackedNetworks[network] = binding
            notifyPathCountChanged()
        }
    }

    private fun resolveBindAddress(network: Network): String? {
        val linkProperties = connectivityManager?.getLinkProperties(network) ?: return null
        return pickBindAddress(linkProperties)
    }

    private fun pickBindAddress(linkProperties: LinkProperties): String? {
        val addresses = collectBindAddresses(linkProperties)

        return addresses.firstOrNull { !it.contains(':') } ?: addresses.firstOrNull()
    }

    private fun collectBindAddresses(linkProperties: LinkProperties): List<String> {
        val directAddresses =
                linkProperties.linkAddresses.mapNotNull { linkAddress ->
                    val address = linkAddress.address ?: return@mapNotNull null
                    when {
                        address.isLoopbackAddress ||
                                address.isLinkLocalAddress ||
                                address.isAnyLocalAddress -> null
                        address is Inet4Address -> address.hostAddress
                        address is Inet6Address ->
                                address.hostAddress
                                        ?.substringBefore('%')
                                        ?.takeUnless { it.isBlank() }
                        else -> null
                    }
                }

        val clatAddresses =
                resolveClatIpv4Addresses(linkProperties.interfaceName)

        return (directAddresses + clatAddresses).distinct()
    }

    private fun resolveClatIpv4Addresses(interfaceName: String?): List<String> {
        if (interfaceName.isNullOrBlank()) {
            return emptyList()
        }

        val clatInterface = NetworkInterface.getByName("v4-$interfaceName") ?: return emptyList()
        return clatInterface.inetAddresses.toList().mapNotNull { address ->
            when {
                address.isLoopbackAddress ||
                        address.isLinkLocalAddress ||
                        address.isAnyLocalAddress -> null
                address is Inet4Address -> address.hostAddress
                else -> null
            }
        }
    }

    private fun transportPriority(transport: Int): Int {
        return when (transport) {
            NetworkCapabilities.TRANSPORT_WIFI -> 0
            NetworkCapabilities.TRANSPORT_CELLULAR -> 1
            NetworkCapabilities.TRANSPORT_ETHERNET -> 2
            else -> 99
        }
    }

    private fun notifyPathCountChanged() {
        onPathCountChanged(activePathCount())
    }
}
