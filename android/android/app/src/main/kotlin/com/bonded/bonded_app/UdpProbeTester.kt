package com.bonded.bonded_app

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.PortUnreachableException
import java.net.SocketTimeoutException
import java.security.SecureRandom

/**
 * UDP-only reachability probe with a caller-supplied host/port, built to
 * localize where UDP traffic dies (phone -> NAT -> WAN -> server) without
 * involving TCP, HTTP, or the VPN session machinery.
 *
 * Each attempt sends one QUIC version-negotiation trigger datagram (a
 * long-header packet carrying a reserved "grease" version). Any QUIC
 * endpoint must answer it with a Version Negotiation packet, so the
 * possible outcomes split the fault domain cleanly:
 *
 * - Version Negotiation received: UDP path and a QUIC endpoint are fine.
 * - Some other datagram received: UDP works end to end, but whatever
 *   answered is not acting as a QUIC endpoint on that port.
 * - ICMP port unreachable: the packet reached a host that has nothing
 *   listening on that UDP port (e.g. a forward landing on the wrong
 *   machine or port).
 * - Silence: the datagram (or its reply) was dropped in transit, which
 *   is what a missing/blocked NAT forward looks like.
 *
 * Comparing a known-good QUIC endpoint (e.g. www.google.com:443) with the
 * target on the same phone and network isolates which hop is at fault.
 */
object UdpProbeTester {
    private const val attempts = 3
    private const val timeoutMs = 3000
    private val secureRandom = SecureRandom()

    fun run(
            host: String,
            port: Int,
            logI: (String) -> Unit,
            logW: (String) -> Unit,
            logE: (String, Throwable?) -> Unit,
    ) {
        if (port !in 1..65535) {
            logE("UDP probe: invalid port $port", null)
            return
        }
        val addresses =
                try {
                    InetAddress.getAllByName(host).toList()
                } catch (e: Exception) {
                    logE("UDP probe: cannot resolve $host", e)
                    return
                }
        val target = addresses.first()
        logI(
                "UDP probe -> $host:$port/udp resolved=${addresses.joinToString(", ") { it.hostAddress }} attempts=$attempts timeout=${timeoutMs}ms"
        )

        var vnSeen = false
        var otherSeen = false
        var unreachableSeen = false
        repeat(attempts) { index ->
            val attempt = index + 1
            try {
                val detail = probeOnce(target, port)
                logI("[attempt $attempt/$attempts] $detail")
                if (detail.startsWith("VERSION NEGOTIATION")) {
                    vnSeen = true
                } else {
                    otherSeen = true
                }
            } catch (e: PortUnreachableException) {
                unreachableSeen = true
                logW(
                        "[attempt $attempt/$attempts] ICMP port unreachable — a host answered, but nothing listens on UDP $port there"
                )
            } catch (e: SocketTimeoutException) {
                logW("[attempt $attempt/$attempts] no response within ${timeoutMs}ms")
            } catch (e: Exception) {
                logE("[attempt $attempt/$attempts] probe error", e)
            }
        }

        val verdict =
                when {
                    vnSeen ->
                            "QUIC endpoint reachable over UDP at $host:$port — UDP forwarding and the server are both fine."
                    otherSeen ->
                            "UDP works end to end ($host:$port answered), but the answer was not a QUIC version negotiation — whatever listens there is not a QUIC endpoint."
                    unreachableSeen ->
                            "Packets reach a host at $host, but nothing listens on UDP port $port — a forward (if any) is landing on the wrong machine or port."
                    else ->
                            "No response at all from $host:$port — UDP is being dropped in transit (e.g. no working NAT forward) or replies are dropped on the way back. Run the same probe against www.google.com port 443: it should answer."
                }
        logI("UDP probe verdict: $verdict")
    }

    private fun probeOnce(target: InetAddress, port: Int): String {
        val packet = buildVersionNegotiationTrigger()
        val buffer = ByteArray(2048)
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            socket.connect(target, port)
            val local = socket.localAddress?.hostAddress ?: "?"
            val startMs = System.currentTimeMillis()
            socket.send(DatagramPacket(packet, packet.size))
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            val elapsedMs = System.currentTimeMillis() - startMs
            return describeResponse(response, elapsedMs, local)
        }
    }

    private fun buildVersionNegotiationTrigger(): ByteArray {
        // QUIC long header: fixed bit + Initial type bits, a reserved
        // grease version (0x0a0a0a0a) that no endpoint supports, an
        // 8-byte destination connection ID, empty source ID, padded to
        // the 1200-byte QUIC minimum datagram size.
        val packet = ByteArray(1200)
        packet[0] = 0xC0.toByte()
        packet[1] = 0x0A
        packet[2] = 0x0A
        packet[3] = 0x0A
        packet[4] = 0x0A
        packet[5] = 8
        val dcid = ByteArray(8)
        secureRandom.nextBytes(dcid)
        dcid.copyInto(packet, destinationOffset = 6)
        packet[14] = 0
        return packet
    }

    private fun describeResponse(
            response: DatagramPacket,
            elapsedMs: Long,
            localAddress: String,
    ): String {
        val data = response.data
        val length = response.length
        if (length >= 5 && (data[0].toInt() and 0x80) != 0) {
            val version =
                    ((data[1].toInt() and 0xFF) shl 24) or
                            ((data[2].toInt() and 0xFF) shl 16) or
                            ((data[3].toInt() and 0xFF) shl 8) or
                            (data[4].toInt() and 0xFF)
            if (version == 0) {
                val versions = parseOfferedVersions(data, length)
                val versionsText =
                        if (versions.isEmpty()) "none listed"
                        else versions.joinToString(", ") { "0x%08x".format(it) }
                return "VERSION NEGOTIATION in ${elapsedMs}ms from ${response.address.hostAddress}:${response.port} via local $localAddress — endpoint offers QUIC versions: $versionsText"
            }
        }
        val preview =
                data.take(minOf(length, 8)).joinToString(" ") { "%02x".format(it.toInt() and 0xFF) }
        return "UDP response (not QUIC version negotiation) in ${elapsedMs}ms from ${response.address.hostAddress}:${response.port}: $length bytes [$preview]"
    }

    private fun parseOfferedVersions(data: ByteArray, length: Int): List<Int> {
        // After the 5-byte header come DCID (length-prefixed), SCID
        // (length-prefixed), then 4-byte version fields to the end.
        var offset = 5
        if (offset >= length) return emptyList()
        val dcidLen = data[offset].toInt() and 0xFF
        offset += 1 + dcidLen
        if (offset >= length) return emptyList()
        val scidLen = data[offset].toInt() and 0xFF
        offset += 1 + scidLen
        val versions = mutableListOf<Int>()
        while (offset + 4 <= length) {
            val v =
                    ((data[offset].toInt() and 0xFF) shl 24) or
                            ((data[offset + 1].toInt() and 0xFF) shl 16) or
                            ((data[offset + 2].toInt() and 0xFF) shl 8) or
                            (data[offset + 3].toInt() and 0xFF)
            versions.add(v)
            offset += 4
        }
        return versions
    }
}
