package com.bonded.bonded_app

import java.io.ByteArrayOutputStream
import java.net.InetAddress

/** DNS refresh outside a dead tunnel (plan 4.116).
 *
 * The server hostname is resolved exactly once per service start
 * and frozen into the native session; when the DNS record moves
 * under a dead tunnel the client re-dials the stale IP forever
 * (2026-11-27: 40+ minutes of retrying, reconnected only after a
 * manual VPN_STOP + VPN_START). This file holds the pieces that
 * are unit-testable without Android: the dead-tunnel trigger /
 * debounce state machine and the hand-rolled DNS wire-format
 * query + response parser. The Android-dependent parts — the
 * protected-socket lookup and the service wiring — live in
 * [BondedVpnService].
 *
 * The lookup itself must use a `VpnService.protect()`ed socket:
 * after the TUN comes up Android routes DNS through it, and an
 * unprotected query would hang in the dead tunnel. The deadlock
 * concern from the freeze rationale does not apply here — nothing
 * flows through a dead tunnel — but the implementation proves it:
 * the socket is protected before any byte is sent, every attempt
 * is time-bounded, and any failure falls back to the frozen IP
 * (the client is never left with no address). */

/** A tunnel with no working transport must stay dead this long
 * before the client spends a DNS lookup on it. Three minutes is
 * ~3+ supervisor re-dial cycles (10→60 s backoff) and well above
 * a transient blip (a 60 s heartbeat gap, a brief network
 * switch). */
internal const val DNS_REFRESH_DEAD_TUNNEL_DEBOUNCE_MS = 180_000L

/** Minimum gap between refresh attempts for one frozen address. */
internal const val DNS_REFRESH_COOLDOWN_MS = 300_000L

/** When a lookup returns the same address the client already
 * dials, the record has not moved: back off this long before
 * spending another lookup on it. */
internal const val DNS_REFRESH_SAME_ADDRESS_BACKOFF_MS = 900_000L

/** Per-resolver UDP timeout for one DNS attempt. */
internal const val DNS_REFRESH_ATTEMPT_TIMEOUT_MS = 2_000

/** Maximum resolvers tried per lookup (system DNS first, then
 * public fallbacks). Bounds one lookup at ~6 s worst case. */
internal const val DNS_REFRESH_MAX_RESOLVERS = 3

/** Outcome of one trigger evaluation. */
internal sealed class DnsRefreshDecision {
    object Noop : DnsRefreshDecision()
    data class Refresh(val frozenAddress: String) : DnsRefreshDecision()
}

/** Dead-tunnel trigger + debounce for the DNS refresh (4.116).
 * Pure state machine over the native snapshot: no Android APIs,
 * no I/O, so it is unit-tested directly.
 *
 * Fires only when ALL of these hold:
 * - the service has EVER had a connected session (`everConnected`)
 *   — sticky across native session restarts, by design: the
 *   error/recovery path restarts the native session every ~66 s
 *   while the tunnel is dead, and every restart zeroes the
 *   snapshot's `connectedAtMs` (a fresh snapshot struct starts at
 *   0 and only fills in when the new session connects). Gating on
 *   the snapshot's instantaneous `connectedAtMs` therefore blocks
 *   the refresh forever in exactly the case it exists for — a
 *   session that WAS connected, lost every transport, and now
 *   restarts on a stale dial target (found live on the 6a,
 *   2026-11-27: restarts at 14:41:24 / 14:42:30 / 14:43:36 all
 *   dialed the dead IP with connectedAtMs 0, no refresh in 5+
 *   minutes of dead tunnel). The service latches `everConnected`
 *   from any snapshot that reports connected, and clears it only
 *   on full shutdown — a session that never connected at all in
 *   this service lifetime is still initial establishment's job;
 * - no transport at all is up (`transportCount == 0`, which
 *   counts peer relays too, so a live relay suppresses the
 *   refresh: the tunnel still carries traffic);
 * - the dead state held continuously for
 *   [DNS_REFRESH_DEAD_TUNNEL_DEBOUNCE_MS];
 * - the server address is a hostname, not an IP literal (there
 *   is nothing to re-resolve for a literal);
 * - the cooldown since the last attempt has elapsed — longer
 *   ([DNS_REFRESH_SAME_ADDRESS_BACKOFF_MS]) when the last lookup
 *   returned the address already being dialed.
 *
 * Times are monotonic milliseconds (the service passes
 * `SystemClock.elapsedRealtime()`). `everConnected` is latched by
 * the service from any snapshot reporting a connected session, so
 * it survives the native session restarts that zero the
 * snapshot's own `connectedAtMs`. */
internal class DnsRefreshDecider {
    private var deadSinceMs: Long? = null
    // Null until the first attempt: a zero epoch would conflate
    // "never attempted" with "attempted at boot" and wrongly gate
    // the first refresh behind the cooldown.
    private var lastAttemptMs: Long? = null
    private var sameAddressBackoffUntilMs: Long = 0L

    // Synchronized: evaluate() runs on the session-monitor thread
    // while noteSameAddress()/noteRefreshed() run on the lookup
    // thread. A race here would only duplicate or delay a lookup,
    // but there is no reason to leave a data race in.
    @Synchronized
    fun evaluate(
            transportCount: Int,
            everConnected: Boolean,
            serverAddress: String,
            frozenAddress: String?,
            nowMs: Long,
    ): DnsRefreshDecision {
        // Nothing to re-resolve: the record is already an IP
        // literal, or the service never recorded a resolved dial
        // target for this session.
        if (frozenAddress.isNullOrBlank() || isIpLiteralAddress(serverAddress)) {
            deadSinceMs = null
            return DnsRefreshDecision.Noop
        }
        // The service never had a connected session, or a transport
        // is up: the tunnel is not dead. Either way the dead period
        // re-arms from scratch next time.
        if (!everConnected || transportCount > 0) {
            deadSinceMs = null
            sameAddressBackoffUntilMs = 0L
            return DnsRefreshDecision.Noop
        }
        // Dead: arm the timer on first sight, then wait out the
        // debounce so a transient blip never spends a lookup.
        val since =
                deadSinceMs
                        ?: run {
                            deadSinceMs = nowMs
                            return DnsRefreshDecision.Noop
                        }
        if (nowMs - since < DNS_REFRESH_DEAD_TUNNEL_DEBOUNCE_MS) {
            return DnsRefreshDecision.Noop
        }
        if (nowMs < sameAddressBackoffUntilMs) {
            return DnsRefreshDecision.Noop
        }
        val lastAttempt = lastAttemptMs
        if (lastAttempt != null && nowMs - lastAttempt < DNS_REFRESH_COOLDOWN_MS) {
            return DnsRefreshDecision.Noop
        }
        lastAttemptMs = nowMs
        return DnsRefreshDecision.Refresh(frozenAddress)
    }

    /** The lookup answered with the address already being dialed:
     * the record has not moved, so do not spend another lookup
     * until the longer backoff elapses. */
    @Synchronized
    fun noteSameAddress(nowMs: Long) {
        sameAddressBackoffUntilMs = nowMs + DNS_REFRESH_SAME_ADDRESS_BACKOFF_MS
    }

    /** A fresh address was applied: the dead period re-arms from
     * scratch, so the new target gets its own debounce window
     * before another lookup is spent on it. */
    @Synchronized
    fun noteRefreshed(nowMs: Long) {
        deadSinceMs = null
        sameAddressBackoffUntilMs = 0L
        lastAttemptMs = nowMs
    }
}

/** Whether a "host:port" address is a well-formed dial target:
 * an IP-literal host (IPv4 or bracketed IPv6) and a numeric port.
 * Used to gate adb-supplied addresses for the diagnostic refresh
 * (4.116): the worker re-validates, but the service persists the
 * address before calling it, so a malformed value must never
 * reach the persisted record. Mirrors the worker's
 * `validate_refresh_address` (Rust `SocketAddr` parse). */
internal fun isValidRefreshAddress(address: String): Boolean {
    val lastColon = address.lastIndexOf(':')
    if (lastColon < 0) {
        return false
    }
    if (!isIpLiteralAddress(address)) {
        return false
    }
    val port = address.substring(lastColon + 1).toIntOrNull() ?: return false
    return port in 1..65535
}

/** Whether a "host:port" address is already an IP literal (IPv4
 * or bracketed IPv6), mirroring the check in
 * `BondedVpnService.resolveServerAddressEarly`. Deliberately the
 * same loose shape test, not a validator: a malformed literal
 * fails the same way in the dial path either way. */
internal fun isIpLiteralAddress(address: String): Boolean {
    val lastColon = address.lastIndexOf(':')
    if (lastColon < 0) {
        return false
    }
    val host = address.substring(0, lastColon)
    if (host.startsWith('[')) {
        return true
    }
    return host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
}

/** Build a DNS wire-format query for one A record. Returns null
 * when the hostname cannot be encoded (blank, an empty label, a
 * label over 63 bytes, or over 253 bytes total) — the caller
 * treats that as a failed lookup and falls back to the frozen IP. */
internal fun buildDnsQuery(hostname: String, id: Int): ByteArray? {
    if (hostname.isBlank() || hostname.length > 253) {
        return null
    }
    val labels = hostname.split('.')
    val labelBytes =
            labels.map { label ->
                if (label.isEmpty() || label.length > 63) {
                    return null
                }
                label.toByteArray(Charsets.US_ASCII)
            }
    val out = ByteArrayOutputStream()
    out.write(id shr 8)
    out.write(id)
    out.write(0x01)
    out.write(0x00) // Flags: recursion desired.
    out.write(0)
    out.write(1) // QDCOUNT = 1.
    out.write(0)
    out.write(0) // ANCOUNT = 0.
    out.write(0)
    out.write(0) // NSCOUNT = 0.
    out.write(0)
    out.write(0) // ARCOUNT = 0.
    for (bytes in labelBytes) {
        out.write(bytes.size)
        out.write(bytes)
    }
    out.write(0) // Root label.
    out.write(0)
    out.write(1) // QTYPE = A.
    out.write(0)
    out.write(1) // QCLASS = IN.
    return out.toByteArray()
}

/** Parse a DNS wire-format response, returning the first A-record
 * address, or null on anything malformed (wrong transaction id,
 * error RCODE, truncated, no A record). The caller tries the next
 * resolver on null, and ultimately falls back to the frozen IP —
 * a bad response must never become a dial target. */
internal fun parseDnsResponse(response: ByteArray, queryId: Int): InetAddress? {
    if (response.size < 12) {
        return null
    }
    val id = u16(response, 0)
    if (id != (queryId and 0xFFFF)) {
        return null
    }
    val flags = u16(response, 2)
    if (flags and 0x8000 == 0) {
        return null // Not a response.
    }
    if (flags and 0x000F != 0) {
        return null // RCODE != NOERROR.
    }
    val qdCount = u16(response, 4)
    val anCount = u16(response, 6)
    if (anCount == 0) {
        return null
    }
    var pos = 12
    // Skip the question section.
    repeat(qdCount) {
        pos = skipDnsName(response, pos) ?: return null
        if (pos + 4 > response.size) {
            return null
        }
        pos += 4 // QTYPE + QCLASS.
    }
    // Walk the answers; take the first A record.
    repeat(anCount) {
        pos = skipDnsName(response, pos) ?: return null
        if (pos + 10 > response.size) {
            return null
        }
        val type = u16(response, pos)
        val cls = u16(response, pos + 2)
        val rdLength = u16(response, pos + 8)
        pos += 10
        if (pos + rdLength > response.size) {
            return null
        }
        if (type == 1 && cls == 1 && rdLength == 4) {
            return runCatching {
                        InetAddress.getByAddress(response.copyOfRange(pos, pos + 4))
                    }
                    .getOrNull()
        }
        pos += rdLength
    }
    return null
}

private fun u16(bytes: ByteArray, pos: Int): Int =
        ((bytes[pos].toInt() and 0xFF) shl 8) or (bytes[pos + 1].toInt() and 0xFF)

/** Offset just past a DNS name at [pos], following compression
 * pointers (0xC0xx) only far enough to know where the name ends
 * — the pointed-to labels are never re-walked. Returns null on a
 * truncated or malformed name. The hop bound keeps a
 * self-referential pointer from looping; ordinary labels always
 * advance, so a well-formed name never approaches it. */
private fun skipDnsName(bytes: ByteArray, pos: Int): Int? {
    var p = pos
    var hops = 0
    while (true) {
        if (p >= bytes.size) {
            return null
        }
        val len = bytes[p].toInt() and 0xFF
        if (len == 0) {
            return p + 1
        }
        if (len and 0xC0 == 0xC0) {
            // Compression pointer: the name ends here.
            if (p + 1 >= bytes.size) {
                return null
            }
            return p + 2
        }
        if (len and 0xC0 != 0) {
            return null // Reserved label types.
        }
        p += 1 + len
        if (++hops > 128) {
            return null
        }
    }
}
