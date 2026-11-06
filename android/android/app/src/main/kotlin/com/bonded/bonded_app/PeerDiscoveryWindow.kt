package com.bonded.bonded_app

import java.util.concurrent.atomic.AtomicLong

/**
 * Windowed Wi-Fi multicast lock schedule for peer discovery.
 *
 * The multicast lock keeps the Wi-Fi driver awake for every multicast
 * frame on the LAN, not just Bonded's, so holding it for a whole VPN
 * session is a steady battery drain. Peer discovery does not need it
 * continuously: mDNS query/response only has to overlap between the two
 * peers, and both sides derive the same schedule from the same clock
 * (UTC minutes, not local time, so time zones cannot split a window).
 *
 * Schedule, all driven by [System.currentTimeMillis]:
 * - 10s window at the top of each UTC minute: lock held, provider
 *   re-announces and consumer re-queries (Rust side, same clock).
 * - 30s continuous burst on VPN start (a peer-share toggle-on takes
 *   effect at the next session start, so it is covered by this burst),
 *   and on network path changes while the session is up.
 * - 60s continuous sweep every 30 minutes of windowed operation. This
 *   is the fallback for both failure modes of windowing: a peer whose
 *   clock is skewed (or an unsynced local clock) never overlaps our
 *   windows, and several empty windows cannot distinguish "no peers"
 *   from "windows never overlap". A full-minute sweep overlaps any
 *   peer's 10s window regardless of skew up to a minute, with no need
 *   to detect NTP sync state (which the app cannot observe reliably)
 *   and no need for the Rust side to signal discoveries to Kotlin.
 *
 * Existing relay legs are unaffected: they are unicast QUIC, and a
 * previously discovered peer is re-dialed from the cached
 * advertisement by unicast, which needs no multicast lock at all. Only
 * genuinely new peers wait for the next window (at most ~60s).
 */
object PeerDiscoveryWindow {
    /** Seconds of lock hold at the top of each UTC minute. */
    const val WINDOW_SECONDS = 10L

    /** Milliseconds of continuous hold on VPN start / path change. */
    const val BURST_MS = 30_000L

    /** Milliseconds of continuous hold per periodic sweep. */
    const val SWEEP_MS = 60_000L

    /** Milliseconds of windowed operation between sweeps. */
    const val SWEEP_INTERVAL_MS = 30L * 60L * 1000L

    /** True during the first [WINDOW_SECONDS] of a UTC minute. */
    fun isInWindow(nowMs: Long): Boolean = (nowMs / 1000L) % 60L < WINDOW_SECONDS
}

/**
 * Owns the lock schedule above. The [acquire]/[release] lambdas are the
 * service's idempotent multicast lock primitives. The scheduler thread
 * re-evaluates once a second, so a [burst] takes effect within a
 * second even while the thread is sleeping toward the next window.
 */
class PeerDiscoveryWindowScheduler(
    private val acquire: () -> Unit,
    private val release: () -> Unit,
) {
    @Volatile private var running = false
    @Volatile private var burstUntilMs = 0L
    private var thread: Thread? = null

    /** Wakeup accounting (battery profiler): windows opened since
     * start() — one per acquire transition (burst, sweep, or
     * top-of-minute window), not per second held. */
    private val windowsOpened = AtomicLong(0)

    /** Total discovery windows opened since start(). */
    fun windowsOpenedCount(): Long = windowsOpened.get()

    /** Starts the schedule (idempotent; a restart re-arms the burst). */
    fun start() {
        burstUntilMs = System.currentTimeMillis() + PeerDiscoveryWindow.BURST_MS
        synchronized(this) {
            if (running) return
            running = true
            thread =
                Thread({ runLoop() }, "bonded-peer-window").also {
                    it.isDaemon = true
                    it.start()
                }
        }
    }

    /** Holds the lock continuously for the next 30s (path change). */
    fun burst() {
        if (!running) return
        burstUntilMs = System.currentTimeMillis() + PeerDiscoveryWindow.BURST_MS
    }

    fun stop() {
        synchronized(this) {
            if (!running) return
            running = false
            thread?.interrupt()
            thread = null
        }
        release()
    }

    private fun runLoop() {
        var nextSweepAtMs =
            System.currentTimeMillis() + PeerDiscoveryWindow.SWEEP_INTERVAL_MS
        var held = false
        try {
            while (running) {
                val now = System.currentTimeMillis()
                val inBurst = now < burstUntilMs
                val inSweep =
                    now in nextSweepAtMs until
                        nextSweepAtMs + PeerDiscoveryWindow.SWEEP_MS
                while (now >= nextSweepAtMs + PeerDiscoveryWindow.SWEEP_MS) {
                    nextSweepAtMs += PeerDiscoveryWindow.SWEEP_INTERVAL_MS
                }
                val want =
                    inBurst || inSweep || PeerDiscoveryWindow.isInWindow(now)
                if (want && !held) {
                    acquire()
                    windowsOpened.incrementAndGet()
                    held = true
                }
                if (!want && held) {
                    release()
                    held = false
                }
                try {
                    Thread.sleep(1000)
                } catch (_: InterruptedException) {
                    break
                }
            }
        } finally {
            if (held) {
                try {
                    release()
                } catch (_: Exception) {
                }
            }
        }
    }
}
