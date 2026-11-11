package com.bonded.bonded_app

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.os.Process
import java.io.File

/**
 * Battery + CPU profiler (plan 4.46).
 *
 * Samples on the session monitor's EXISTING tick (1 s while the UI is
 * asking, 30 s in the background) — it adds no timers, alarms, or
 * WorkManager work of its own. A sample is a handful of binder calls
 * (BatteryManager / PowerManager properties, one /proc scan) plus
 * arithmetic, riding a wakeup that already happens.
 *
 * Honesty limits, stated wherever the numbers are shown:
 * - The charge counter measures WHOLE-DEVICE drain, not Bonded's
 *   share. Attribution is differential and state-segmented (idle vs
 *   active, Wi-Fi vs cellular, peer sharing on/off, battery-saver
 *   on/off) — never an absolute "Bonded used X mAh" claim.
 * - Some devices do not implement the charge counter (or report it
 *   coarsely); the UI then degrades to level-% deltas and says so.
 * - Every rate is shown with its window length and sample count.
 * - Sparse samples during Doze are expected, not a bug: the profiler
 *   never wakes the device to sample.
 */

/** Cumulative wakeup-source counts at one sample instant. */
data class WakeupCounts(
        val heartbeatPings: Long = 0,
        val quicPings: Long = 0,
        val snapshotSerializations: Long = 0,
        val networkCallbacks: Long = 0,
        val mdnsWindows: Long = 0,
        val relayTasksStarted: Long = 0,
        val relayTasksEnded: Long = 0,
        /** Path-supervisor re-dial attempts (one per due path per
         * wakeup). Counted by the native worker and read live from
         * the snapshot, like heartbeatPings. A re-dialed transport
         * restarts its own counters from zero, so this field is the
         * only way to see the re-dial loop's share. */
        val supervisorRedials: Long = 0,
) {
    fun total(): Long =
            heartbeatPings + quicPings + snapshotSerializations + networkCallbacks +
                    mdnsWindows + relayTasksStarted + relayTasksEnded + supervisorRedials

    /** Per-field delta, saturating at zero (a counter that went
     * backwards — e.g. a re-dialed transport restarting its QUIC
     * PING count from zero — contributes nothing, not a negative). */
    fun deltaFrom(before: WakeupCounts): WakeupCounts =
            WakeupCounts(
                    heartbeatPings = (heartbeatPings - before.heartbeatPings).coerceAtLeast(0),
                    quicPings = (quicPings - before.quicPings).coerceAtLeast(0),
                    snapshotSerializations =
                            (snapshotSerializations - before.snapshotSerializations)
                                    .coerceAtLeast(0),
                    networkCallbacks =
                            (networkCallbacks - before.networkCallbacks).coerceAtLeast(0),
                    mdnsWindows = (mdnsWindows - before.mdnsWindows).coerceAtLeast(0),
                    relayTasksStarted =
                            (relayTasksStarted - before.relayTasksStarted).coerceAtLeast(0),
                    relayTasksEnded =
                            (relayTasksEnded - before.relayTasksEnded).coerceAtLeast(0),
                    supervisorRedials =
                            (supervisorRedials - before.supervisorRedials).coerceAtLeast(0),
            )

    /** Per-field values as a named map, for the persisted
     * per-source breakdown. Keys are the field names. */
    fun asMap(): Map<String, Long> =
            mapOf(
                    "heartbeatPings" to heartbeatPings,
                    "quicPings" to quicPings,
                    "snapshotSerializations" to snapshotSerializations,
                    "networkCallbacks" to networkCallbacks,
                    "mdnsWindows" to mdnsWindows,
                    "relayTasksStarted" to relayTasksStarted,
                    "relayTasksEnded" to relayTasksEnded,
                    "supervisorRedials" to supervisorRedials,
            )
}

/** Session context tagging one sample, so rates segment by state. */
data class SampleContext(
        val idle: Boolean,
        val screenOn: Boolean,
        val doze: Boolean,
        val powerSave: Boolean,
        val peerSharing: Boolean,
        val activeRelays: Int,
        val relayedUpBytes: Long,
        val relayedDownBytes: Long,
        val batterySaver: Boolean,
        /** Distinct transport kinds joined with '+', e.g. "QUIC+WireGuard". */
        val transportMix: String,
        val pathCount: Int,
        val activeTransport: String,
        /** "wifi" | "cellular" | "ethernet" | "unknown" for the active path. */
        val activeNetworkKind: String,
)

/** One profiler sample. Charge/current are null when the device does
 * not implement that BatteryManager property. */
data class BatterySample(
        val timestampMs: Long,
        val chargeUah: Long?,
        val currentUa: Long?,
        val capacityPct: Int?,
        val charging: Boolean,
        val processCpuMs: Long,
        val threadCpuMs: Map<String, Long>,
        val wakeups: WakeupCounts,
        val context: SampleContext,
)

/** One hour of rolled-up samples, persisted across restarts.
 * `wakeupsBySource` is the per-source wakeup rate (per
 * [WakeupCounts] field, e.g. "heartbeatPings" -> 144.0) and
 * `threadCpuMsPerHour` the per-thread CPU rate (per
 * [ThreadCpuReader] label); both default empty so aggregates
 * written by older builds still decode. */
data class HourAggregate(
        val hourStartMs: Long,
        val sampleCount: Int,
        val mahPerHour: Double?,
        val cpuMsPerHour: Double?,
        val wakeupsPerHour: Double?,
        /** mAh/h per segment key ("idle", "wifi", "peerSharingOn", …);
         * only segments with a computable rate are present. */
        val segments: Map<String, Double>,
        val wakeupsBySource: Map<String, Double> = emptyMap(),
        val threadCpuMsPerHour: Map<String, Double> = emptyMap(),
)

/** Pure rate math over samples. No Android APIs: unit-testable on the JVM. */
object BatteryProfileMath {
    /** No user traffic (and no transport churn) for this long => idle.
     * Mirrors `bonded_core::heartbeat::IDLE_AFTER` (60 s). */
    const val IDLE_AFTER_MS: Long = 60_000L

    /** In-memory ring capacity: ~24 h at the 30 s background cadence. */
    const val RING_CAPACITY: Int = 2880

    /** Persisted hourly aggregates: last 7 days. */
    const val MAX_AGGREGATE_HOURS: Int = 24 * 7

    /** One hour, in ms, for bucketing. */
    const val HOUR_MS: Long = 3_600_000L

    const val MIN_WINDOW_MS: Long = 60_000L

    fun hourStartMs(timestampMs: Long): Long = timestampMs - (timestampMs % HOUR_MS)

    /** mAh/h drained over the samples' discharging span: (first -
     * last) charge counter / elapsed hours. Null when the counter is
     * unavailable, fewer than two discharging samples exist, or the
     * span is under a minute. A counter that rose while discharging
     * (weak charger, status lag) is UNMEASURABLE that hour — it
     * returns null, not 0.0, so "0.0 measured" (counter exactly
     * flat) stays distinguishable from "no drain reading". */
    fun mahPerHour(samples: List<BatterySample>): Double? {
        val discharging =
                samples.filter { !it.charging && it.chargeUah != null }
        if (discharging.size < 2) return null
        val first = discharging.first()
        val last = discharging.last()
        val elapsedMs = last.timestampMs - first.timestampMs
        if (elapsedMs < MIN_WINDOW_MS) return null
        val drainedUah = (first.chargeUah!! - last.chargeUah!!).toDouble()
        if (drainedUah < 0) return null
        return drainedUah / 1000.0 / (elapsedMs / 3_600_000.0)
    }

    /** Process CPU ms per hour over the samples' span. */
    fun cpuMsPerHour(samples: List<BatterySample>): Double? {
        if (samples.size < 2) return null
        val elapsedMs = samples.last().timestampMs - samples.first().timestampMs
        if (elapsedMs < MIN_WINDOW_MS) return null
        val delta = (samples.last().processCpuMs - samples.first().processCpuMs)
                .coerceAtLeast(0)
        return delta / (elapsedMs / 3_600_000.0)
    }

    /** Wakeups per hour over the samples' span (all counted sources). */
    fun wakeupsPerHour(samples: List<BatterySample>): Double? {
        if (samples.size < 2) return null
        val elapsedMs = samples.last().timestampMs - samples.first().timestampMs
        if (elapsedMs < MIN_WINDOW_MS) return null
        val delta = samples.last().wakeups.deltaFrom(samples.first().wakeups).total()
        return delta / (elapsedMs / 3_600_000.0)
    }

    /** Wakeups per hour per source (one rate per [WakeupCounts]
     * field, keyed by field name). Empty when the span is too short
     * to rate. A counter that went backwards contributes 0 for that
     * field (see [WakeupCounts.deltaFrom]). */
    fun wakeupRatesBySource(samples: List<BatterySample>): Map<String, Double> {
        if (samples.size < 2) return emptyMap()
        val elapsedMs = samples.last().timestampMs - samples.first().timestampMs
        if (elapsedMs < MIN_WINDOW_MS) return emptyMap()
        val hours = elapsedMs / 3_600_000.0
        val delta = samples.last().wakeups.deltaFrom(samples.first().wakeups).asMap()
        return delta.mapValues { (_, count) -> count / hours }
    }

    /** Process-thread CPU ms per hour, one rate per [ThreadCpuReader]
     * label. A thread that appeared mid-span (or whose counter went
     * backwards) contributes from its first observed value; a thread
     * present only in the first sample contributes 0. Empty when the
     * span is too short to rate. */
    fun threadCpuMsPerHour(samples: List<BatterySample>): Map<String, Double> {
        if (samples.size < 2) return emptyMap()
        val elapsedMs = samples.last().timestampMs - samples.first().timestampMs
        if (elapsedMs < MIN_WINDOW_MS) return emptyMap()
        val hours = elapsedMs / 3_600_000.0
        val first = samples.first().threadCpuMs
        val last = samples.last().threadCpuMs
        val labels = first.keys + last.keys
        return labels.associateWith { label ->
            val delta =
                    ((last[label] ?: 0L) - (first[label] ?: 0L)).coerceAtLeast(0)
            delta / hours
        }
    }

    /** mAh/h per segment key, from the samples in each segment.
     * Only segments with a computable rate are returned; the caller
     * pairs the result with [segmentSampleCounts] for the UI. */
    fun segmentedMahPerHour(
            samples: List<BatterySample>,
            key: (BatterySample) -> String,
    ): Map<String, Double> {
        return samples
                .groupBy(key)
                .mapNotNull { (segment, group) ->
                    mahPerHour(group)?.let { segment to it }
                }
                .toMap()
    }

    fun segmentSampleCounts(
            samples: List<BatterySample>,
            key: (BatterySample) -> String,
    ): Map<String, Int> = samples.groupingBy(key).eachCount()

    /** Roll one hour's samples into a persisted aggregate. */
    fun aggregateHour(samples: List<BatterySample>, hourStartMs: Long): HourAggregate {
        val segments = mutableMapOf<String, Double>()
        segments.putAll(
                segmentedMahPerHour(samples) { if (it.context.idle) "idle" else "active" }
        )
        segments.putAll(
                segmentedMahPerHour(samples) { it.context.activeNetworkKind }
        )
        segments.putAll(
                segmentedMahPerHour(samples) {
                    if (it.context.peerSharing) "peerSharingOn" else "peerSharingOff"
                }
        )
        segments.putAll(
                segmentedMahPerHour(samples) {
                    if (it.context.batterySaver) "batterySaverOn" else "batterySaverOff"
                }
        )
        segments.putAll(
                segmentedMahPerHour(samples) {
                    if (it.context.screenOn) "screenOn" else "screenOff"
                }
        )
        segments.putAll(
                segmentedMahPerHour(samples) {
                    if (it.context.doze) "doze" else "notDoze"
                }
        )
        return HourAggregate(
                hourStartMs = hourStartMs,
                sampleCount = samples.size,
                mahPerHour = mahPerHour(samples),
                cpuMsPerHour = cpuMsPerHour(samples),
                wakeupsPerHour = wakeupsPerHour(samples),
                segments = segments,
                wakeupsBySource = wakeupRatesBySource(samples),
                threadCpuMsPerHour = threadCpuMsPerHour(samples),
        )
    }
}

/** Per-thread CPU time from /proc, for the named worker threads.
 * `Debug.threadCpuTimeNanos()` only covers the calling thread, so
 * the other workers are read from /proc/self/task/<tid>/stat
 * (utime + stime, fields 14 + 15, in 10 ms ticks). Pure parsing is
 * separated from the filesystem walk so tests can inject content. */
object ThreadCpuReader {
    /** Exact comm names tracked individually. */
    val TRACKED_THREADS: List<String> =
            listOf(
                    "bonded-vpn-outbound",
                    "bonded-vpn-inbound",
                    "bonded-session-monitor",
                    "bonded-peer-window",
            )

    /** Tokio runtime workers (the native session worker) share one
     * comm prefix; their CPU is reported as one aggregate row. */
    const val TOKIO_WORKER_PREFIX: String = "tokio-runtime-worker"
    const val TOKIO_WORKER_LABEL: String = "tokio-runtime-worker"

    /** One clock tick is 10 ms on Android (USER_HZ = 100). */
    const val TICK_MS: Long = 10L

    /** Parse utime + stime (fields 14 + 15) from a /proc stat line
     * into CPU milliseconds. The comm field is parenthesised and may
     * contain spaces, so the split starts after the LAST ')'. */
    fun parseStatCpuMs(stat: String): Long? {
        val afterComm = stat.substringAfterLast(')', "")
        if (afterComm.isBlank()) return null
        val fields = afterComm.trim().split(Regex("\\s+"))
        // After "(comm)": field 3 is index 0, so utime (14) is
        // index 11 and stime (15) is index 12.
        if (fields.size <= 12) return null
        val utime = fields[11].toLongOrNull() ?: return null
        val stime = fields[12].toLongOrNull() ?: return null
        return (utime + stime) * TICK_MS
    }

    /** Process CPU ms from /proc/self/stat (utime + stime, fields
     * 14 + 15) — the ground truth `batterystats` uses. Preferred
     * over `Process.getElapsedCpuTime()`, whose value on the 6a
     * advances at wall-clock rate (~3.6M ms/h, i.e. 100% of one
     * core, while batterystats shows ~0.5%). Null when the file
     * cannot be read or parsed; the caller falls back. */
    fun readProcessCpuMs(statFile: File = File("/proc/self/stat")): Long? {
        return try {
            parseStatCpuMs(statFile.readText())
        } catch (_: Exception) {
            null
        }
    }

    /** Read CPU ms per tracked thread name from a task dir
     * (default /proc/self/task). Unreadable entries are skipped, so
     * a partial map is still useful. */
    fun read(taskDir: File = File("/proc/self/task")): Map<String, Long> {
        val out = mutableMapOf<String, Long>()
        val tasks = try {
            taskDir.listFiles() ?: return emptyMap()
        } catch (_: Exception) {
            return emptyMap()
        }
        for (task in tasks) {
            val comm = try {
                File(task, "comm").readText().trim()
            } catch (_: Exception) {
                continue
            }
            val label =
                    when {
                        comm in TRACKED_THREADS -> comm
                        comm.startsWith(TOKIO_WORKER_PREFIX) -> TOKIO_WORKER_LABEL
                        else -> continue
                    }
            val stat = try {
                File(task, "stat").readText()
            } catch (_: Exception) {
                continue
            }
            val cpuMs = parseStatCpuMs(stat) ?: continue
            out[label] = (out[label] ?: 0L) + cpuMs
        }
        return out
    }
}

/** Fixed-schema codec for the persisted hourly aggregates file
 * (one JSON-ish object per line). Hand-rolled on purpose: the only
 * other JSON in this module is `org.json`, whose android.jar stubs
 * throw in local unit tests, and a new dependency for one small
 * file is not worth it. Keys are fixed ASCII and values are
 * numbers, so no string escaping is needed; the decoder is strict
 * about the shape and drops malformed lines instead of failing
 * the whole file. */
object BatteryAggregatesCodec {
    const val FILE_NAME: String = "battery-hourly-aggregates.jsonl"

    fun encode(aggregates: List<HourAggregate>): String {
        return aggregates.joinToString("\n") { agg ->
            val segments =
                    agg.segments.entries.joinToString(",") { (key, value) ->
                        "\"$key\":$value"
                    }
            val wakeupsBySource =
                    agg.wakeupsBySource.entries.joinToString(",") { (key, value) ->
                        "\"$key\":$value"
                    }
            val threadCpu =
                    agg.threadCpuMsPerHour.entries.joinToString(",") { (key, value) ->
                        "\"$key\":$value"
                    }
            val mah = agg.mahPerHour?.toString() ?: "null"
            val cpu = agg.cpuMsPerHour?.toString() ?: "null"
            val wakeups = agg.wakeupsPerHour?.toString() ?: "null"
            "{\"hour\":${agg.hourStartMs},\"samples\":${agg.sampleCount}," +
                    "\"mah\":$mah,\"cpu\":$cpu,\"wakeups\":$wakeups," +
                    "\"segments\":{$segments}," +
                    "\"wakeupsBySource\":{$wakeupsBySource}," +
                    "\"threadCpu\":{$threadCpu}}"
        }
    }

    fun decode(text: String): List<HourAggregate> {
        return text.lineSequence()
                .mapNotNull { line -> decodeLine(line) }
                .toList()
    }

    private fun numberAfter(line: String, key: String): Double? {
        val start = line.indexOf("\"$key\":")
        if (start < 0) return null
        val rest = line.substring(start + key.length + 3)
        val end = rest.indexOfFirst { it == ',' || it == '}' }
        if (end < 0) return null
        val token = rest.substring(0, end).trim()
        if (token == "null") return null
        return token.toDoubleOrNull()
    }

    /** Parse a `"key":{"a":1.0,"b":2.0}` object. Absent or malformed
     * keys yield an empty map, so aggregates written by older builds
     * (which lack the newer keys) still decode. Values are numbers,
     * so the body ends at the first '}'. */
    private fun stringDoubleMapAfter(line: String, key: String): Map<String, Double> {
        val start = line.indexOf("\"$key\":{")
        if (start < 0) return emptyMap()
        val body =
                line.substring(start + key.length + 4)
                        .substringBefore('}')
        if (body.isBlank()) return emptyMap()
        val out = mutableMapOf<String, Double>()
        for (entry in body.split(",")) {
            val parts = entry.split(":")
            if (parts.size != 2) continue
            val entryKey = parts[0].trim().trim('"')
            val value = parts[1].trim().toDoubleOrNull() ?: continue
            out[entryKey] = value
        }
        return out
    }

    private fun decodeLine(line: String): HourAggregate? {
        val trimmed = line.trim()
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null
        val hour = numberAfter(trimmed, "hour")?.toLong() ?: return null
        val samples = numberAfter(trimmed, "samples")?.toInt() ?: return null
        return HourAggregate(
                hourStartMs = hour,
                sampleCount = samples,
                mahPerHour = numberAfter(trimmed, "mah"),
                cpuMsPerHour = numberAfter(trimmed, "cpu"),
                wakeupsPerHour = numberAfter(trimmed, "wakeups"),
                segments = stringDoubleMapAfter(trimmed, "segments"),
                wakeupsBySource = stringDoubleMapAfter(trimmed, "wakeupsBySource"),
                threadCpuMsPerHour = stringDoubleMapAfter(trimmed, "threadCpu"),
        )
    }
}

/**
 * Owns the sample ring and the persisted hourly aggregates. One
 * instance per service lifetime; raw samples die with the process,
 * closed hourly aggregates survive in [BatteryAggregatesCodec.FILE_NAME]
 * under the app's files dir. Every public method is safe to call from
 * the session-monitor thread; sampling never throws (a failed read
 * degrades that sample, never the monitor loop).
 */
class BatteryProfiler(context: Context) {
    private val appContext: Context = context.applicationContext
    private val batteryManager: BatteryManager? =
            appContext.getSystemService(BatteryManager::class.java)
    private val powerManager: PowerManager? =
            appContext.getSystemService(PowerManager::class.java)

    private val ring: ArrayDeque<BatterySample> = ArrayDeque()
    private val aggregates: MutableList<HourAggregate> =
            loadPersistedAggregates(appContext).toMutableList()
    private var openHourStartMs: Long? = null
    private var samplesSincePersist: Int = 0
    private var serializations: Long = 0

    /** Idle clocks, mirroring `bonded_core::heartbeat::is_idle`:
     * idle once no traffic AND no transport churn for 60 s. */
    private var lastTrafficMs: Long? = null
    private var lastTransportChangeMs: Long? = null
    private var lastTotalBytes: Long? = null
    private var lastTransportCount: Int? = null

    /**
     * Take one sample. Called by the session monitor after each
     * native snapshot serialization — exactly once per serialization,
     * so the sample count IS the serialization count. All Android
     * reads are best-effort; a failure degrades the sample (null
     * charge counter, empty thread map) instead of throwing.
     */
    @Synchronized
    fun sample(
            snapshot: SessionSnapshot,
            peerSharing: Boolean,
            batterySaver: Boolean,
            networkSummaries: List<String>,
            networkCallbacks: Long,
            mdnsWindows: Long,
    ) {
        val nowMs = System.currentTimeMillis()
        try {
            serializations += 1
            val (chargeUah, currentUa, capacityPct, charging) = readBattery()
            val idle = computeIdle(snapshot, nowMs)
            val context =
                    SampleContext(
                            idle = idle,
                            screenOn = powerManager?.isInteractive ?: true,
                            doze = isDeviceIdleMode(),
                            powerSave = powerManager?.isPowerSaveMode ?: false,
                            peerSharing = peerSharing,
                            activeRelays = snapshot.peerRelayCount,
                            relayedUpBytes = snapshot.relayedUpBytes,
                            relayedDownBytes = snapshot.relayedDownBytes,
                            batterySaver = batterySaver,
                            transportMix =
                                    snapshot.paths
                                            .map { it.kind }
                                            .distinct()
                                            .sorted()
                                            .joinToString("+")
                                            .ifEmpty { "none" },
                            pathCount = snapshot.transportCount,
                            activeTransport = snapshot.activeTransport,
                            activeNetworkKind =
                                    activeNetworkKind(snapshot, networkSummaries),
                    )
            val wakeups =
                    WakeupCounts(
                            heartbeatPings = snapshot.heartbeatPingsSent,
                            quicPings =
                                    snapshot.paths.sumOf { it.quicPingFrames ?: 0 },
                            snapshotSerializations = serializations,
                            networkCallbacks = networkCallbacks,
                            mdnsWindows = mdnsWindows,
                            relayTasksStarted = snapshot.relayTasksStarted,
                            relayTasksEnded = snapshot.relayTasksEnded,
                            supervisorRedials = snapshot.supervisorRedialAttempts,
                    )
            val sample =
                    BatterySample(
                            timestampMs = nowMs,
                            chargeUah = chargeUah,
                            currentUa = currentUa,
                            capacityPct = capacityPct,
                            charging = charging,
                            // Process CPU from /proc/self/stat, not
                            // Process.getElapsedCpuTime(): the latter
                            // advances at wall-clock rate on the 6a
                            // (~3.6M ms/h). Falls back to it only when
                            // /proc is unreadable.
                            processCpuMs =
                                    ThreadCpuReader.readProcessCpuMs()
                                            ?: Process.getElapsedCpuTime(),
                            threadCpuMs = ThreadCpuReader.read(),
                            wakeups = wakeups,
                            context = context,
                    )
            ring.addLast(sample)
            while (ring.size > BatteryProfileMath.RING_CAPACITY) {
                ring.removeFirst()
            }
            rollHourIfNeeded(nowMs)
            samplesSincePersist += 1
            if (samplesSincePersist >= 10) {
                persistAggregates()
            }
        } catch (e: Exception) {
            android.util.Log.w("BondedVPN", "battery sample failed: ${e.message}")
        }
    }

    private fun isDeviceIdleMode(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
        return try {
            powerManager?.isDeviceIdleMode ?: false
        } catch (_: Exception) {
            false
        }
    }

    /** Battery state. The charge counter / current come from
     * BatteryManager properties (no permission needed); charging
     * state and level come from the sticky ACTION_BATTERY_CHANGED
     * intent, which works back to API 1 (BATTERY_PROPERTY_STATUS
     * needs API 26). Integer.MIN_VALUE means "not implemented" for
     * the properties and becomes null. */
    private fun readBattery(): BatteryReading {
        val chargeUah =
                batteryManager
                        ?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)
                        ?.takeIf { it != Int.MIN_VALUE }
                        ?.toLong()
        val currentUa =
                batteryManager
                        ?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)
                        ?.takeIf { it != Int.MIN_VALUE }
                        ?.toLong()
                        ?: batteryManager
                                ?.getIntProperty(
                                        BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE
                                )
                                ?.takeIf { it != Int.MIN_VALUE }
                                ?.toLong()
        val capacityPct =
                batteryManager
                        ?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
                        ?.takeIf { it != Int.MIN_VALUE }
        var charging = false
        var levelPct: Int? = null
        try {
            val intent =
                    appContext.registerReceiver(
                            null,
                            IntentFilter(Intent.ACTION_BATTERY_CHANGED),
                    )
            val status =
                    intent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
            charging =
                    status == BatteryManager.BATTERY_STATUS_CHARGING ||
                            status == BatteryManager.BATTERY_STATUS_FULL
            val level = intent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = intent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
            if (level >= 0 && scale > 0) {
                levelPct = (level * 100) / scale
            }
        } catch (_: Exception) {
        }
        return BatteryReading(
                chargeUah = chargeUah,
                currentUa = currentUa,
                capacityPct = capacityPct ?: levelPct,
                charging = charging,
        )
    }

    private data class BatteryReading(
            val chargeUah: Long?,
            val currentUa: Long?,
            val capacityPct: Int?,
            val charging: Boolean,
    )

    private fun computeIdle(snapshot: SessionSnapshot, nowMs: Long): Boolean {
        val totalBytes = snapshot.outboundBytes + snapshot.inboundBytes
        if (lastTotalBytes == null || lastTotalBytes != totalBytes) {
            lastTrafficMs = nowMs
            lastTotalBytes = totalBytes
        }
        if (lastTransportCount == null || lastTransportCount != snapshot.transportCount) {
            lastTransportChangeMs = nowMs
            lastTransportCount = snapshot.transportCount
        }
        val trafficMs = lastTrafficMs ?: nowMs
        val changeMs = lastTransportChangeMs ?: nowMs
        return nowMs - trafficMs >= BatteryProfileMath.IDLE_AFTER_MS &&
                nowMs - changeMs >= BatteryProfileMath.IDLE_AFTER_MS
    }

    /** Network kind ("wifi"/"cellular"/"ethernet"/"unknown") for the
     * active path, from the "kind:address" summaries indexed by path
     * index — the same indexing the Dart side uses. */
    private fun activeNetworkKind(
            snapshot: SessionSnapshot,
            networkSummaries: List<String>,
    ): String {
        val activeIndex =
                snapshot.paths.firstOrNull { it.active }?.pathIndex ?: return "unknown"
        val summary = networkSummaries.getOrNull(activeIndex) ?: return "unknown"
        return when {
            summary.startsWith("wifi:") -> "wifi"
            summary.startsWith("cellular:") -> "cellular"
            summary.startsWith("ethernet:") -> "ethernet"
            else -> "unknown"
        }
    }

    /** Close the previous hour into the aggregates list when the
     * clock crosses an hour boundary. */
    private fun rollHourIfNeeded(nowMs: Long) {
        val hour = BatteryProfileMath.hourStartMs(nowMs)
        val open = openHourStartMs
        if (open == null) {
            openHourStartMs = hour
            return
        }
        if (hour == open) return
        val hourSamples = ring.filter { BatteryProfileMath.hourStartMs(it.timestampMs) == open }
        if (hourSamples.isNotEmpty()) {
            aggregates.add(BatteryProfileMath.aggregateHour(hourSamples, open))
            while (aggregates.size > BatteryProfileMath.MAX_AGGREGATE_HOURS) {
                aggregates.removeAt(0)
            }
        }
        openHourStartMs = hour
        persistAggregates()
    }

    @Synchronized
    fun persistAggregates() {
        samplesSincePersist = 0
        try {
            val file = File(appContext.filesDir, BatteryAggregatesCodec.FILE_NAME)
            file.writeText(BatteryAggregatesCodec.encode(aggregates))
        } catch (e: Exception) {
            android.util.Log.w("BondedVPN", "battery aggregates persist failed: ${e.message}")
        }
    }

    /** The UI map for the Battery card: last-hour rates segmented by
     * state, plus the persisted hourly aggregates and the counts
     * that make every rate checkable. Nulls mean "not measurable
     * yet" (too few samples, counter unavailable), never zero. */
    @Synchronized
    fun profileForUi(): Map<String, Any?> {
        val nowMs = System.currentTimeMillis()
        val windowStart = nowMs - BatteryProfileMath.HOUR_MS
        val window = ring.filter { it.timestampMs >= windowStart }
        val segments = mutableMapOf<String, Double?>()
        val segmentSamples = mutableMapOf<String, Int>()
        segments.putAll(
                BatteryProfileMath.segmentedMahPerHour(window) {
                    if (it.context.idle) "idle" else "active"
                }
        )
        segments.putAll(
                BatteryProfileMath.segmentedMahPerHour(window) { it.context.activeNetworkKind }
        )
        segments.putAll(
                BatteryProfileMath.segmentedMahPerHour(window) {
                    if (it.context.peerSharing) "peerSharingOn" else "peerSharingOff"
                }
        )
        segments.putAll(
                BatteryProfileMath.segmentedMahPerHour(window) {
                    if (it.context.batterySaver) "batterySaverOn" else "batterySaverOff"
                }
        )
        segments.putAll(
                BatteryProfileMath.segmentedMahPerHour(window) {
                    if (it.context.screenOn) "screenOn" else "screenOff"
                }
        )
        segments.putAll(
                BatteryProfileMath.segmentedMahPerHour(window) {
                    if (it.context.doze) "doze" else "notDoze"
                }
        )
        segmentSamples.putAll(
                BatteryProfileMath.segmentSampleCounts(window) {
                    if (it.context.idle) "idle" else "active"
                }
        )
        segmentSamples.putAll(
                BatteryProfileMath.segmentSampleCounts(window) { it.context.activeNetworkKind }
        )
        segmentSamples.putAll(
                BatteryProfileMath.segmentSampleCounts(window) {
                    if (it.context.peerSharing) "peerSharingOn" else "peerSharingOff"
                }
        )
        segmentSamples.putAll(
                BatteryProfileMath.segmentSampleCounts(window) {
                    if (it.context.batterySaver) "batterySaverOn" else "batterySaverOff"
                }
        )
        segmentSamples.putAll(
                BatteryProfileMath.segmentSampleCounts(window) {
                    if (it.context.screenOn) "screenOn" else "screenOff"
                }
        )
        segmentSamples.putAll(
                BatteryProfileMath.segmentSampleCounts(window) {
                    if (it.context.doze) "doze" else "notDoze"
                }
        )
        val chargeAvailable = ring.any { it.chargeUah != null }
        val currentUa = ring.lastOrNull()?.currentUa
        val capacityPct = ring.lastOrNull()?.capacityPct
        return mapOf(
                "live" to true,
                "chargeCounterAvailable" to chargeAvailable,
                "windowMs" to BatteryProfileMath.HOUR_MS,
                "windowSamples" to window.size,
                "windowStartMs" to windowStart,
                "mahPerHour" to BatteryProfileMath.mahPerHour(window),
                "cpuMsPerHour" to BatteryProfileMath.cpuMsPerHour(window),
                "wakeupsPerHour" to BatteryProfileMath.wakeupsPerHour(window),
                "wakeupsBySource" to BatteryProfileMath.wakeupRatesBySource(window),
                "threadCpuMsPerHour" to BatteryProfileMath.threadCpuMsPerHour(window),
                "currentUa" to currentUa,
                "capacityPct" to capacityPct,
                "segments" to segments,
                "segmentSamples" to segmentSamples,
                "totalSamples" to ring.size,
                "aggregates" to
                        aggregates.map { agg ->
                            mapOf<String, Any?>(
                                    "hourStartMs" to agg.hourStartMs,
                                    "samples" to agg.sampleCount,
                                    "mahPerHour" to agg.mahPerHour,
                                    "cpuMsPerHour" to agg.cpuMsPerHour,
                                    "wakeupsPerHour" to agg.wakeupsPerHour,
                                    "segments" to agg.segments,
                                    "wakeupsBySource" to agg.wakeupsBySource,
                                    "threadCpuMsPerHour" to agg.threadCpuMsPerHour,
                            )
                        },
        )
    }

    companion object {
        /** Aggregates-only view for when the service is not running:
         * the history survives process death even though the live
         * ring does not. */
        fun loadPersistedAggregates(context: Context): List<HourAggregate> {
            return try {
                val file = File(context.filesDir, BatteryAggregatesCodec.FILE_NAME)
                if (!file.exists()) return emptyList()
                BatteryAggregatesCodec.decode(file.readText())
                        .takeLast(BatteryProfileMath.MAX_AGGREGATE_HOURS)
            } catch (_: Exception) {
                emptyList()
            }
        }
    }
}
