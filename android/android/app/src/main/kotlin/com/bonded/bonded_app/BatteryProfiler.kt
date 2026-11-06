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
) {
    fun total(): Long =
            heartbeatPings + quicPings + snapshotSerializations + networkCallbacks +
                    mdnsWindows + relayTasksStarted + relayTasksEnded

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

/** One hour of rolled-up samples, persisted across restarts. */
data class HourAggregate(
        val hourStartMs: Long,
        val sampleCount: Int,
        val mahPerHour: Double?,
        val cpuMsPerHour: Double?,
        val wakeupsPerHour: Double?,
        /** mAh/h per segment key ("idle", "wifi", "peerSharingOn", …);
         * only segments with a computable rate are present. */
        val segments: Map<String, Double>,
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
     * (weak charger, status lag) reports 0 rather than a negative
     * drain. */
    fun mahPerHour(samples: List<BatterySample>): Double? {
        val discharging =
                samples.filter { !it.charging && it.chargeUah != null }
        if (discharging.size < 2) return null
        val first = discharging.first()
        val last = discharging.last()
        val elapsedMs = last.timestampMs - first.timestampMs
        if (elapsedMs < MIN_WINDOW_MS) return null
        val drainedUah = (first.chargeUah!! - last.chargeUah!!).toDouble()
        if (drainedUah < 0) return 0.0
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
        return HourAggregate(
                hourStartMs = hourStartMs,
                sampleCount = samples.size,
                mahPerHour = mahPerHour(samples),
                cpuMsPerHour = cpuMsPerHour(samples),
                wakeupsPerHour = wakeupsPerHour(samples),
                segments = segments,
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
            val mah = agg.mahPerHour?.toString() ?: "null"
            val cpu = agg.cpuMsPerHour?.toString() ?: "null"
            val wakeups = agg.wakeupsPerHour?.toString() ?: "null"
            "{\"hour\":${agg.hourStartMs},\"samples\":${agg.sampleCount}," +
                    "\"mah\":$mah,\"cpu\":$cpu,\"wakeups\":$wakeups," +
                    "\"segments\":{$segments}}"
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

    private fun decodeLine(line: String): HourAggregate? {
        val trimmed = line.trim()
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null
        val hour = numberAfter(trimmed, "hour")?.toLong() ?: return null
        val samples = numberAfter(trimmed, "samples")?.toInt() ?: return null
        val segments = mutableMapOf<String, Double>()
        val segStart = trimmed.indexOf("\"segments\":{")
        if (segStart >= 0) {
            val segBody =
                    trimmed.substring(segStart + "\"segments\":{".length)
                            .substringBefore('}')
            if (segBody.isNotBlank()) {
                for (entry in segBody.split(",")) {
                    val parts = entry.split(":")
                    if (parts.size != 2) continue
                    val key = parts[0].trim().trim('"')
                    val value = parts[1].trim().toDoubleOrNull() ?: continue
                    segments[key] = value
                }
            }
        }
        return HourAggregate(
                hourStartMs = hour,
                sampleCount = samples,
                mahPerHour = numberAfter(trimmed, "mah"),
                cpuMsPerHour = numberAfter(trimmed, "cpu"),
                wakeupsPerHour = numberAfter(trimmed, "wakeups"),
                segments = segments,
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
                    )
            val sample =
                    BatterySample(
                            timestampMs = nowMs,
                            chargeUah = chargeUah,
                            currentUa = currentUa,
                            capacityPct = capacityPct,
                            charging = charging,
                            processCpuMs = Process.getElapsedCpuTime(),
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
