package com.bonded.bonded_app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BatteryProfilerTest {
    private fun context(
            idle: Boolean = false,
            networkKind: String = "wifi",
            peerSharing: Boolean = false,
            batterySaver: Boolean = false,
            screenOn: Boolean = true,
            doze: Boolean = false,
    ) = SampleContext(
            idle = idle,
            screenOn = screenOn,
            doze = doze,
            powerSave = false,
            peerSharing = peerSharing,
            activeRelays = 0,
            relayedUpBytes = 0,
            relayedDownBytes = 0,
            batterySaver = batterySaver,
            transportMix = "QUIC",
            pathCount = 1,
            activeTransport = "QUIC",
            activeNetworkKind = networkKind,
    )

    private fun sample(
            atMs: Long,
            chargeUah: Long? = 4_000_000,
            charging: Boolean = false,
            processCpuMs: Long = 0,
            threadCpuMs: Map<String, Long> = emptyMap(),
            wakeups: WakeupCounts = WakeupCounts(),
            context: SampleContext = context(),
    ) = BatterySample(
            timestampMs = atMs,
            chargeUah = chargeUah,
            currentUa = null,
            capacityPct = 80,
            charging = charging,
            processCpuMs = processCpuMs,
            threadCpuMs = threadCpuMs,
            wakeups = wakeups,
            context = context,
    )

    @Test
    fun mahPerHour_measuresDrainOverDischargingSpan() {
        // 100_000 µAh lost over 1 h = 100 mAh/h.
        val samples = listOf(
                sample(atMs = 0, chargeUah = 4_000_000),
                sample(atMs = 1_800_000, chargeUah = 3_950_000),
                sample(atMs = 3_600_000, chargeUah = 3_900_000),
        )
        assertEquals(100.0, BatteryProfileMath.mahPerHour(samples)!!, 0.001)
    }

    @Test
    fun mahPerHour_ignoresChargingSamples() {
        // The middle sample is charging (counter rose); only the
        // discharging endpoints count, over their own span.
        val samples = listOf(
                sample(atMs = 0, chargeUah = 4_000_000),
                sample(atMs = 1_800_000, chargeUah = 4_100_000, charging = true),
                sample(atMs = 3_600_000, chargeUah = 3_900_000),
        )
        assertEquals(100.0, BatteryProfileMath.mahPerHour(samples)!!, 0.001)
    }

    @Test
    fun mahPerHour_nullWithoutUsableCounter() {
        assertNull(BatteryProfileMath.mahPerHour(listOf(
                sample(atMs = 0, chargeUah = null),
                sample(atMs = 3_600_000, chargeUah = null),
        )))
        // Fewer than two discharging samples.
        assertNull(BatteryProfileMath.mahPerHour(listOf(
                sample(atMs = 0, chargeUah = 4_000_000),
        )))
        // Span under a minute is not a rate.
        assertNull(BatteryProfileMath.mahPerHour(listOf(
                sample(atMs = 0, chargeUah = 4_000_000),
                sample(atMs = 30_000, chargeUah = 3_990_000),
        )))
    }

    @Test
    fun mahPerHour_counterRiseWhileDischargingIsUnmeasurable() {
        // The counter rose while discharging (weak charger / status
        // lag): the drain that hour is unmeasurable, not zero.
        val samples = listOf(
                sample(atMs = 0, chargeUah = 4_000_000),
                sample(atMs = 3_600_000, chargeUah = 4_001_000),
        )
        assertNull(BatteryProfileMath.mahPerHour(samples))
    }

    @Test
    fun mahPerHour_flatCounterWhileDischargingIsZero() {
        // Counter exactly flat while discharging is a real measured
        // 0.0 — distinct from the unmeasurable (null) case above.
        val samples = listOf(
                sample(atMs = 0, chargeUah = 4_000_000),
                sample(atMs = 3_600_000, chargeUah = 4_000_000),
        )
        assertEquals(0.0, BatteryProfileMath.mahPerHour(samples)!!, 0.001)
    }

    @Test
    fun cpuMsPerHour_scalesByElapsedTime() {
        val samples = listOf(
                sample(atMs = 0, processCpuMs = 1_000),
                sample(atMs = 1_800_000, processCpuMs = 4_000),
        )
        // 3000 ms over 0.5 h = 6000 ms/h.
        assertEquals(6000.0, BatteryProfileMath.cpuMsPerHour(samples)!!, 0.001)
        assertNull(BatteryProfileMath.cpuMsPerHour(listOf(samples[0])))
    }

    @Test
    fun wakeupsPerHour_countsAllSources() {
        val samples = listOf(
                sample(atMs = 0, wakeups = WakeupCounts(heartbeatPings = 10)),
                sample(
                        atMs = 3_600_000,
                        wakeups = WakeupCounts(
                                heartbeatPings = 154,
                                quicPings = 288,
                                snapshotSerializations = 120,
                        ),
                ),
        )
        // (144 + 288 + 120) over 1 h = 552/h.
        assertEquals(552.0, BatteryProfileMath.wakeupsPerHour(samples)!!, 0.001)
    }

    @Test
    fun wakeupRatesBySource_splitsPerField() {
        val samples = listOf(
                sample(
                        atMs = 0,
                        wakeups = WakeupCounts(heartbeatPings = 10, supervisorRedials = 0),
                ),
                sample(
                        atMs = 3_600_000,
                        wakeups = WakeupCounts(
                                heartbeatPings = 154,
                                quicPings = 288,
                                snapshotSerializations = 120,
                                supervisorRedials = 180,
                        ),
                ),
        )
        val rates = BatteryProfileMath.wakeupRatesBySource(samples)
        assertEquals(144.0, rates["heartbeatPings"]!!, 0.001)
        assertEquals(288.0, rates["quicPings"]!!, 0.001)
        assertEquals(120.0, rates["snapshotSerializations"]!!, 0.001)
        assertEquals(180.0, rates["supervisorRedials"]!!, 0.001)
        assertEquals(0.0, rates["networkCallbacks"]!!, 0.001)
        // The total is the sum of the per-source rates.
        assertEquals(732.0, rates.values.sum(), 0.001)
        assertEquals(732.0, BatteryProfileMath.wakeupsPerHour(samples)!!, 0.001)
    }

    @Test
    fun threadCpuMsPerHour_splitsPerThread() {
        val samples = listOf(
                sample(
                        atMs = 0,
                        threadCpuMs = mapOf(
                                "bonded-session-monitor" to 1_000L,
                                "tokio-runtime-worker" to 5_000L,
                        ),
                ),
                sample(
                        atMs = 3_600_000,
                        threadCpuMs = mapOf(
                                "bonded-session-monitor" to 4_000L,
                                "tokio-runtime-worker" to 6_000L,
                                "bonded-peer-window" to 500L,
                        ),
                ),
        )
        val rates = BatteryProfileMath.threadCpuMsPerHour(samples)
        assertEquals(3000.0, rates["bonded-session-monitor"]!!, 0.001)
        assertEquals(1000.0, rates["tokio-runtime-worker"]!!, 0.001)
        // A thread that appeared mid-span counts from zero.
        assertEquals(500.0, rates["bonded-peer-window"]!!, 0.001)
    }

    @Test
    fun aggregateHour_persistsPerSourceAndPerThread() {
        val samples = listOf(
                sample(
                        atMs = 0,
                        chargeUah = 4_000_000,
                        processCpuMs = 0,
                        threadCpuMs = mapOf("bonded-session-monitor" to 1_000L),
                        wakeups = WakeupCounts(heartbeatPings = 10),
                        context = context(screenOn = true, doze = false),
                ),
                sample(
                        atMs = 1_800_000,
                        chargeUah = 3_970_000,
                        processCpuMs = 3_000,
                        threadCpuMs = mapOf("bonded-session-monitor" to 2_500L),
                        wakeups = WakeupCounts(heartbeatPings = 82),
                        context = context(screenOn = true, doze = false),
                ),
                sample(
                        atMs = 1_800_000,
                        chargeUah = 3_970_000,
                        processCpuMs = 3_000,
                        threadCpuMs = mapOf("bonded-session-monitor" to 2_500L),
                        wakeups = WakeupCounts(heartbeatPings = 82),
                        context = context(screenOn = false, doze = true),
                ),
                sample(
                        atMs = 3_600_000,
                        chargeUah = 3_900_000,
                        processCpuMs = 6_000,
                        threadCpuMs = mapOf("bonded-session-monitor" to 4_000L),
                        wakeups = WakeupCounts(
                                heartbeatPings = 154,
                                supervisorRedials = 180,
                        ),
                        context = context(screenOn = false, doze = true),
                ),
        )
        val agg = BatteryProfileMath.aggregateHour(samples, 0L)
        assertEquals(144.0, agg.wakeupsBySource["heartbeatPings"]!!, 0.001)
        assertEquals(180.0, agg.wakeupsBySource["supervisorRedials"]!!, 0.001)
        assertEquals(3000.0, agg.threadCpuMsPerHour["bonded-session-monitor"]!!, 0.001)
        // Screen-on half drained 30 mAh over 0.5 h = 60 mAh/h;
        // screen-off half drained 70 mAh over 0.5 h = 140 mAh/h.
        assertEquals(60.0, agg.segments["screenOn"]!!, 0.001)
        assertEquals(140.0, agg.segments["screenOff"]!!, 0.001)
        assertEquals(140.0, agg.segments["doze"]!!, 0.001)
        assertEquals(60.0, agg.segments["notDoze"]!!, 0.001)
    }

    @Test
    fun wakeupDelta_saturatesBackwardsCountersAtZero() {
        // A re-dialed transport restarts its QUIC PING count from
        // zero; the delta must not go negative.
        val before = WakeupCounts(heartbeatPings = 100, quicPings = 50)
        val after = WakeupCounts(heartbeatPings = 110, quicPings = 3)
        val delta = after.deltaFrom(before)
        assertEquals(10L, delta.heartbeatPings)
        assertEquals(0L, delta.quicPings)
        assertEquals(10L, delta.total())
    }

    @Test
    fun segmentedMahPerHour_splitsByState() {
        val idle = context(idle = true)
        val active = context(idle = false)
        val samples = listOf(
                sample(atMs = 0, chargeUah = 4_000_000, context = idle),
                sample(atMs = 3_600_000, chargeUah = 3_990_000, context = idle),
                sample(atMs = 3_600_000, chargeUah = 3_980_000, context = active),
                sample(atMs = 7_200_000, chargeUah = 3_900_000, context = active),
        )
        val rates = BatteryProfileMath.segmentedMahPerHour(samples) {
            if (it.context.idle) "idle" else "active"
        }
        assertEquals(10.0, rates["idle"]!!, 0.001)
        assertEquals(80.0, rates["active"]!!, 0.001)
        val counts = BatteryProfileMath.segmentSampleCounts(samples) {
            if (it.context.idle) "idle" else "active"
        }
        assertEquals(2, counts["idle"])
        assertEquals(2, counts["active"])
    }

    @Test
    fun aggregateHour_rollsUpOneHour() {
        val samples = listOf(
                sample(atMs = 0, chargeUah = 4_000_000, processCpuMs = 0),
                sample(atMs = 3_600_000, chargeUah = 3_900_000, processCpuMs = 6_000),
        )
        val agg = BatteryProfileMath.aggregateHour(samples, 0L)
        assertEquals(0L, agg.hourStartMs)
        assertEquals(2, agg.sampleCount)
        assertEquals(100.0, agg.mahPerHour!!, 0.001)
        assertEquals(6000.0, agg.cpuMsPerHour!!, 0.001)
    }

    @Test
    fun threadCpu_parsesStatFieldsAfterParenthesisedComm() {
        // pid (comm with spaces) state ppid ... utime=100 stime=50
        // => (100 + 50) ticks * 10 ms = 1500 ms. Fields after the
        // comm: state(3) ppid(4) pgrp(5) session(6) tty_nr(7)
        // tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12)
        // cmajflt(13) utime(14) stime(15).
        val stat =
                "1234 (bonded-session-monitor) S 1 1234 1234 0 -1 4194304 " +
                        "100 0 0 0 100 50 0 0 20 0 1 0 100 1000000 1000"
        assertEquals(1500L, ThreadCpuReader.parseStatCpuMs(stat))
    }

    @Test
    fun threadCpu_malformedStatReturnsNull() {
        assertNull(ThreadCpuReader.parseStatCpuMs("not a stat line"))
        assertNull(ThreadCpuReader.parseStatCpuMs("1 (x) S 1"))
        assertNull(ThreadCpuReader.parseStatCpuMs(""))
    }

    @Test
    fun threadCpu_readsTrackedThreadsFromTaskDir() {
        // The kernel truncates comm to 15 chars, so the fake task
        // dirs use the truncated forms — the full names are the
        // output-map labels, not what /proc reports.
        val dir = kotlin.io.path.createTempDirectory("bonded-cpu-test").toFile()
        try {
            val worker = java.io.File(dir, "101")
            worker.mkdirs()
            java.io.File(worker, "comm").writeText("bonded-session-\n")
            java.io.File(worker, "stat").writeText(
                    "101 (bonded-session-) S 1 101 101 0 -1 4194304 " +
                            "100 0 0 0 200 100 0 0 20 0 1 0 100 1000000 1000"
            )
            val other = java.io.File(dir, "102")
            other.mkdirs()
            java.io.File(other, "comm").writeText("something-else\n")
            java.io.File(other, "stat").writeText(
                    "102 (something-else) S 1 102 102 0 -1 4194304 " +
                            "100 0 0 0 999 999 0 0 20 0 1 0 100 1000000 1000"
            )
            val tokio = java.io.File(dir, "103")
            tokio.mkdirs()
            java.io.File(tokio, "comm").writeText("tokio-runtime-w\n")
            java.io.File(tokio, "stat").writeText(
                    "103 (tokio-runtime-w) S 1 103 103 0 -1 4194304 " +
                            "100 0 0 0 10 5 0 0 20 0 1 0 100 1000000 1000"
            )
            val result = ThreadCpuReader.read(dir)
            assertEquals(3000L, result["bonded-session-monitor"])
            assertEquals(150L, result["tokio-runtime-worker"])
            assertTrue(!result.containsKey("something-else"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aggregatesCodec_roundTripsAndDropsMalformedLines() {
        val aggregates = listOf(
                HourAggregate(
                        hourStartMs = 1_700_000_000_000,
                        sampleCount = 120,
                        mahPerHour = 12.5,
                        cpuMsPerHour = 4500.0,
                        wakeupsPerHour = 88.0,
                        segments = mapOf("idle" to 9.0, "wifi" to 11.0),
                        wakeupsBySource = mapOf(
                                "heartbeatPings" to 144.0,
                                "supervisorRedials" to 180.0,
                        ),
                        threadCpuMsPerHour = mapOf(
                                "bonded-session-monitor" to 3000.0,
                        ),
                ),
                HourAggregate(
                        hourStartMs = 1_700_003_600_000,
                        sampleCount = 3,
                        mahPerHour = null,
                        cpuMsPerHour = null,
                        wakeupsPerHour = null,
                        segments = emptyMap(),
                ),
        )
        val encoded = BatteryAggregatesCodec.encode(aggregates)
        val decoded = BatteryAggregatesCodec.decode(encoded + "\nthis is not json\n")
        assertEquals(2, decoded.size)
        assertEquals(1_700_000_000_000L, decoded[0].hourStartMs)
        assertEquals(120, decoded[0].sampleCount)
        assertEquals(12.5, decoded[0].mahPerHour!!, 0.001)
        assertEquals(9.0, decoded[0].segments["idle"]!!, 0.001)
        assertEquals(11.0, decoded[0].segments["wifi"]!!, 0.001)
        assertEquals(144.0, decoded[0].wakeupsBySource["heartbeatPings"]!!, 0.001)
        assertEquals(180.0, decoded[0].wakeupsBySource["supervisorRedials"]!!, 0.001)
        assertEquals(
                3000.0,
                decoded[0].threadCpuMsPerHour["bonded-session-monitor"]!!,
                0.001,
        )
        assertNull(decoded[1].mahPerHour)
        assertTrue(decoded[1].segments.isEmpty())
        assertTrue(decoded[1].wakeupsBySource.isEmpty())
        assertTrue(decoded[1].threadCpuMsPerHour.isEmpty())
    }

    @Test
    fun aggregatesCodec_decodesOldFormatLines() {
        // Aggregates written before the per-source / per-thread maps
        // existed decode with empty maps, not a dropped line.
        val oldLine =
                "{\"hour\":1700000000000,\"samples\":120,\"mah\":12.5," +
                        "\"cpu\":4500.0,\"wakeups\":88.0," +
                        "\"segments\":{\"idle\":9.0}}"
        val decoded = BatteryAggregatesCodec.decode(oldLine)
        assertEquals(1, decoded.size)
        assertEquals(9.0, decoded[0].segments["idle"]!!, 0.001)
        assertTrue(decoded[0].wakeupsBySource.isEmpty())
        assertTrue(decoded[0].threadCpuMsPerHour.isEmpty())
    }

    @Test
    fun processCpu_readsProcSelfStat() {
        // pid (comm) state ppid ... utime=100 stime=50 => 1500 ms.
        val dir = kotlin.io.path.createTempDirectory("bonded-proc-cpu-test").toFile()
        try {
            val stat = java.io.File(dir, "stat")
            stat.writeText(
                    "1234 (bonded) S 1 1234 1234 0 -1 4194304 " +
                            "100 0 0 0 100 50 0 0 20 0 1 0 100 1000000 1000"
            )
            assertEquals(1500L, ThreadCpuReader.readProcessCpuMs(stat))
            assertNull(ThreadCpuReader.readProcessCpuMs(java.io.File(dir, "missing")))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun discoveryWindow_countsWindowsOpened() {
        val scheduler = PeerDiscoveryWindowScheduler(
                acquire = {},
                release = {},
        )
        assertEquals(0L, scheduler.windowsOpenedCount())
        scheduler.start()
        try {
            // The start burst opens a window on the scheduler's first
            // iteration, which runs immediately.
            Thread.sleep(1000)
            assertEquals(1L, scheduler.windowsOpenedCount())
        } finally {
            scheduler.stop()
        }
    }
}
