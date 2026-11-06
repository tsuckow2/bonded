package com.bonded.bonded_app

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Snapshot JSON parse + forward (plan 4.48): the wire-byte fields
 * must survive the Kotlin layer that dropped them before 4.48, and
 * missing keys must read as null, never crash. Needs the real
 * org.json on the test classpath (see build.gradle.kts): the
 * android.jar stubs throw in local unit tests. */
class SessionSnapshotTest {
    @Test
    fun parseSessionPaths_readsWireBytes() {
        val paths =
                parseSessionPaths(
                        JSONArray(
                                """[
                                    {"pathIndex": 0, "kind": "QUIC", "active": true,
                                     "outboundBytes": 100, "inboundBytes": 90,
                                     "wireTxBytes": 120, "wireRxBytes": 110,
                                     "quicPingFrames": 7,
                                     "quicLostPackets": 3, "quicLostBytes": 3600,
                                     "quicSentPackets": 100, "lastRttMs": 12},
                                    {"pathIndex": 1, "kind": "WebSocketTls", "active": false,
                                     "outboundBytes": 0, "inboundBytes": 0,
                                     "lastRttMs": 0}
                                ]"""
                        )
                )
        assertEquals(2, paths.size)
        assertEquals(120L, paths[0].wireTxBytes)
        assertEquals(110L, paths[0].wireRxBytes)
        assertEquals(7L, paths[0].quicPingFrames)
        assertEquals(3L, paths[0].quicLostPackets)
        assertEquals(3600L, paths[0].quicLostBytes)
        assertEquals(100L, paths[0].quicSentPackets)
        assertNull(paths[1].wireTxBytes)
        assertNull(paths[1].wireRxBytes)
        assertNull(paths[1].quicPingFrames)
        assertNull(paths[1].quicLostPackets)
        assertNull(paths[1].quicLostBytes)
        assertNull(paths[1].quicSentPackets)
    }

    @Test
    fun parseSessionPaths_explicitNull_readsNull() {
        val paths =
                parseSessionPaths(
                        JSONArray(
                                """[
                                    {"kind": "QUIC", "wireTxBytes": null,
                                     "wireRxBytes": null, "quicPingFrames": null,
                                     "quicLostPackets": null, "quicLostBytes": null,
                                     "quicSentPackets": null}
                                ]"""
                        )
                )
        assertEquals(1, paths.size)
        assertNull(paths[0].wireTxBytes)
        assertNull(paths[0].wireRxBytes)
        assertNull(paths[0].quicPingFrames)
        assertNull(paths[0].quicLostPackets)
        assertNull(paths[0].quicLostBytes)
        assertNull(paths[0].quicSentPackets)
    }

    @Test
    fun parseSessionPaths_nullArray_returnsEmpty() {
        assertTrue(parseSessionPaths(null).isEmpty())
    }

    @Test
    fun parseSessionPaths_nonObjectEntry_isSkipped() {
        val paths = parseSessionPaths(JSONArray("""[42, {"kind": "QUIC"}]"""))
        assertEquals(1, paths.size)
        assertEquals("QUIC", paths[0].kind)
    }

    @Test
    fun sessionPathStatToMap_forwardsWireBytes() {
        val map =
                sessionPathStatToMap(
                        SessionPathStat(
                                pathIndex = 0,
                                kind = "QUIC",
                                active = true,
                                outboundBytes = 100,
                                inboundBytes = 90,
                                wireTxBytes = 120,
                                wireRxBytes = 110,
                                lastRttMs = 12,
                                serverSeenAddress = null,
                                quicPingFrames = 7,
                                quicLostPackets = 3,
                                quicLostBytes = 3600,
                                quicSentPackets = 100,
                        )
                )
        assertEquals(120L, map["wireTxBytes"])
        assertEquals(110L, map["wireRxBytes"])
        assertEquals(7L, map["quicPingFrames"])
        assertEquals(3L, map["quicLostPackets"])
        assertEquals(3600L, map["quicLostBytes"])
        assertEquals(100L, map["quicSentPackets"])
        assertEquals(100L, map["outboundBytes"])
    }

    @Test
    fun sessionPathStatToMap_nullWireBytes_forwardNull() {
        val map =
                sessionPathStatToMap(
                        SessionPathStat(
                                pathIndex = null,
                                kind = "WebSocketTls",
                                active = false,
                                outboundBytes = 0,
                                inboundBytes = 0,
                                lastRttMs = 0,
                                serverSeenAddress = null,
                        )
                )
        assertNull(map["wireTxBytes"])
        assertNull(map["wireRxBytes"])
        assertNull(map["quicPingFrames"])
        assertNull(map["quicLostPackets"])
        assertNull(map["quicLostBytes"])
        assertNull(map["quicSentPackets"])
    }
}
