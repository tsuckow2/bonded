package com.bonded.bonded_app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PeerDiscoveryWindowTest {
    @Test
    fun window_coversFirstTenSecondsOfMinute() {
        assertTrue(PeerDiscoveryWindow.isInWindow(0L))
        assertTrue(PeerDiscoveryWindow.isInWindow(9_999L))
        assertFalse(PeerDiscoveryWindow.isInWindow(10_000L))
        assertFalse(PeerDiscoveryWindow.isInWindow(59_999L))
    }

    @Test
    fun window_reopensAtNextMinute() {
        assertTrue(PeerDiscoveryWindow.isInWindow(60_000L))
        assertTrue(PeerDiscoveryWindow.isInWindow(69_999L))
        assertFalse(PeerDiscoveryWindow.isInWindow(70_000L))
    }

    @Test
    fun window_usesUtcMinutesNotWallClockMinutes() {
        // 2026-01-01T00:00:05Z is 5s into a UTC minute regardless of the
        // device time zone; the schedule keys off epoch seconds, so it
        // cannot split across time zones.
        val fiveSecondsIntoUtcMinute = 1_767_225_605_000L
        assertTrue(PeerDiscoveryWindow.isInWindow(fiveSecondsIntoUtcMinute))
        assertFalse(
            PeerDiscoveryWindow.isInWindow(fiveSecondsIntoUtcMinute + 10_000L)
        )
    }
}
