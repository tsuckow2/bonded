package com.bonded.bonded_app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Dead-tunnel trigger + debounce for the DNS refresh (plan
 * 4.116). The decider is a pure state machine over the native
 * snapshot, so the whole trigger/cooldown/backoff matrix is
 * pinned here without Android. Times are arbitrary monotonic
 * milliseconds. */
class DnsRefreshDeciderTest {
    private val connectedAtMs = 1_000L
    private val hostname = "charter.codingwell.net:443"
    private val frozen = "75.164.73.150:443"

    private fun dead(
            decider: DnsRefreshDecider,
            nowMs: Long,
            transportCount: Int = 0,
            connectedAt: Long = connectedAtMs,
            serverAddress: String = hostname,
            frozenAddress: String? = frozen,
    ) = decider.evaluate(transportCount, connectedAt, serverAddress, frozenAddress, nowMs)

    @Test
    fun deadTunnel_refreshesOnlyAfterThreeMinuteDebounce() {
        val decider = DnsRefreshDecider()
        // First sight arms the timer; the debounce waits it out.
        assertTrue(dead(decider, 0L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 60_000L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 179_999L) is DnsRefreshDecision.Noop)
        // At exactly the debounce the refresh fires, carrying the
        // frozen address the lookup must beat.
        val decision = dead(decider, 180_000L)
        assertTrue(decision is DnsRefreshDecision.Refresh)
        assertEquals(frozen, (decision as DnsRefreshDecision.Refresh).frozenAddress)
    }

    @Test
    fun refreshIsRateLimitedToOneAttemptPerFiveMinutes() {
        val decider = DnsRefreshDecider()
        dead(decider, 0L)
        assertTrue(dead(decider, 180_000L) is DnsRefreshDecision.Refresh)
        // Still dead, but the cooldown gates the next attempt.
        assertTrue(dead(decider, 180_001L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 479_999L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 480_000L) is DnsRefreshDecision.Refresh)
    }

    @Test
    fun sameAddressAnswerBacksOffFifteenMinutes() {
        val decider = DnsRefreshDecider()
        dead(decider, 0L)
        assertTrue(dead(decider, 180_000L) is DnsRefreshDecision.Refresh)
        // The lookup answered with the address already dialed: the
        // record has not moved, so the next attempt waits 15 min
        // even though the 5 min cooldown elapses first.
        decider.noteSameAddress(180_000L)
        assertTrue(dead(decider, 780_000L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 1_079_999L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 1_080_000L) is DnsRefreshDecision.Refresh)
    }

    @Test
    fun refreshedAddressRearmsTheDeadPeriodFromScratch() {
        val decider = DnsRefreshDecider()
        dead(decider, 0L)
        assertTrue(dead(decider, 180_000L) is DnsRefreshDecision.Refresh)
        // A fresh address was applied: the new target gets its own
        // 3-minute evidence window before another lookup is spent,
        // and the 5-minute attempt cooldown still runs from the
        // refresh — the later of the two gates the next attempt.
        decider.noteRefreshed(180_000L)
        assertTrue(dead(decider, 180_001L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 360_001L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 479_999L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 480_000L) is DnsRefreshDecision.Refresh)
    }

    @Test
    fun liveTransportResetsTheDeadTimer() {
        val decider = DnsRefreshDecider()
        dead(decider, 0L)
        assertTrue(dead(decider, 120_000L) is DnsRefreshDecision.Noop)
        // A transport comes up: the tunnel is not dead, and the
        // dead period re-arms from scratch when it dies again.
        assertTrue(dead(decider, 120_001L, transportCount = 1) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 120_002L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 300_001L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 300_002L) is DnsRefreshDecision.Refresh)
    }

    @Test
    fun sessionThatNeverConnectedNeverRefreshes() {
        val decider = DnsRefreshDecider()
        // Zero transports from the start is initial establishment,
        // not a dead tunnel — the normal path owns it.
        assertTrue(dead(decider, 0L, connectedAt = 0L) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 1_000_000L, connectedAt = 0L) is DnsRefreshDecision.Noop)
    }

    @Test
    fun ipLiteralServerAddressNeverRefreshes() {
        val decider = DnsRefreshDecider()
        // Nothing to re-resolve for an address that is already an IP.
        assertTrue(
                dead(decider, 0L, serverAddress = "75.164.73.150:443")
                        is DnsRefreshDecision.Noop
        )
        assertTrue(
                dead(decider, 1_000_000L, serverAddress = "75.164.73.150:443")
                        is DnsRefreshDecision.Noop
        )
        assertTrue(
                dead(decider, 1_000_000L, serverAddress = "[2001:db8::1]:443")
                        is DnsRefreshDecision.Noop
        )
    }

    @Test
    fun missingFrozenAddressNeverRefreshes() {
        val decider = DnsRefreshDecider()
        assertTrue(dead(decider, 0L, frozenAddress = null) is DnsRefreshDecision.Noop)
        assertTrue(dead(decider, 1_000_000L, frozenAddress = "") is DnsRefreshDecision.Noop)
    }
}
