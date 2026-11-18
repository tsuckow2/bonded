package com.bonded.bonded_app

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class PairedServerStoreSelectionTest {
    @Test
    fun selectPreferredRecord_prefersRequestedDeviceId() {
        val old = pairedServer("old-device", "2024-01-01T00:00:00Z")
        val newest = pairedServer("local-test-device", "2026-06-14T06:18:49.792503Z")

        val result = PairedServerStore.selectPreferredRecord(listOf(old, newest), "local-test-device")

        assertEquals("local-test-device", result?.id)
    }

    @Test
    fun selectPreferredRecord_fallsBackToMostRecentPairing() {
        val old = pairedServer("old-device", "2024-01-01T00:00:00Z")
        val newest = pairedServer("new-device", "2026-06-14T06:18:49.792503Z")

        val result = PairedServerStore.selectPreferredRecord(listOf(old, newest), null)

        assertEquals("new-device", result?.id)
    }

    @Test
    fun selectPreferredRecord_prefersPeerShareOverRecency() {
        // The wrong-record trap: a newer record with peer sharing
        // off must lose to an older record with it on.
        val charter = pairedServer("charter-device", "2026-10-18T00:00:00Z", peerShareEnabled = true)
        val local = pairedServer("local-device", "2026-10-22T00:00:00Z", peerShareEnabled = false)

        val result = PairedServerStore.selectPreferredRecord(listOf(charter, local), null)

        assertEquals("charter-device", result?.id)
    }

    @Test
    fun selectPreferredRecord_newestPeerShareWinsAmongPeerShare() {
        val older = pairedServer("older-peer", "2026-10-18T00:00:00Z", peerShareEnabled = true)
        val newer = pairedServer("newer-peer", "2026-10-20T00:00:00Z", peerShareEnabled = true)
        val local = pairedServer("local-device", "2026-10-22T00:00:00Z", peerShareEnabled = false)

        val result = PairedServerStore.selectPreferredRecord(listOf(older, newer, local), null)

        assertEquals("newer-peer", result?.id)
    }

    @Test
    fun selectPreferredRecord_explicitIdStillWinsOverPeerShare() {
        val charter = pairedServer("charter-device", "2026-10-18T00:00:00Z", peerShareEnabled = true)
        val local = pairedServer("local-device", "2026-10-22T00:00:00Z", peerShareEnabled = false)

        val result = PairedServerStore.selectPreferredRecord(listOf(charter, local), "local-device")

        assertEquals("local-device", result?.id)
    }

    private fun pairedServer(
        id: String,
        pairedAt: String,
        peerShareEnabled: Boolean = false,
    ): PairedServerRecord =
        PairedServerRecord(
            id = id,
            publicAddress = "127.0.0.1:8000",
            serverIdentityPublicKey = "key-$id",
            supportedProtocols = emptyList(),
            peerShareEnabled = peerShareEnabled,
            peerShareBindAddress = "",
            peerShareAdvertiseIp = "",
            peerShareMaxConsumers = 4,
            peerShareRelayBandwidthKbps = 0,
            pairedAt = pairedAt,
        )
}
