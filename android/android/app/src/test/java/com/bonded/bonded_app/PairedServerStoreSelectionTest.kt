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

    private fun pairedServer(id: String, pairedAt: String): PairedServerRecord =
        PairedServerRecord(
            id = id,
            publicAddress = "127.0.0.1:8000",
            serverIdentityPublicKey = "key-$id",
            supportedProtocols = emptyList(),
            peerShareEnabled = false,
            peerShareBindAddress = "",
            peerShareAdvertiseIp = "",
            peerShareMaxConsumers = 4,
            peerShareRelayBandwidthKbps = 0,
            pairedAt = pairedAt,
        )
}
