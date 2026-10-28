package com.bonded.bonded_app

import android.content.ComponentName
import android.content.Context
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * Quick Settings tile: shows the VPN state and toggles the selected
 * server's session without opening the app. When consent is missing (or
 * nothing is paired) a tap opens the app instead, via [VpnStarter].
 */
class BondedTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        VpnStarter.toggle(this)
        // The session state lands asynchronously; the tile re-reads state
        // the next time the shade is opened, and BondedVpnService asks for
        // a refresh on every state transition.
        refreshTile()
    }

    private fun refreshTile() {
        val tile = qsTile ?: return
        val snapshot = BondedVpnService.getSessionSnapshot()
        val state = snapshot?.get("state") as? String
        val record = AppSettingsStore.selectedRecord(this)
        tile.state =
                when {
                    state == "connected" || (state == null && BondedVpnService.isRunning()) ->
                            Tile.STATE_ACTIVE
                    state == "connecting" || state == "error" -> Tile.STATE_INACTIVE
                    else -> Tile.STATE_INACTIVE
                }
        tile.label = "Bonded"
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            tile.subtitle =
                    when (state) {
                        "connected" -> record?.publicAddress ?: "Connected"
                        "connecting" -> "Connecting…"
                        "error" -> "Error — open app"
                        else -> record?.publicAddress ?: "Disconnected"
                    }
        }
        tile.updateTile()
    }

    companion object {
        /** Ask the system to re-run onStartListening so the tile reflects
         * a session state transition that happened elsewhere. */
        fun requestRefresh(context: Context) {
            try {
                requestListeningState(
                        context,
                        ComponentName(context, BondedTileService::class.java),
                )
            } catch (_: Exception) {
                // Tile not placed / QS unavailable: nothing to refresh.
            }
        }
    }
}
