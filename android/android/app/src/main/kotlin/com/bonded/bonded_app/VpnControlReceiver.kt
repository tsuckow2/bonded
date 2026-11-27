package com.bonded.bonded_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Exported broadcast receiver for VPN control via adb (testing only).
 * Usage:
 *   adb shell am broadcast -a com.bonded.bonded_app.VPN_START com.bonded.bonded_app
 *   adb shell am broadcast -a com.bonded.bonded_app.VPN_STOP com.bonded.bonded_app
 *   adb shell am broadcast -a com.bonded.bonded_app.TEST_DNS_REFRESH com.bonded.bonded_app
 *   adb shell am broadcast -a com.bonded.bonded_app.TEST_DNS_REFRESH --es address 75.164.64.252:443 com.bonded.bonded_app
 */
class VpnControlReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null) return

        android.util.Log.i("VpnControlReceiver", "Received action: ${intent.action}")

        when (intent.action) {
            "com.bonded.bonded_app.VPN_START" -> {
                val deviceId = intent.getStringExtra("device_id")
                val runBackground = intent.getBooleanExtra("run_background", true)

                if (deviceId != null) {
                    // Explicit device ID provided
                    android.util.Log.i("VpnControlReceiver", "Starting VPN with device_id=$deviceId")
                    BondedVpnService.start(context, deviceId, runBackground)
                } else {
                    // Try to find first paired device: UI-selected
                    // record first, then newest peer-share record,
                    // then newest record.
                    val preferred = AppSettingsStore.selectedRecord(context)
                    if (preferred != null) {
                        android.util.Log.i(
                            "VpnControlReceiver",
                            "Starting VPN with preferred paired device: ${preferred.id} peerShareEnabled=${preferred.peerShareEnabled}",
                        )
                        BondedVpnService.start(context, preferred.id, runBackground)
                    } else {
                        android.util.Log.w("VpnControlReceiver", "No paired devices found")
                    }
                }
            }

            "com.bonded.bonded_app.VPN_STOP" -> {
                android.util.Log.i("VpnControlReceiver", "Stopping VPN")
                BondedVpnService.stop(context)
            }

            // Diagnostic DNS refresh (4.116): force the refresh path
            // outside the decider. Without --es address, the active
            // server is re-resolved over the protected socket and the
            // answer applied (lookup test); with one, the address is
            // pushed straight into the live session (mutation test).
            "com.bonded.bonded_app.TEST_DNS_REFRESH" -> {
                val address = intent.getStringExtra("address")
                android.util.Log.i(
                        "VpnControlReceiver",
                        "Forcing DNS refresh (address=$address)",
                )
                val ok = BondedVpnService.testDnsRefresh(address)
                android.util.Log.i("VpnControlReceiver", "DNS refresh started: $ok")
            }

            else -> {
                android.util.Log.w("VpnControlReceiver", "Unknown action: ${intent.action}")
            }
        }
    }
}
