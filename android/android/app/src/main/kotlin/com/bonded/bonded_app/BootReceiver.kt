package com.bonded.bonded_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Auto-connect on boot (Settings toggle): after the device boots and the
 * user has unlocked it once, start the selected server's session when the
 * preference is on and VPN consent was previously granted in the app.
 * Any failure is logged and dropped — boot is the wrong place to surface
 * errors; auto-connect on app open covers the retry.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!AppSettingsStore.autoConnectOnBoot(context)) return
        if (!VpnStarter.hasConsent(context)) {
            android.util.Log.i("BootReceiver", "auto-connect on boot: no VPN consent yet, skipping")
            return
        }
        val started = VpnStarter.startSelected(context)
        android.util.Log.i("BootReceiver", "auto-connect on boot: start issued=$started")
    }
}
