package com.bonded.bonded_app

import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * App-level settings shared by the Flutter UI (via the MainActivity method
 * channel), the Quick Settings tile, the home-screen widget, and the boot
 * receiver. Stored in plain SharedPreferences so every surface reads the
 * same truth without the Flutter engine running.
 */
object AppSettingsStore {
    private const val PREFS = "bonded_app_settings"
    private const val KEY_AUTO_CONNECT_ON_OPEN = "auto_connect_on_open"
    private const val KEY_AUTO_CONNECT_ON_BOOT = "auto_connect_on_boot"
    private const val KEY_SELECTED_SERVER_ID = "selected_server_id"

    private fun prefs(context: Context) =
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun autoConnectOnOpen(context: Context): Boolean =
            prefs(context).getBoolean(KEY_AUTO_CONNECT_ON_OPEN, false)

    fun autoConnectOnBoot(context: Context): Boolean =
            prefs(context).getBoolean(KEY_AUTO_CONNECT_ON_BOOT, false)

    fun selectedServerId(context: Context): String? =
            prefs(context).getString(KEY_SELECTED_SERVER_ID, null)?.takeIf { it.isNotBlank() }

    fun setAutoConnectOnOpen(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTO_CONNECT_ON_OPEN, value).apply()
    }

    fun setAutoConnectOnBoot(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTO_CONNECT_ON_BOOT, value).apply()
    }

    fun setSelectedServerId(context: Context, value: String?) {
        val editor = prefs(context).edit()
        if (value.isNullOrBlank()) {
            editor.remove(KEY_SELECTED_SERVER_ID)
        } else {
            editor.putString(KEY_SELECTED_SERVER_ID, value)
        }
        editor.apply()
    }

    /** The record the main screen's dropdown has selected, falling back to
     * the store's preferred record when the selection is unset or stale. */
    fun selectedRecord(context: Context): PairedServerRecord? {
        val records = PairedServerStore.loadAll(context)
        val selectedId = selectedServerId(context)
        return records.firstOrNull { it.id == selectedId }
                ?: PairedServerStore.selectPreferredRecord(records)
    }
}

/**
 * Start/stop glue shared by the tile, the widget, and the boot receiver:
 * every surface toggles the same selected server the same way.
 */
object VpnStarter {
    private const val TAG = "VpnStarter"

    /** True when VPN consent has been granted and a background start is
     * allowed to proceed without UI. */
    fun hasConsent(context: Context): Boolean =
            try {
                VpnService.prepare(context) == null
            } catch (_: Exception) {
                false
            }

    fun openApp(context: Context) {
        val intent =
                Intent(context, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(intent)
        } catch (e: Exception) {
            android.util.Log.w(TAG, "openApp failed: ${e.message}")
        }
    }

    /** Start the selected server's session. Returns false when there is
     * nothing paired or the start could not be issued. */
    fun startSelected(context: Context): Boolean {
        val record = AppSettingsStore.selectedRecord(context) ?: return false
        return try {
            BondedVpnService.start(context, record.id, runInBackground = true)
            true
        } catch (e: Exception) {
            android.util.Log.w(TAG, "startSelected failed: ${e.message}")
            false
        }
    }

    /**
     * The one toggle behavior for tile and widget: stop when running;
     * when stopped, start the selected server if consent exists, else
     * bring up the app so the user can grant it / pick a server.
     */
    fun toggle(context: Context) {
        if (BondedVpnService.isRunning()) {
            BondedVpnService.stop(context)
            return
        }
        if (!hasConsent(context) || AppSettingsStore.selectedRecord(context) == null) {
            openApp(context)
            return
        }
        startSelected(context)
    }
}
