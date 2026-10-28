package com.bonded.bonded_app

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

/**
 * Home-screen widget: at-a-glance session state for the selected server
 * plus a one-tap toggle (the same [VpnStarter.toggle] the tile uses;
 * without consent the toggle opens the app instead). Tapping the body
 * opens the app.
 */
class BondedWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(
            context: Context,
            appWidgetManager: AppWidgetManager,
            appWidgetIds: IntArray,
    ) {
        for (id in appWidgetIds) {
            appWidgetManager.updateAppWidget(id, buildViews(context))
        }
    }

    companion object {
        fun buildViews(context: Context): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.bonded_widget)
            val snapshot = BondedVpnService.getSessionSnapshot()
            val state = snapshot?.get("state") as? String
            val record = AppSettingsStore.selectedRecord(context)
            val statusText =
                    when (state) {
                        "connected" -> "Connected"
                        "connecting" -> "Connecting…"
                        "error" -> "Error"
                        else ->
                                if (BondedVpnService.isRunning()) "Connected"
                                else "Disconnected"
                    }
            views.setTextViewText(R.id.widget_status, statusText)
            views.setTextViewText(
                    R.id.widget_server,
                    record?.publicAddress ?: "No server paired",
            )
            views.setTextViewText(
                    R.id.widget_toggle_label,
                    if (statusText == "Connected") "Disconnect" else "Connect",
            )

            val openApp =
                    Intent(context, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            views.setOnClickPendingIntent(
                    R.id.widget_body,
                    PendingIntent.getActivity(
                            context,
                            0,
                            openApp,
                            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    ),
            )
            val toggle = Intent(context, BondedWidgetToggleReceiver::class.java)
            views.setOnClickPendingIntent(
                    R.id.widget_toggle,
                    PendingIntent.getBroadcast(
                            context,
                            1,
                            toggle,
                            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    ),
            )
            return views
        }

        /** Push fresh state to every placed widget (called on session
         * state transitions from BondedVpnService). */
        fun refreshAll(context: Context) {
            try {
                val manager = AppWidgetManager.getInstance(context)
                val ids =
                        manager.getAppWidgetIds(
                                ComponentName(context, BondedWidgetProvider::class.java)
                        )
                if (ids.isNotEmpty()) {
                    for (id in ids) {
                        manager.updateAppWidget(id, buildViews(context))
                    }
                }
            } catch (_: Exception) {
                // No widgets placed / manager unavailable.
            }
        }
    }
}

/** Handles the widget's toggle button. */
class BondedWidgetToggleReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        VpnStarter.toggle(context)
        BondedWidgetProvider.refreshAll(context)
    }
}
