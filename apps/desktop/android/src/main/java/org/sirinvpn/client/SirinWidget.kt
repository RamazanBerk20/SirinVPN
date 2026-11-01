package org.sirinvpn.client

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import org.json.JSONArray
import org.json.JSONObject

/** Home-screen status and toggle, rendered by the :vpn controller. Shows a server's name, never its address. */
class SirinWidget : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        Controller.initialize(context); Controller.refreshWidget()
    }
    companion object {
        private val running = setOf("connected", "connecting", "reconnecting", "waiting_for_network", "degraded")
        fun render(context: Context, snapshot: JSONObject) {
            val manager = AppWidgetManager.getInstance(context)
            val ids = manager.getAppWidgetIds(ComponentName(context, SirinWidget::class.java))
            if (ids.isEmpty()) return
            val servers = JSONObject(Native.call("list_servers", "{}", snapshot.getLong("generation"))).optJSONArray("ok")
            manager.updateAppWidget(ids, views(context, snapshot, servers))
        }
        fun views(context: Context, snapshot: JSONObject, servers: JSONArray?): RemoteViews {
            val phase = snapshot.getString("phase")
            val generation = snapshot.getLong("generation")
            val status = snapshot.getJSONObject("status")
            val quick = if (snapshot.isNull("quick_profile")) null else snapshot.getString("quick_profile")
            val server = if (phase in running && !status.isNull("server_id")) status.getString("server_id") else quick
            val name = (0 until (servers?.length() ?: 0)).map { servers!!.getJSONObject(it) }
                .firstOrNull { it.optString("id") == server }?.optString("name")
            val text = context.getString(when (phase) {
                "connected" -> if (snapshot.optBoolean("always_on")) R.string.tile_status_always_on else R.string.status_connected
                "connecting" -> R.string.status_connecting
                "reconnecting" -> R.string.status_reconnecting
                "waiting_for_network" -> R.string.notification_status_waiting_for_network
                "degraded" -> R.string.status_interrupted
                "failed" -> R.string.notification_status_failed
                "unknown" -> R.string.status_unknown
                "disconnected", "paused" -> R.string.status_disconnected
                else -> R.string.tile_status_open_app
            })
            // The same paths as the tile and notification: stale generations are refused by the controller.
            fun control(command: String, code: Int) = PendingIntent.getBroadcast(context, code,
                Intent(context, VpnActionReceiver::class.java).setAction("org.sirinvpn.$command")
                    .setData(android.net.Uri.parse("sirin-control://widget-${command.lowercase()}/$generation"))
                    .putExtra("generation", generation), PendingIntent.FLAG_IMMUTABLE)
            val (label, action) = when {
                snapshot.optBoolean("always_on") -> R.string.notification_action_vpn_settings to PendingIntent.getActivity(context, 2,
                    Intent(android.provider.Settings.ACTION_VPN_SETTINGS), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                phase in running -> (if (phase in setOf("connected", "degraded")) R.string.notification_action_disconnect
                    else R.string.notification_action_stop_connecting) to control("STOP", 5)
                quick == null -> R.string.widget_action_open to VpnNotifications.openApp(context)
                VpnService.prepare(context) != null -> R.string.widget_action_connect to PendingIntent.getActivity(context, 6,
                    Intent(context, ControlActionActivity::class.java).putExtra("command", "connect_saved").putExtra("generation", generation)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                else -> R.string.widget_action_connect to control("CONNECT", 7)
            }
            return RemoteViews(context.packageName, R.layout.sirin_widget).apply {
                setTextViewText(R.id.widget_status, text)
                setTextViewText(R.id.widget_server, name ?: context.getString(R.string.widget_no_server))
                setTextViewText(R.id.widget_toggle, context.getString(label))
                setOnClickPendingIntent(R.id.widget_toggle, action)
                setOnClickPendingIntent(R.id.widget_root, VpnNotifications.openApp(context))
            }
        }
    }
}
