package org.sirinvpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import org.json.JSONObject

object VpnNotifications {
    const val VPN_ID = 70
    const val CHANNEL = "vpn_v2"
    const val MAINTENANCE_CHANNEL = "maintenance_v2"
    const val UPDATE_CHANNEL = "updates_v2"
    private var lastState=""
    private var lastRx=0L
    private var lastTx=0L
    private var lastSample=0L
    fun channels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        // Badge behavior is immutable after creation, so existing installs need new channel IDs.
        val channels = listOf(
            NotificationChannel(CHANNEL, "VPN connection", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Current VPN state and controls"; setSound(null, null); enableVibration(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
            NotificationChannel(MAINTENANCE_CHANNEL, "Server operations", NotificationManager.IMPORTANCE_LOW),
            NotificationChannel(UPDATE_CHANNEL, "App updates", NotificationManager.IMPORTANCE_DEFAULT))
        for (channel in channels) {
            val oldId = channel.id.removeSuffix("_v2")
            if (manager.getNotificationChannel(channel.id) == null) {
                manager.getNotificationChannel(oldId)?.let { old ->
                    channel.importance = old.importance
                    channel.setSound(old.sound, old.audioAttributes)
                    channel.vibrationPattern = old.vibrationPattern
                    channel.enableVibration(old.shouldVibrate())
                    channel.enableLights(old.shouldShowLights()); channel.lightColor = old.lightColor
                    channel.lockscreenVisibility = old.lockscreenVisibility
                    channel.group = old.group
                }
                channel.setShowBadge(false)
                manager.createNotificationChannel(channel)
            }
            val previous = manager.activeNotifications.filter { it.notification.channelId == oldId }
            for (notice in previous) manager.notify(notice.tag, notice.id,
                Notification.Builder.recoverBuilder(context, notice.notification).setChannelId(channel.id)
                    .setBadgeIconType(Notification.BADGE_ICON_NONE).build())
            // Wait until old notifications have moved before retiring their channel.
            if (previous.isEmpty() && manager.getNotificationChannel(oldId) != null) manager.deleteNotificationChannel(oldId)
        }
    }
    fun openApp(context: Context): PendingIntent = PendingIntent.getActivity(context, 1,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    private fun base(context: Context) = Notification.Builder(context, CHANNEL)
        .setSmallIcon(R.drawable.ic_sirin_vpn).setContentTitle("SirinVPN")
        .setContentIntent(openApp(context)).setOnlyAlertOnce(true).setOngoing(true)
        .setBadgeIconType(Notification.BADGE_ICON_NONE)
        .setVisibility(Notification.VISIBILITY_PRIVATE).setCategory(Notification.CATEGORY_SERVICE)
    fun connecting(context: Context): Notification = base(context).setContentText("Starting VPN…").build()
    private fun controlAction(context: Context, label: String, intent: PendingIntent): Notification.Action {
        val builder = Notification.Action.Builder(null, label, intent)
        // Android closes the shade for authentication-required actions even when already unlocked.
        // The receiver rechecks the lock at delivery, including after the notification was built.
        if (Build.VERSION.SDK_INT >= 31) builder.setAuthenticationRequired(context.getSystemService(KeyguardManager::class.java).isDeviceLocked)
        return builder.build()
    }
    private fun rate(bytes: Long, seconds: Double): String {
        val units = arrayOf("B/s", "KB/s", "MB/s", "GB/s", "TB/s")
        var amount = bytes / seconds
        var unit = 0
        while (amount >= 1024 && unit < units.lastIndex) { amount /= 1024; unit++ }
        return String.format(java.util.Locale.ROOT,
            if (unit == 0 || amount >= 10) "%.0f %s" else "%.1f %s", amount, units[unit])
    }
    fun update(service: Context, snapshot: JSONObject) {
        val phase = snapshot.getString("phase")
        val policy = snapshot.optBoolean("always_on")
        val status=snapshot.getJSONObject("status")
        val sampledAt=status.optLong("counter_sampled_at_ms")
        val state="$phase:$policy:${snapshot.getLong("generation")}:${snapshot.optBoolean("wifi_automation_enabled")}:${service.getSystemService(KeyguardManager::class.java).isDeviceLocked}:${status.optString("counter_epoch")}:${status.optBoolean("byte_counters_available")}"
        // Publish every fresh counter sample; unrelated status events keep the current rates.
        if(state==lastState && sampledAt==lastSample) return
        val rx=status.optLong("rx_bytes");val tx=status.optLong("tx_bytes")
        val elapsed=(sampledAt-lastSample)/1000.0
        val traffic=if(state==lastState && lastSample>0 && elapsed>0 && elapsed<=20 && rx>=lastRx && tx>=lastTx && status.optBoolean("byte_counters_available")) " · ↓ ${rate(rx-lastRx,elapsed)} · ↑ ${rate(tx-lastTx,elapsed)}" else ""
        lastState=state;lastRx=rx;lastTx=tx;lastSample=sampledAt
        val monitoring=snapshot.optBoolean("wifi_automation_enabled") && phase in setOf("paused", "disconnected", "failed", "permission_required")
        val label = if (policy) "VPN settings" else if (phase in setOf("connected", "degraded")) "Disconnect" else if (monitoring) "Stop Wi-Fi automation" else "Stop attempts"
        val action = if (policy) PendingIntent.getActivity(service, 2, Intent(android.provider.Settings.ACTION_VPN_SETTINGS),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        else PendingIntent.getBroadcast(service, 3, Intent(service, VpnActionReceiver::class.java)
            .setAction(if(monitoring) "org.sirinvpn.STOP_AUTOMATION" else "org.sirinvpn.STOP")
            .setData(android.net.Uri.parse("sirin-control://stop/${snapshot.getLong("generation")}"))
            .putExtra("generation", snapshot.getLong("generation")), PendingIntent.FLAG_IMMUTABLE)
        service.getSystemService(NotificationManager::class.java).notify(VPN_ID,
            base(service).setContentText(when (phase) {
                "connected" -> "Connected$traffic"
                "degraded" -> "Connection interrupted"
                "waiting_for_network" -> "Waiting for network"
                "reconnecting" -> "Reconnecting…"
                "unknown" -> "Connection status unavailable"
                "failed" -> "Connection needs attention"
                "paused" -> if(snapshot.optBoolean("wifi_automation_enabled")) "Wi-Fi automation paused on this network" else "Disconnected"
                "disconnected" -> if(snapshot.optBoolean("wifi_automation_enabled")) "Monitoring Wi-Fi · VPN disconnected" else "Disconnected"
                else -> "Connecting…"
            }).addAction(controlAction(service, label, action)).build())
    }
    fun failed(context:Context,snapshot:JSONObject) {
        if(!context.getSharedPreferences("application-preferences",0).getBoolean("notifications",true)) return
        val action=PendingIntent.getBroadcast(context,4,Intent(context,VpnActionReceiver::class.java)
            .setAction("org.sirinvpn.CONNECT").setData(android.net.Uri.parse("sirin-control://retry/${snapshot.getLong("generation")}"))
            .putExtra("generation",snapshot.getLong("generation")),PendingIntent.FLAG_IMMUTABLE)
        context.getSystemService(NotificationManager::class.java).notify(73,base(context).setOngoing(false).setAutoCancel(true)
            .setContentText("Connection needs attention").addAction(controlAction(context, "Retry", action)).build())
    }
    fun clearFailure(context:Context) {context.getSystemService(NotificationManager::class.java).cancel(73)}
}
