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
            NotificationChannel(CHANNEL, context.getString(R.string.notification_channel_vpn), NotificationManager.IMPORTANCE_LOW).apply {
                description = context.getString(R.string.notification_channel_vpn_description); setSound(null, null); enableVibration(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
            NotificationChannel(MAINTENANCE_CHANNEL, context.getString(R.string.notification_channel_maintenance), NotificationManager.IMPORTANCE_LOW).apply {
                description = context.getString(R.string.notification_channel_maintenance_description)
            },
            NotificationChannel(UPDATE_CHANNEL, context.getString(R.string.notification_channel_updates), NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = context.getString(R.string.notification_channel_updates_description)
            })
        for (channel in channels) {
            val oldId = channel.id.removeSuffix("_v2")
            val existing = manager.getNotificationChannel(channel.id)
            if (existing != null && (existing.name != channel.name || existing.description != channel.description)) {
                // Follow the device language. Re-registering an existing channel only
                // updates its name and description; the user's settings are kept.
                existing.name = channel.name; existing.description = channel.description
                manager.createNotificationChannel(existing)
            }
            if (existing == null) {
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
        .setSmallIcon(R.drawable.ic_sirin_vpn).setContentTitle(context.getString(R.string.app_name))
        .setContentIntent(openApp(context)).setOnlyAlertOnce(true).setOngoing(true)
        .setBadgeIconType(Notification.BADGE_ICON_NONE)
        .setVisibility(Notification.VISIBILITY_PRIVATE).setCategory(Notification.CATEGORY_SERVICE)
    fun connecting(context: Context): Notification = base(context).setContentText(context.getString(R.string.status_connecting)).build()
    private fun controlAction(context: Context, label: String, intent: PendingIntent): Notification.Action {
        val builder = Notification.Action.Builder(null, label, intent)
        // Android closes the shade for authentication-required actions even when already unlocked.
        // The receiver rechecks the lock at delivery, including after the notification was built.
        if (Build.VERSION.SDK_INT >= 31) builder.setAuthenticationRequired(context.getSystemService(KeyguardManager::class.java).isDeviceLocked)
        return builder.build()
    }
    private val rateUnits = intArrayOf(R.string.notification_rate_bytes, R.string.notification_rate_kilobytes,
        R.string.notification_rate_megabytes, R.string.notification_rate_gigabytes, R.string.notification_rate_terabytes)
    private fun rate(context: Context, bytes: Long, seconds: Double): String {
        var amount = bytes / seconds
        var unit = 0
        while (amount >= 1024 && unit < rateUnits.lastIndex) { amount /= 1024; unit++ }
        val number = String.format(context.resources.configuration.locales[0],
            if (unit == 0 || amount >= 10) "%.0f" else "%.1f", amount)
        return context.getString(rateUnits[unit], number)
    }
    fun update(service: Context, snapshot: JSONObject) {
        val phase = snapshot.getString("phase")
        val policy = snapshot.optBoolean("always_on")
        val status=snapshot.getJSONObject("status")
        val sampledAt=status.optLong("counter_sampled_at_ms")
        val state="$phase:$policy:${snapshot.getLong("generation")}:${service.getSystemService(KeyguardManager::class.java).isDeviceLocked}:${status.optString("counter_epoch")}:${status.optBoolean("byte_counters_available")}"
        // Publish every fresh counter sample; unrelated status events keep the current rates.
        if(state==lastState && sampledAt==lastSample) return
        val rx=status.optLong("rx_bytes");val tx=status.optLong("tx_bytes")
        val elapsed=(sampledAt-lastSample)/1000.0
        val connectedText=if(state==lastState && lastSample>0 && elapsed>0 && elapsed<=20 && rx>=lastRx && tx>=lastTx && status.optBoolean("byte_counters_available"))
            service.getString(R.string.notification_status_connected_traffic, rate(service,rx-lastRx,elapsed), rate(service,tx-lastTx,elapsed))
            else service.getString(R.string.status_connected)
        lastState=state;lastRx=rx;lastTx=tx;lastSample=sampledAt
        val label = service.getString(if (policy) R.string.notification_action_vpn_settings
            else if (phase in setOf("connected", "degraded")) R.string.notification_action_disconnect
            else R.string.notification_action_stop_connecting)
        val action = if (policy) PendingIntent.getActivity(service, 2, Intent(android.provider.Settings.ACTION_VPN_SETTINGS),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        else PendingIntent.getBroadcast(service, 3, Intent(service, VpnActionReceiver::class.java)
            .setAction("org.sirinvpn.STOP")
            .setData(android.net.Uri.parse("sirin-control://stop/${snapshot.getLong("generation")}"))
            .putExtra("generation", snapshot.getLong("generation")), PendingIntent.FLAG_IMMUTABLE)
        service.getSystemService(NotificationManager::class.java).notify(VPN_ID,
            base(service).setContentText(when (phase) {
                "connected" -> connectedText
                "degraded" -> service.getString(R.string.status_interrupted)
                "waiting_for_network" -> service.getString(R.string.notification_status_waiting_for_network)
                "reconnecting" -> service.getString(R.string.status_reconnecting)
                "unknown" -> service.getString(R.string.status_unknown)
                "failed" -> service.getString(R.string.notification_status_failed)
                "paused", "disconnected" -> service.getString(R.string.status_disconnected)
                else -> service.getString(R.string.status_connecting)
            }).addAction(controlAction(service, label, action)).build())
    }
    fun failed(context:Context,snapshot:JSONObject) {
        if(!context.getSharedPreferences("application-preferences",0).getBoolean("notifications",true)) return
        val action=PendingIntent.getBroadcast(context,4,Intent(context,VpnActionReceiver::class.java)
            .setAction("org.sirinvpn.CONNECT").setData(android.net.Uri.parse("sirin-control://retry/${snapshot.getLong("generation")}"))
            .putExtra("generation",snapshot.getLong("generation")),PendingIntent.FLAG_IMMUTABLE)
        context.getSystemService(NotificationManager::class.java).notify(73,base(context).setOngoing(false).setAutoCancel(true)
            .setContentText(context.getString(R.string.notification_failure_text))
            .addAction(controlAction(context, context.getString(R.string.notification_action_retry), action)).build())
    }
    fun clearFailure(context:Context) {context.getSystemService(NotificationManager::class.java).cancel(73)}
}
