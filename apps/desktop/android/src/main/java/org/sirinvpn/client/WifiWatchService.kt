package org.sirinvpn.client

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.provider.Settings

/**
 * Keeps :vpn alive only while Wi-Fi auto-connect is on, the VPN is off and the device is on Wi-Fi: Android
 * offers no way to hear about the next Wi-Fi network from a stopped app. Off Wi-Fi, a one-shot callback does.
 */
class WifiWatchService : Service() {
    override fun attachBaseContext(base: Context) { super.attachBaseContext(AppLanguage.wrap(base)) }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // As MaintenanceService: a stop arriving before startForeground must not stop a foreground start.
        if (intent?.action == STOP) { stopSelf(startId); return START_NOT_STICKY }
        VpnNotifications.channels(this)
        // Android raises an app's own off or minimum channel to visible for a foreground service; only the user
        // can turn it off, after which Android keeps this service running unseen. Hide opens that switch.
        val hide = PendingIntent.getActivity(this, 4, Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, packageName).putExtra(Settings.EXTRA_CHANNEL_ID, VpnNotifications.WIFI_CHANNEL),
            PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, VpnNotifications.WIFI_CHANNEL).setSmallIcon(R.drawable.ic_sirin_vpn)
            .setBadgeIconType(Notification.BADGE_ICON_NONE).setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_wifi_watch_text)).setOngoing(true).setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE).setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(VpnNotifications.openApp(this))
            .addAction(Notification.Action.Builder(null, getString(R.string.notification_action_hide), hide).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(VpnNotifications.WIFI_WATCH_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(VpnNotifications.WIFI_WATCH_ID, notification)
        // A sticky restart after Android reclaimed :vpn checks again whether it is still needed.
        Controller.initialize(this)
        WifiAutomation.monitorStarted()
        WifiAutomation.changed()
        return START_STICKY
    }
    override fun onBind(intent: Intent): IBinder? = null
    override fun onDestroy() { WifiAutomation.monitorStopped(); stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy() }
    companion object {
        const val STOP = "org.sirinvpn.WIFI_WATCH_STOP"
    }
}
