package org.sirinvpn.client

import android.app.Notification
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Keeps :vpn alive only while Wi-Fi auto-connect is on, the VPN is off and the device is on Wi-Fi: Android
 * offers no way to hear about the next Wi-Fi network from a stopped app. Off Wi-Fi, a one-shot callback does.
 */
class WifiWatchService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // As MaintenanceService: a stop arriving before startForeground must not stop a foreground start.
        if (intent?.action == STOP) { stopSelf(startId); return START_NOT_STICKY }
        VpnNotifications.channels(this)
        val notification = Notification.Builder(this, VpnNotifications.WIFI_CHANNEL).setSmallIcon(R.drawable.ic_sirin_vpn)
            .setBadgeIconType(Notification.BADGE_ICON_NONE).setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_wifi_watch_text)).setOngoing(true).setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE).setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(VpnNotifications.openApp(this)).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(ID, notification)
        WifiAutomation.monitoring = true
        // A sticky restart after Android reclaimed :vpn checks again whether it is still needed.
        Controller.initialize(this)
        WifiAutomation.changed()
        return START_STICKY
    }
    override fun onBind(intent: Intent): IBinder? = null
    override fun onDestroy() { WifiAutomation.monitoring = false; stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy() }
    companion object {
        const val STOP = "org.sirinvpn.WIFI_WATCH_STOP"
        private const val ID = 74
    }
}
