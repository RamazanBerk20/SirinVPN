package org.sirinvpn.client

import android.app.Service
import android.app.Notification
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.Build

/** Finite, explicitly requested file/SSH work; never a VPN keepalive. */
class MaintenanceService : Service() {
    override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
        // Stop requests arrive here, after onCreate, rather than via stopService: an
        // operation that fails within milliseconds must not stop a foreground start
        // before startForeground. A newer start keeps the service for its own work.
        if(intent?.action==STOP) { stopSelf(startId); return START_NOT_STICKY }
        VpnNotifications.channels(this)
        val notification=Notification.Builder(this,VpnNotifications.MAINTENANCE_CHANNEL).setSmallIcon(R.drawable.ic_sirin_vpn)
            .setBadgeIconType(Notification.BADGE_ICON_NONE)
            .setContentTitle("SirinVPN server operation").setContentText("A requested operation is in progress. Reopen SirinVPN for its result.")
            .setOngoing(true).setOnlyAlertOnce(true).setContentIntent(VpnNotifications.openApp(this)).build()
        if(Build.VERSION.SDK_INT>=29) startForeground(72,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC) else startForeground(72,notification)
        return START_NOT_STICKY
    }
    override fun onBind(intent:Intent):IBinder?=null
    override fun onTimeout(startId:Int,fgsType:Int) { Controller.maintenanceTimeout();stopForeground(STOP_FOREGROUND_REMOVE);stopSelf() }
    override fun onDestroy() { stopForeground(STOP_FOREGROUND_REMOVE);super.onDestroy() }
    companion object {
        private const val STOP="org.sirinvpn.MAINTENANCE_STOP"
        /** A plain start never requires startForeground; when the service already stopped, it is not recreated as foreground. */
        fun stop(context:Context) {
            try { context.startService(Intent(context,MaintenanceService::class.java).setAction(STOP)) }
            catch (_:Exception) { /* Background start refused: the service is no longer started. */ }
        }
    }
}
