package org.sirinvpn.client

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.UserManager

class SirinVpnService : VpnService() {
    companion object { @Volatile var instance: SirinVpnService? = null }
    @Volatile private var acceptingGeneration=-1L
    @Volatile private var stopping=false
    private var lastStartId=0
    fun accepts(generation:Long)=!stopping && acceptingGeneration==generation
    override fun onCreate() {
        super.onCreate()
        instance = this
        VpnNotifications.channels(this)
        val notification = VpnNotifications.connecting(this)
        if (Build.VERSION.SDK_INT >= 34) startForeground(VpnNotifications.VPN_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(VpnNotifications.VPN_ID, notification)
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId=startId
        if (!getSystemService(UserManager::class.java).isUserUnlocked) { finishSession(); return START_NOT_STICKY }
        Controller.initialize(this)
        if (intent == null || intent.action == SERVICE_INTERFACE) Controller.restart(systemStart=intent?.action==SERVICE_INTERFACE)
        else {
            val generation=intent.getLongExtra("generation",-1)
            if(Controller.current(generation)) {stopping=false;acceptingGeneration=generation}
            else if(Controller.needsReconstruction()) Controller.restart()
        }
        return START_STICKY
    }
    override fun onTaskRemoved(rootIntent: Intent?) { /* Task removal does not change connection intent. */ }
    override fun onRevoke() { Controller.stop(true) }
    fun finishSession() {
        val generation=Controller.generation()
        stopping=true;acceptingGeneration=-1
        android.os.Handler(mainLooper).post {
            // A queued stop belongs to its session, never to a later Connect.
            if(Controller.current(generation) && stopSelfResult(lastStartId)) stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }
    override fun onDestroy() {
        if(instance===this) {instance=null;Controller.serviceDestroyed()}
        super.onDestroy()
    }
}
