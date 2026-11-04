package org.sirinvpn.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.UserManager

/**
 * Resume existing intent after this package's verified replacement; never after force-stop.
 * Wi-Fi auto-connect resumes after an update or boot, and wakes here when Wi-Fi joins while :vpn is stopped.
 */
class ReplacementReceiver:BroadcastReceiver() {
    override fun onReceive(context:Context,intent:Intent) {
        if(intent.action !in setOf(Intent.ACTION_MY_PACKAGE_REPLACED,Intent.ACTION_BOOT_COMPLETED,WifiAutomation.JOINED) ||
            !context.getSystemService(UserManager::class.java).isUserUnlocked) return
        VpnNotifications.channels(context)
        if(intent.action==WifiAutomation.JOINED || WifiAutomation.enabled(context)) {
            Controller.initialize(context)
            if(intent.action==WifiAutomation.JOINED) WifiAutomation.joined()
            // Connect or start the monitor before Android may stop this process again.
            val pending=goAsync()
            Thread { try { WifiAutomation.check() } finally { pending?.finish() } }.start()
        }
        if(intent.action!=Intent.ACTION_MY_PACKAGE_REPLACED) return
        val prefs=context.getSharedPreferences("connection-intent",Context.MODE_PRIVATE)
        if(!prefs.getBoolean("requested",false) || prefs.getBoolean("paused",false) || VpnService.prepare(context)!=null) return
        try {context.startForegroundService(Intent(context,SirinVpnService::class.java).setAction("org.sirinvpn.RECOVER"))}
        catch (_:Exception) { /* Android can require the user to reopen the app; retain intent. */ }
    }
}
