package org.sirinvpn.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.UserManager

/** Resume existing intent after this package's verified replacement; never after force-stop. */
class ReplacementReceiver:BroadcastReceiver() {
    override fun onReceive(context:Context,intent:Intent) {
        if(intent.action!=Intent.ACTION_MY_PACKAGE_REPLACED || !context.getSystemService(UserManager::class.java).isUserUnlocked) return
        VpnNotifications.channels(context)
        val prefs=context.getSharedPreferences("connection-intent",Context.MODE_PRIVATE)
        if(!prefs.getBoolean("requested",false) || prefs.getBoolean("paused",false) || VpnService.prepare(context)!=null) return
        try {context.startForegroundService(Intent(context,SirinVpnService::class.java).setAction("org.sirinvpn.RECOVER"))}
        catch (_:Exception) { /* Android can require the user to reopen the app; retain intent. */ }
    }
}
