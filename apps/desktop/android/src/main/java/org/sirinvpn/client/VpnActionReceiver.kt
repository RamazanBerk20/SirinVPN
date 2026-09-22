package org.sirinvpn.client

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.util.UUID

class VpnActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.getLongExtra("generation",-1) < 0) return
        val command=when(intent.action) {
            "org.sirinvpn.CONNECT" -> "connect_saved"
            "org.sirinvpn.STOP_AUTOMATION" -> "disable_wifi_automation"
            else -> "disconnect_server"
        }
        if (context.getSystemService(KeyguardManager::class.java).isDeviceLocked) {
            context.startActivity(Intent(context, ControlActionActivity::class.java)
                .putExtra("command",command)
                .putExtra("generation", intent.getLongExtra("generation", -2)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return
        }
        val pending = goAsync()
        val link = ServiceLink(context)
        link.bind()
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            link.ready.completeExceptionally(java.util.concurrent.TimeoutException())
        },5000)
        link.ready.whenComplete { control, error ->
            try {
                if(error==null) control.execute(command,"{}",UUID.randomUUID().toString(),intent.getLongExtra("generation",-2),
                    object:IResult.Stub(){override fun complete(result:String){}})
            } catch (_:Exception) { /* A dead service cannot report a successful action. */ }
            finally {link.close();pending.finish()}
        }
    }
}
