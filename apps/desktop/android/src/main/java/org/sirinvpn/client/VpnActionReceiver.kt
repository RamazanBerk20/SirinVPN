package org.sirinvpn.client

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.util.UUID

/**
 * Notification and widget control actions. Notification actions always require authentication
 * (VpnNotifications.controlAction), so Android unlocks before delivering them here: a receiver
 * may not start an activity for a notification tap on Android 12+.
 */
class VpnActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val generation = intent.getLongExtra("generation", -1)
        // Only a sender that bypassed Android's authentication arrives while locked: refuse it.
        if (generation < 0 || context.getSystemService(KeyguardManager::class.java).isDeviceLocked) return
        val command = if (intent.action == "org.sirinvpn.CONNECT") "connect_saved" else "disconnect_server"
        val pending = goAsync()
        val link = ServiceLink(context)
        link.control(5000).whenComplete { control, error ->
            try {
                if (error == null) control.execute(command, "{}", UUID.randomUUID().toString(), generation,
                    object : IResult.Stub() { override fun complete(result: String) {} })
            } catch (_: Exception) { /* A dead service cannot report a successful action. */ }
            finally { link.close(); pending.finish() }
        }
    }
}
