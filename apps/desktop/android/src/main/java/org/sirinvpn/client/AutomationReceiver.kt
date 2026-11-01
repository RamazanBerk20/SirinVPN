package org.sirinvpn.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Automation API (docs/android/automation.md). Exported only behind CONTROL_VPN,
 * a dangerous permission the user grants to the automation app. Results are not returned.
 */
class AutomationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        val server = intent.getStringExtra("server")?.trim()
        if (action !in setOf(CONNECT, DISCONNECT, SELECT_SERVER) || action == SELECT_SERVER && server.isNullOrEmpty()) return
        val pending = goAsync()
        val link = ServiceLink(context)
        val finished = AtomicBoolean()
        fun finish() { if (finished.compareAndSet(false, true)) { link.close(); pending.finish() } }
        link.bind()
        // Stay inside the receiver budget; the controller completes accepted commands on its own.
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ finish() }, 9000)
        link.ready.whenComplete { control, error ->
            if (error != null) return@whenComplete finish()
            fun run(command: String, arguments: JSONObject, next: (JSONObject) -> Unit) =
                control.execute(command, arguments.toString(), UUID.randomUUID().toString(), -1, object : IResult.Stub() {
                    override fun complete(result: String) { try { next(JSONObject(result)) } catch (_: Exception) { finish() } }
                })
            try {
                val state = JSONObject(control.snapshot())
                when (action) {
                    DISCONNECT -> run("disconnect_server", JSONObject()) { finish() }
                    // Repeated triggers must not interrupt a connection that already uses the chosen server.
                    CONNECT -> if (state.getString("phase") in RUNNING &&
                        state.getJSONObject("status").opt("server_id") == state.opt("quick_profile")) finish()
                        else { run("connect_saved", JSONObject()) {}; finish() }
                    else -> run("list_servers", JSONObject()) { result ->
                        val servers = result.getJSONArray("ok")
                        val matches = (0 until servers.length()).map { servers.getJSONObject(it) }
                            .filter { it.getString("id") == server || it.getString("name") == server }
                        if (matches.size == 1) run("android_set_quick_profile", JSONObject().put("serverId", matches[0].getString("id"))) { finish() }
                        else finish()
                    }
                }
            } catch (_: Exception) { finish() }
        }
    }
    companion object {
        const val CONNECT = "org.sirinvpn.action.CONNECT"
        const val DISCONNECT = "org.sirinvpn.action.DISCONNECT"
        const val SELECT_SERVER = "org.sirinvpn.action.SELECT_SERVER"
        private val RUNNING = setOf("connected", "connecting", "reconnecting", "waiting_for_network", "degraded")
    }
}
