package org.sirinvpn.client

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.json.JSONObject
import java.util.UUID

class SirinTileService : TileService() {
    private var link: ServiceLink? = null
    private var snapshot: JSONObject? = null
    private val listener = object : IStatus.Stub() {
        override fun changed(value: String) { mainExecutor.execute { snapshot = JSONObject(value); render() } }
    }
    override fun onStartListening() {
        super.onStartListening()
        link?.close()
        link = ServiceLink(this,lost={ mainExecutor.execute { snapshot = null; render() } },
            connected={ it.subscribe(listener) }).also { it.bind() }
    }
    override fun onStopListening() {
        link?.ready?.getNow(null)?.let { try { it.unsubscribe(listener) } catch (_: Exception) {} }
        link?.close(); link = null; snapshot = null
        super.onStopListening()
    }
    private fun render() {
        val state = snapshot
        qsTile?.apply {
            label = "SirinVPN"
            val phase = state?.optString("phase")
            this.state = when (phase) {
                "connected" -> Tile.STATE_ACTIVE
                "disconnected", "paused", "failed", "permission_required", "connecting", "reconnecting", "waiting_for_network" -> Tile.STATE_INACTIVE
                else -> Tile.STATE_UNAVAILABLE
            }
            subtitle = when (phase) {
                "connected" -> if (state?.optBoolean("always_on") == true) "Always-on" else "Connected"
                "connecting", "reconnecting" -> "Connecting…"
                "waiting_for_network" -> "No network"
                "disconnected", "paused" -> "Disconnected"
                else -> "Open SirinVPN"
            }
            contentDescription = "SirinVPN, $subtitle"
            updateTile()
        }
    }
    override fun onClick() {
        super.onClick()
        if (isLocked && isSecure) unlockAndRun { act() } else act()
    }
    private fun act() {
        // Active tiles stop listening after one update. A tap owns a fresh,
        // short binding; absence of a listening binding is not missing setup.
        val actionLink=ServiceLink(this)
        actionLink.bind()
        android.os.Handler(mainLooper).postDelayed({
            actionLink.ready.completeExceptionally(java.util.concurrent.TimeoutException())
        },5000)
        actionLink.ready.whenComplete {control,error -> mainExecutor.execute {
            try {
                if(error==null) act(control) else {snapshot=null;render()}
            } catch (_:Exception) {snapshot=null;render()}
            finally {actionLink.close()}
        }}
    }
    private fun act(control:IControl) {
        val current = JSONObject(control.snapshot())
        if (current.optBoolean("always_on")) return launch(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
        val command = if (current.getString("phase") in setOf("connected", "connecting", "reconnecting", "waiting_for_network")) "disconnect_server" else "connect_saved"
        if(command=="connect_saved" && current.isNull("quick_profile")) return openApp()
        if(command=="connect_saved" && VpnService.prepare(this)!=null) return launch(Intent(this,ControlActionActivity::class.java)
            .putExtra("command",command).putExtra("generation",current.getLong("generation")))
        control.execute(command, "{}", UUID.randomUUID().toString(), current.getLong("generation"), object : IResult.Stub() {
            override fun complete(result: String) { mainExecutor.execute {
                try {snapshot=JSONObject(control.snapshot())} catch (_:Exception) {snapshot=null}
                render()
            } }
        })
    }
    private fun openApp() = launch(Intent(this, MainActivity::class.java))
    // Android 10–13 have no PendingIntent overload; Android 14+ uses it below.
    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
    private fun launch(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
        else { @Suppress("DEPRECATION") startActivityAndCollapse(intent) }
    }
}
