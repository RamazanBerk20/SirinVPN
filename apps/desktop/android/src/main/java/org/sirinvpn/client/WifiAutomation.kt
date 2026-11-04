package org.sirinvpn.client

import android.Manifest
import android.app.ActivityManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiInfo
import android.provider.Settings
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Android side of Wi-Fi auto-connect (docs/android/security-and-platform.md): Wi-Fi identity, the wake-ups
 * that see the next network while the app is closed, and WifiRule's actions. Runs in :vpn.
 */
object WifiAutomation {
    const val JOINED = "org.sirinvpn.WIFI_JOINED"
    private lateinit var context: Context
    // One check at a time; one more queued covers every change that arrives meanwhile.
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1), ThreadPoolExecutor.DiscardPolicy())
    @Volatile private var status = "disabled"
    @Volatile private var revision = 0L
    // Unknown after a process start: the first check re-applies both.
    private var joinArmed: Boolean? = null
    @Volatile var monitoring = false
    private val preferences get() = context.getSharedPreferences("connection-intent", Context.MODE_PRIVATE)

    fun initialize(application: Context) { context = application.applicationContext }
    /** Boot and update receivers decide from this without loading native code. */
    fun enabled(context: Context) = context.getSharedPreferences("connection-intent", Context.MODE_PRIVATE).getBoolean("wifi_auto", false)
    fun changed() { if (::context.isInitialized) worker.execute(::check) }
    /** A saved policy, trust or server change is a new entry, as on desktop. The caller checks once it is idle. */
    fun policyChanged() { revision++; preferences.edit().remove("wifi_attempted").commit() }
    /** The one-shot join callback was delivered and Android released it. */
    @Synchronized fun joined() { joinArmed = false }

    @Synchronized fun check() {
        val observed = Controller.network
        val seen = revision
        val state = try { JSONObject(Native.call("get_wifi_policy", "{\"automation\":true}", Controller.generation())).optJSONObject("ok") }
            catch (_: Exception) { null } ?: return
        val policy = state.getJSONObject("policy")
        val enabled = policy.optBoolean("enabled")
        if (enabled != enabled(context)) preferences.edit().putBoolean("wifi_auto", enabled).commit()
        synchronized(Controller) {
            // Desktop re-reads before connecting: a newer network or policy gets its own check.
            if (Controller.network != observed || revision != seen) { changed(); return }
            val entry = observed?.let { "${Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, 0)}:${it.networkHandle}" }
            val decision = WifiRule.decide(WifiRule.Input(enabled, state.getString("current_network"), entry,
                preferences.getString("wifi_attempted", null), Controller.sessionActive(), Controller.busy(), VpnService.prepare(context) == null,
                Controller.failed(), Controller.wifiPresent()))
            status = decision.status
            // Save the entry before connecting: a cancelled or failed attempt never repeats on this network.
            if (decision.remember) preferences.edit().putString("wifi_attempted", entry).commit()
            if (decision.connect) Controller.execute("connect_saved", JSONObject().put("serverId", policy.getString("server_id")).toString(),
                UUID.randomUUID().toString(), Controller.generation(), Controller.ignoreResult)
            join(decision.watch == WifiRule.Watch.WIFI_JOIN)
            monitor(decision.watch == WifiRule.Watch.MONITOR)
        }
    }

    /** get_wifi_policy for the UI: the rule's status and what Android still needs from the user. */
    fun decorate(response: String): String {
        val result = JSONObject(response)
        val ok = result.optJSONObject("ok") ?: return response
        val fine = context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val always = fine && context.checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED
        ok.put("automation_status", if (ok.getJSONObject("policy").optBoolean("enabled")) status else "disabled")
            .put("android_access", JSONObject().put("location", if (always) "always" else if (fine) "while_in_use" else "denied")
                .put("location_enabled", context.getSystemService(LocationManager::class.java).isLocationEnabled)
                .put("background_restricted", context.getSystemService(ActivityManager::class.java).isBackgroundRestricted))
        return result.toString()
    }

    /** NativePlatform.wifi(): the default underlying network's identity, or why it has none. */
    fun identity(): String {
        val network = Controller.network ?: return "{}"
        val manager = context.getSystemService(ConnectivityManager::class.java)
        if (manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) != true)
            return JSONObject().put("wifi", false).put("trustable", false).put("identifier", "android-network:v1:${network.networkHandle}").toString()
        // Without precise location Android hides the name anyway; a background read can still be refused.
        val info = if (context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) null
            else try { located(manager, network) } catch (_: Exception) { null }
        val identifier = WifiRule.identifier(info?.ssid, info?.let { WifiRule.securityClass(it.currentSecurityType) })
        return JSONObject().put("wifi", true).put("trustable", identifier != null)
            // Without a readable name each connection is its own untrusted network: fail safe, connect.
            .put("identifier", identifier ?: "android-wifi:v2:unknown:${network.networkHandle}")
            .put("name", if (identifier != null) info!!.ssid.removeSurrounding("\"") else JSONObject.NULL).toString()
    }

    /** Only a callback asking for location info sees the SSID; getNetworkCapabilities always hides it. */
    private fun located(manager: ConnectivityManager, network: Network): WifiInfo? {
        val result = CompletableFuture<WifiInfo?>()
        val callback = object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
            override fun onCapabilitiesChanged(value: Network, capabilities: NetworkCapabilities) {
                if (value == network) result.complete(capabilities.transportInfo as? WifiInfo)
            }
        }
        manager.registerNetworkCallback(NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(), callback)
        return try { result.get(2, TimeUnit.SECONDS) } finally { manager.unregisterNetworkCallback(callback) }
    }

    /**
     * Android sends a PendingIntent network callback once, immediately if a Wi-Fi network already exists, and
     * releases it 5 s after delivery by Intent.filterEquals. Arm it only off Wi-Fi, each time with a new URI.
     */
    private fun join(on: Boolean) {
        if (joinArmed == on) return
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val number = preferences.getLong("wifi_join", 0)
        fun intent(value: Long) = PendingIntent.getBroadcast(context, 0, Intent(JOINED, android.net.Uri.parse("sirin-wifi://joined/$value"),
            context, ReplacementReceiver::class.java), PendingIntent.FLAG_IMMUTABLE)
        intent(number).also { manager.unregisterNetworkCallback(it); it.cancel() }
        if (on) {
            preferences.edit().putLong("wifi_join", number + 1).commit()
            manager.registerNetworkCallback(NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(), intent(number + 1))
        }
        joinArmed = on
    }

    private fun monitor(on: Boolean) {
        if (on == monitoring) return
        try {
            if (on) context.startForegroundService(Intent(context, WifiWatchService::class.java))
            else context.startService(Intent(context, WifiWatchService::class.java).setAction(WifiWatchService.STOP))
        } catch (_: Exception) { /* Android refused a background start; the next check or app start retries. */ }
    }
}
