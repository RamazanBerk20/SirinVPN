package org.sirinvpn.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.Process
import android.os.RemoteCallbackList
import android.os.SystemClock
import android.service.quicksettings.TileService
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** One controller per :vpn process. UI clients only bind to ControlService. */
object Controller {
    private lateinit var context: Context
    private val worker = java.util.concurrent.ThreadPoolExecutor(1,1,0,TimeUnit.MILLISECONDS,java.util.concurrent.ArrayBlockingQueue(2))
    private val readers = java.util.concurrent.ThreadPoolExecutor(2,2,0,TimeUnit.MILLISECONDS,java.util.concurrent.ArrayBlockingQueue(32))
    // Local settings must not wait behind network requests or an interrupted connection.
    private val preferenceWorker = Executors.newSingleThreadExecutor()
    private val monitor = Executors.newSingleThreadScheduledExecutor()
    // Monotonic across process recreation as well as within this process.
    private val epoch = AtomicLong(SystemClock.elapsedRealtime() * 1000)
    private var sequence = 0L
    private val listeners = RemoteCallbackList<IStatus>()
    val engineLock: Any get() = this
    @Volatile var network: Network? = null
    @Volatile var handle = -1
    @Volatile private var phase = "disconnected"
    private var active: String? = null
    private var tunnelConfiguration: JSONObject? = null
    private var quality:JSONObject?=null
    private var mtu:JSONObject?=null
    private var measuredGeneration=-1L
    private var measuredMtu:Triple<Network?,String,Int>?=null
    private var started = 0L
    private var rx: Long? = null
    private var tx: Long? = null
    private var counterSampledAt = 0L
    private var handshake: Long? = null
    private var health = TunnelHealth()
    private var error: String? = null
    private var initialized = false
    private var operation = false
    private var switching = false
    private var protectedTransition=false
    private var operationState:JSONObject?=null
    private var paused = false
    private var attempts = 0
    private var retryAt = 0L
    private var sampling: java.util.concurrent.ScheduledFuture<*>? = null
    private var tileState = ""
    private var wifiPolicy: JSONObject? = null
    private var wifiAttempt: String? = null
    private var wifiAttemptNetwork: Network? = null
    private val wifiReading = java.util.concurrent.atomic.AtomicBoolean(false)
    private var lastCommand = "connect_saved"
    private var lastArguments = "{}"
    private var retryEnabled = false
    private var reconnectOverride: Boolean? = null
    private var pendingServer: String? = null
    private var wifiRequested = false
    private var settingsUpdating = false
    private var wifiRevision = 0L
    private var wifiRefreshPending = false
    private var pausedNetwork: Network? = null
    private var systemStartRequested = false
    private fun retryRequested() = retryEnabled || systemStartRequested || SirinVpnService.instance?.isAlwaysOn == true
    private val requests = LinkedHashMap<String, String>()
    private val exports=LinkedHashMap<String,Long>()
    private val networks = LinkedHashMap<Network,NetworkCapabilities>()
    private val preferences get() = context.getSharedPreferences("connection-intent", Context.MODE_PRIVATE)

    @Synchronized fun initialize(application: Context) {
        if (initialized) return
        context = application.applicationContext
        check(Native.initialize(context.noBackupFilesDir.absolutePath, NativePlatform(context)))
        paused = preferences.getBoolean("paused", false)
        wifiRequested = preferences.getBoolean("wifi_requested", false)
        val appPrefs = context.getSharedPreferences("application-preferences", 0)
        if (!appPrefs.contains("notifications")) {
            val legacy = context.getSharedPreferences("presentation", 0)
            check(appPrefs.edit().putBoolean("notifications", legacy.getBoolean("notifications", true))
                .putBoolean("animations", legacy.getBoolean("animations", true)).commit())
        }
        if (preferences.contains("maintenance")) {
            error = "A server operation was interrupted. Review its current state and retry the same operation."
            operationState=JSONObject().put("command",preferences.getString("maintenance","")).put("phase","interrupted")
        }
        initialized = true
        wifiPolicy=JSONObject(Native.call("get_wifi_policy","{}",epoch.get())).optJSONObject("ok")
        var interrupted=false
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            val last=context.getSystemService(android.app.ActivityManager::class.java).getHistoricalProcessExitReasons(null,0,16)
                .firstOrNull { it.processName.endsWith(":vpn") }
            if (last?.reason==android.app.ApplicationExitInfo.REASON_USER_REQUESTED && last.timestamp >= preferences.getLong("request_time_ms",0)) {
                paused=true;preferences.edit().putBoolean("paused",true).putBoolean("requested",false).commit()
            }
            interrupted=last!=null && last.timestamp>=preferences.getLong("request_time_ms",0) && last.reason in setOf(
                android.app.ApplicationExitInfo.REASON_CRASH,android.app.ApplicationExitInfo.REASON_CRASH_NATIVE,
                android.app.ApplicationExitInfo.REASON_LOW_MEMORY,android.app.ApplicationExitInfo.REASON_SIGNALED)
        }
        val manager = context.getSystemService(ConnectivityManager::class.java)
        manager.registerNetworkCallback(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), object : ConnectivityManager.NetworkCallback() {
            override fun onLost(value: Network) {
                synchronized(Controller) { networks.remove(value) };selectNetwork()
            }
            override fun onCapabilitiesChanged(value:Network,capabilities:NetworkCapabilities) {
                synchronized(Controller) {networks[value]=capabilities};selectNetwork()
            }
        })
        // A bound controller can be recreated before Android restarts the VPN.
        // Reconstruct once after a known involuntary exit, only if Android permits
        // the foreground start. Never infer this from persisted intent alone.
        if(interrupted && SirinVpnService.instance==null && needsReconstruction()) {
            try {context.startForegroundService(Intent(context,SirinVpnService::class.java).setAction("org.sirinvpn.RECOVER"))}
            catch (_:Exception) {error="Android deferred VPN recovery. Open SirinVPN and reconnect."}
        }
    }

    private fun selectNetwork() {
        val changed=synchronized(this) {
            fun score(cap:NetworkCapabilities)=
                (if(cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 100 else 0)+
                (if(cap.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) 3 else if(cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) 2 else 1)
            val best=networks.maxByOrNull { score(it.value) }
            val next=if(network!=null && networks[network]?.let { score(it)==best?.value?.let(::score) }==true) network else best?.key
            (next!=network).also { network=next }
        }
        if(changed) networkChanged() else refreshWifi()
    }

    @Synchronized fun prepareConnection(args:JSONObject,generation:Long) {
        check(current(generation))
        pendingServer=args.getString("serverId")
        reconnectOverride?.let { args.getJSONObject("preferences").getJSONObject("policy").put("automatic_reconnect",it) }
        lastCommand="connect_saved";lastArguments=args.toString()
        retryEnabled=args.getJSONObject("preferences").getJSONObject("policy").optBoolean("automatic_reconnect")
        preferences.edit().putString("requested_arguments",lastArguments).putString("active_profile",pendingServer).commit()
    }
    @Synchronized fun effectiveMtu(config:JSONObject):Int {
        val measured=measuredMtu
        return if(config.optBoolean("mtu_automatic") && measured?.first==network && measured?.second==config.getString("server_id"))
            minOf(config.getInt("mtu"),measured!!.third) else config.getInt("mtu")
    }
    @Synchronized fun qualityState(generation:Long):JSONObject? =
        if(current(generation) && !operation && phase=="connected" && handle>=0)
            tunnelConfiguration?.let {JSONObject(it.toString())} else null
    @Synchronized fun handoff(config:JSONObject,generation:Long):Boolean {
        val current=qualityState(generation) ?: return false
        if(!current.optBoolean("automatic_transport") || current.getString("endpoint")!=config.getString("previous") || current.getInt("mtu")>config.getInt("maximum_mtu")) return false
        if(!WireGuard.endpoint(handle,"public_key=${current.getString("peer")}\nendpoint=${config.getString("endpoint")}\n")) return false
        switching=true
        tunnelConfiguration!!.put("endpoint",config.getString("endpoint"))
        return true
    }
    @Synchronized fun qualityResult(value:JSONObject?,generation:Long) {
        if(!current(generation)) return
        switching=false
        if(value==null || qualityState(generation)==null) return
        quality=value
        value.optString("selected_transport").takeIf {it.isNotEmpty()}?.let {tunnelConfiguration?.put("transport",it)}
        publish()
    }

    @Synchronized private fun startSampling() {
        if (sampling == null && !paused && preferences.getBoolean("requested",false)) sampling = monitor.scheduleWithFixedDelay({ sample() }, 1, 1, TimeUnit.SECONDS)
    }
    fun current(generation: Long) = epoch.get() == generation
    fun generation() = epoch.get()
    @Synchronized fun needsReconstruction() = initialized && phase=="disconnected" && handle<0 && !operation && !paused && preferences.getBoolean("requested",false)
    @Synchronized fun exported(uri:String) {
        exports[uri]=SystemClock.elapsedRealtime()
        while(exports.size>8) exports.remove(exports.keys.first())
    }
    @Synchronized fun snapshot(): JSONObject {
        val service = SirinVpnService.instance
        val lockdown = service?.isLockdownEnabled == true
        val config = tunnelConfiguration
        val local = JSONObject().put("state", when (phase) {
            "waiting_for_network", "reconnecting" -> "connecting"
            "paused", "permission_required" -> "disconnected"
            else -> phase
        }).put("interface_name", "SirinVPN").put("server_id", active ?: pendingServer ?: JSONObject.NULL)
            .put("rx_bytes", rx ?: 0).put("tx_bytes", tx ?: 0)
            .put("byte_counters_available", rx != null && tx != null)
            .put("counter_sampled_at_ms", if (rx != null && tx != null) counterSampledAt else JSONObject.NULL)
            .put("traffic_metrics_supported", true).put("counter_epoch", if (handle >= 0) "$started:$handle" else JSONObject.NULL)
            .put("tunnel_uptime_seconds", if (handle >= 0) (SystemClock.elapsedRealtime() - started) / 1000 else JSONObject.NULL)
            .put("last_handshake_seconds_ago", handshake?.let { System.currentTimeMillis() / 1000 - it } ?: JSONObject.NULL)
            .put("ipv6_blocked", config?.optBoolean("ipv6_blocked") ?: false)
            .put("ipv6_tunneled", config?.optBoolean("ipv6_tunneled") ?: false)
            .put("kill_switch_enabled", lockdown).put("kill_switch_state", if (lockdown) "blocking" else "off")
            .put("always_on",service?.isAlwaysOn==true).put("lockdown",lockdown)
            .put("supervisor_status_known",true).put("endpoint_updates_supported",true)
            .put("auto_reconnect_enabled", retryEnabled)
            .put("transport_fallback_enabled", config?.optBoolean("automatic_transport") == true)
            .put("routing_mode", config?.optString("routing_mode") ?: "full_tunnel")
            .put("allow_lan", config?.optBoolean("allow_lan") ?: false)
            .put("transport", config?.optString("transport") ?: JSONObject.NULL)
            .put("connection_control_supported", true).put("https_transport_supported", true)
            .put("application_routing_supported", true).put("application_routing_backend", "android_packages")
            .put("application_routing_ready", handle >= 0 && config?.optJSONObject("applications") != null)
            .put("mtu_detection_supported",true).put("mtu",mtu ?: JSONObject.NULL)
            .put("transport_quality_supported",true).put("transport_quality",quality ?: JSONObject.NULL)
            .put("independent_policy_supported", true).put("startup_service_enabled", service?.isAlwaysOn == true)
        return JSONObject().put("status", local).put("phase", phase).put("generation", epoch.get())
            .put("sequence", sequence).put("stale", false).put("always_on", service?.isAlwaysOn == true)
            .put("lockdown", lockdown).put("operation_in_progress", operation)
            .put("operation",operationState ?: JSONObject.NULL)
            .put("wifi_automation_enabled",wifiPolicy?.optJSONObject("policy")?.optBoolean("enabled")==true)
            .put("error", error ?: JSONObject.NULL).put("quick_profile", preferences.getString("profile", null) ?: JSONObject.NULL)
            .put("automation_paused", paused).put("observed_elapsed_ms", SystemClock.elapsedRealtime())
    }

    @Synchronized fun activated(config: JSONObject, generation: Long) {
        check(current(generation))
        active = config.getString("server_id")
        // Never retain WireGuard configuration (contains a private key) as presentation state.
        tunnelConfiguration = JSONObject(config.toString()).apply { remove("wireguard") }
        reconnectOverride?.let { tunnelConfiguration!!.put("automatic_reconnect",it) }
        started = SystemClock.elapsedRealtime(); rx = null; tx = null; handshake = null
        health = TunnelHealth()
        phase = "connecting"; error = null
        quality=null;mtu=null
        publish()
    }
    fun stopWireGuard() {
        switching=false
        if (handle >= 0) { val previous = handle; handle = -1; WireGuard.stop(previous) }
    }
    fun stopEngine() {
        stopWireGuard()
        Native.stopTransport()
        rx = null; tx = null; handshake = null
        health = TunnelHealth()
        if (phase == "connected") phase = "unknown"
    }
    @Synchronized fun serviceDestroyed() {
        if(handle>=0) Native.generation(epoch.incrementAndGet())
        stopEngine()
        if (initialized) publish()
    }
    @Synchronized fun subscribe(listener: IStatus) { listeners.register(listener); listener.changed(snapshot().toString()) }
    fun unsubscribe(listener: IStatus) { listeners.unregister(listener) }
    @Synchronized fun publish() {
        sequence++
        val value = snapshot().toString()
        val count = listeners.beginBroadcast()
        try { for (i in 0 until count) try { listeners.getBroadcastItem(i).changed(value) } catch (_: Exception) {} }
        finally { listeners.finishBroadcast() }
        val tile = "$phase:${preferences.getString("profile", null)}:${SirinVpnService.instance?.isAlwaysOn}"
        if (tile != tileState) { tileState = tile; TileService.requestListeningState(context, ComponentName(context, SirinTileService::class.java)) }
        SirinVpnService.instance?.let { VpnNotifications.update(it, snapshot()) }
    }

    fun execute(command: String, arguments: String, requestId: String, expected: Long, callback: IResult,
                retry: Boolean = false, wifi: Boolean = false) {
        if (arguments.length > 131072 || requestId.length > 80) { callback.complete(failure("Request too large.")); return }
        if (command in setOf("get_app_preferences", "set_app_preferences")) {
            try {
                val prefs = context.getSharedPreferences("application-preferences", 0)
                synchronized(this) {
                    if (command == "set_app_preferences") {
                        val value = JSONObject(arguments).getJSONObject("preferences")
                        check(prefs.edit().putBoolean("notifications", value.getBoolean("notifications"))
                            .putBoolean("animations", value.getBoolean("animations")).commit())
                        if (!value.getBoolean("notifications")) VpnNotifications.clearFailure(context)
                    }
                    callback.complete(success(JSONObject().put("preferences", JSONObject()
                        .put("notifications", prefs.getBoolean("notifications", true))
                        .put("animations", prefs.getBoolean("animations", true))
                        .put("start_on_login", false).put("launch_minimized", false).put("close_to_tray", false))
                        .put("startup_available", false).put("tray_available", false)
                        .put("notification_permission", if (context.getSystemService(android.app.NotificationManager::class.java).areNotificationsEnabled()) "granted" else "denied")
                        .put("font_scale", context.resources.configuration.fontScale)))
                }
            } catch (_: Exception) { callback.complete(failure("App preferences could not be saved or read.")) }
            return
        }
        if(command=="android_dismiss_operation") {
            synchronized(this) {
                if(!operation) {operationState=null;preferences.edit().remove("maintenance").commit();publish()}
            }
            callback.complete(success());return
        }
        if(command=="authorize_document_share") {
            val uri=try {JSONObject(arguments).getString("uri")} catch (_:Exception) {""}
            val allowed=synchronized(this) { exports[uri]?.let {SystemClock.elapsedRealtime()-it<600000}==true }
            callback.complete(if(allowed) success() else failure("Export the encrypted file again before sharing it."));return
        }
        if (command == "remember_secret") {
            try { callback.complete(success(SecretInputs.remember(JSONObject(arguments).getString("value")))) }
            catch (_: Exception) { callback.complete(failure("Protected input could not be retained.")) }
            return
        }
        if (command == "reveal_secret") {
            try { callback.complete(success(SecretInputs.reveal(JSONObject(arguments).getString("reference")))) }
            catch (_: Exception) { callback.complete(failure("Protected value expired. Enter or create it again.")) }
            return
        }
        synchronized(this) {
            requests[requestId]?.let { callback.complete(it); return }
        }
        if (command in setOf("disconnect_server", "cancel_connection")) {
            synchronized(this) {
            if (SirinVpnService.instance?.isAlwaysOn == true) { callback.complete(failure("Android Always-on controls this connection. Open VPN settings.")); return }
            if (expected >= 0 && !current(expected)) { callback.complete(failure("The connection changed. Refresh its status.")); return }
            if (operation && (protectedTransition || phase !in setOf("connecting", "reconnecting", "waiting_for_network"))) { callback.complete(failure("Finish the current protected operation before stopping.")); return }
            stop(true); callback.complete(success(snapshot().getJSONObject("status"))); return
            }
        }
        if (command == "local_status") {
            synchronized(this) {
                refreshStatistics()
                callback.complete(success(snapshot().getJSONObject("status")))
            }
            return
        }
        val transition=command in setOf("rotate_device_keys","apply_endpoint_update","publish_endpoint_update")
        val connection = transition || command in setOf("connect_server", "connect_server_with_policy", "connect_saved", "reconnect_server", "resume_server", "join_server", "recover_owner_access")
        val maintenance = transition || command in setOf("provision_server","repair_server","uninstall_server","export_server_backup","import_server_backup","export_vps_backup","restore_vps_backup","export_recovery_package","import_recovery_package","inspect_server_network","check_release_update","install_release_update","prepare_vps_baseline","install_vps_baseline","manage_vps_release","save_ssh_login")
        val readOnly = command in setOf("list_servers", "get_connection_preferences", "key_rotation_pending", "server_status", "server_configuration", "membership", "get_ssh_login", "get_wifi_policy", "recovery_settings", "available_endpoint_update", "local_component_update_status", "current_network_profile")
        val setting = command in setOf("set_connection_preferences", "android_set_reconnect", "set_wifi_policy", "disable_wifi_automation", "trust_current_wifi", "forget_trusted_wifi")
        val wifiSetting = setting && command !in setOf("set_connection_preferences", "android_set_reconnect")
        var previousHandle=-1
        var previousPhase="unknown"
        val generation: Long
        synchronized(this) {
            if ((operation && !readOnly && (!setting || protectedTransition || phase !in setOf("connecting", "reconnecting", "waiting_for_network"))) || settingsUpdating && !readOnly) {
                callback.complete(failure("Another operation is in progress.")); return
            }
            if (retry && (paused || !preferences.getBoolean("requested", false) || !retryRequested())) { callback.complete(success()); return }
            if (wifi && (paused || !wifiEnabled() || wifiPolicy?.optString("current_network") != "untrusted_wifi")) { callback.complete(success()); return }
            if(switching && !connection && !readOnly && !setting) {callback.complete(failure("A transport handoff is being verified. Retry in a moment."));return}
            if (expected >= 0 && !current(expected)) { callback.complete(failure("The connection changed. Refresh its status.")); return }
            if (connection && VpnService.prepare(context) != null) {
                phase = "permission_required"; publish(); callback.complete(failure("VPN permission is required.")); return
            }
            if (setting) { settingsUpdating=true; if(wifiSetting) wifiRevision++ }
            else if (!readOnly) {operation = true;protectedTransition=transition}
            if (connection) {
                previousHandle=handle;previousPhase=phase
                if(callback !== ignoreResult) {
                    attempts=0;measuredMtu=null
                    if(SirinVpnService.instance?.isAlwaysOn!=true) systemStartRequested=false
                }
                if (callback !== ignoreResult) wifiRequested=false
                if (wifi) wifiRequested=true
                pendingServer=try { JSONObject(arguments).optString("serverId").takeIf { it.isNotEmpty() }
                    ?: preferences.getString("profile", null) } catch (_: Exception) { null }
                retryAt=0; retryEnabled=false; reconnectOverride=null
                Native.generation(epoch.incrementAndGet()); paused = false; error = null
                phase = if (network == null) "waiting_for_network" else "connecting"
                preferences.edit().putBoolean("paused", false).putBoolean("requested", true).putBoolean("wifi_requested",wifiRequested)
                    .putLong("request_time_ms",System.currentTimeMillis()).commit()
            }
            generation = epoch.get()
        }
        if (connection) startSampling()
        if(connection) VpnNotifications.clearFailure(context)
        if (maintenance) try {
            context.startForegroundService(Intent(context,MaintenanceService::class.java))
            preferences.edit().putString("maintenance",command).commit()
            synchronized(this) {operationState=JSONObject().put("command",command).put("phase","running")}
        } catch (_:Exception) {
            synchronized(this) { operation=false;publish() }
            callback.complete(failure("Open SirinVPN to start this server operation."));return
        }
        if (connection) try {
            context.startForegroundService(Intent(context, SirinVpnService::class.java).setAction("org.sirinvpn.START").putExtra("generation",generation))
        } catch (_: Exception) {
            synchronized(this) { operation = false; phase = "failed"; error = "Android could not start the VPN service."; publish() }
            callback.complete(failure("Open SirinVPN to start the VPN.")); return
        }
        publish()
        try { (if (setting) preferenceWorker else if (readOnly) readers else worker).execute {
            val result = try {
                if (connection) {
                    val deadline = SystemClock.elapsedRealtime() + 4000
                    while (SirinVpnService.instance?.accepts(generation)!=true && current(generation) && SystemClock.elapsedRealtime() < deadline) Thread.sleep(20)
                    check(SirinVpnService.instance?.accepts(generation)==true && current(generation))
                }
                val args = SecretInputs.resolve(JSONObject(arguments)) as JSONObject
                val effective = if (command == "connect_saved") {
                    if (!args.has("serverId")) args.put("serverId", preferences.getString("profile", null) ?: error("Choose a quick-connect profile in SirinVPN."))
                    "connect_saved"
                } else command
                var response = Native.call(effective, args.toString(), generation)
                if (setting && JSONObject(response).has("ok")) synchronized(this) {
                    if (wifiSetting) {
                        // Apply stored policy before acknowledging the switch; older reads cannot restore it.
                        val enabledBefore=wifiEnabled()
                        if (command == "set_wifi_policy") wifiPolicy?.put("policy", args.getJSONObject("policy"))
                        if (wifiEnabled() && !enabledBefore) {
                            paused=false; pausedNetwork=null
                            preferences.edit().putBoolean("paused", false).remove("paused_wifi").commit()
                        }
                        if (command == "disable_wifi_automation") wifiPolicy?.getJSONObject("policy")?.put("enabled", false)
                        wifiAttempt=null
                        if (!wifiEnabled() && wifiRequested && phase != "connected" && !protectedTransition && SirinVpnService.instance?.isAlwaysOn != true) stop(true)
                    } else applyReconnectPreference(args.getString("serverId"), JSONObject(response).getJSONObject("ok").getJSONObject("policy").getBoolean("automatic_reconnect"))
                }
                if(command=="android_set_quick_profile" && JSONObject(response).has("ok")) preferences.edit().putString("profile",args.getString("serverId")).commit()
                if(command=="remove_server" && JSONObject(response).has("ok")) {
                    val removed=args.getString("serverId")
                    val update=preferences.edit()
                    if(preferences.getString("profile",null)==removed) update.remove("profile")
                    if(preferences.getString("active_profile",null)==removed) update.remove("active_profile")
                    update.commit()
                }
                if (command=="get_wifi_policy") {
                    val result=JSONObject(response)
                    result.optJSONObject("ok")?.put("automation_status",wifiStatus(result.getJSONObject("ok")))
                    response=result.toString()
                }
                if (command in setOf("create_invitation","create_recovery_key","import_recovery_package")) {
                    val protected = JSONObject(response)
                    protected.optJSONObject("ok")?.let { output ->
                        for (key in listOf("code","key")) if (output.has(key)) output.put(key,SecretInputs.remember(output.getString(key),output.optJSONArray("qr_modules")))
                        output.remove("qr_modules")
                        output.put("qr_svg","")
                    }
                    response = protected.toString()
                }
                if (connection && JSONObject(response).has("ok")) synchronized(this) {
                    if (current(generation)) {
                        active?.let {
                            val update = preferences.edit().putString("active_profile",it)
                            if (!preferences.contains("profile")) update.putString("profile",it)
                            update.commit()
                        }
                        if(command in setOf("join_server","recover_owner_access")) {
                            lastCommand = "connect_saved"; lastArguments = JSONObject().put("serverId", active).toString()
                            retryEnabled=tunnelConfiguration?.optBoolean("automatic_reconnect")==true
                            preferences.edit().putString("requested_arguments",lastArguments).commit()
                        }
                        attempts = 0; phase = "connected"; error = null
                    }
                }
                if (connection && !transition && effective !in setOf("join_server", "recover_owner_access") && JSONObject(response).has("ok")) success(snapshot().getJSONObject("status")) else response
            } catch (_: Exception) { failure("The operation could not finish. Check permissions, configuration and network access.") }
            synchronized(this) {
                if (setting) settingsUpdating=false else if (!readOnly) operation = false
                if (maintenance) {
                    operationState=JSONObject().put("command",command).put("phase",if(JSONObject(result).has("error")) "failed" else "completed")
                    preferences.edit().remove("maintenance").commit()
                    context.stopService(Intent(context,MaintenanceService::class.java))
                }
                if (connection && current(generation) && JSONObject(result).has("error")) {
                    if(previousHandle>=0 && handle==previousHandle) {
                        // Local validation can reject a command before touching the
                        // existing engine. Its counters and traffic remain authoritative.
                        phase=previousPhase;error=null
                        retryEnabled=tunnelConfiguration?.optBoolean("automatic_reconnect")==true
                    } else {
                        val shouldRetry=retryRequested()
                        phase = "failed"; error = JSONObject(result).optString("error")
                        synchronized(engineLock) { stopEngine() }
                        if (shouldRetry && !paused && attempts < 8) {
                            phase = if (network == null) "waiting_for_network" else "reconnecting"
                            retryAt = SystemClock.elapsedRealtime() + (1000L shl attempts.coerceAtMost(5)); attempts++
                        } else {
                            preferences.edit().putBoolean("requested", false).commit()
                            sampling?.cancel(false); sampling = null
                            if(wifiPolicy?.optJSONObject("policy")?.optBoolean("enabled")!=true) SirinVpnService.instance?.finishSession()
                            VpnNotifications.failed(context,snapshot())
                        }
                    }
                }
                if (!readOnly && !command.contains("invitation") && !command.contains("recovery")) {
                    requests[requestId] = result
                    while (requests.size > 32) requests.remove(requests.keys.first())
                }
                publish()
                finishIfIdle()
            }
            if (setting || command == "remove_server") refreshWifi()
            try { callback.complete(result) } catch (_: Exception) { /* UI lifetime does not own this operation. */ }
        } } catch (_:java.util.concurrent.RejectedExecutionException) {
            synchronized(this) { if(setting) settingsUpdating=false else if(!readOnly) operation=false }
            if (wifiSetting) refreshWifi()
            callback.complete(failure("Too many pending requests. Retry after the current operation finishes."))
        }
    }
    @Synchronized fun maintenanceTimeout() {
        operationState?.put("phase","interrupted");publish()
    }

    @Synchronized private fun applyReconnectPreference(id: String, enabled: Boolean) {
        if (id != (pendingServer ?: active)) return
        retryEnabled=enabled; reconnectOverride=enabled
        tunnelConfiguration?.put("automatic_reconnect", enabled)
        val arguments=JSONObject(lastArguments)
        arguments.optJSONObject("preferences")?.getJSONObject("policy")?.put("automatic_reconnect", enabled)
        lastArguments=arguments.toString()
        preferences.edit().putString("requested_arguments", lastArguments).commit()
        if (!retryRequested()) {
            val wasWaiting=retryAt>0 || phase in setOf("connecting", "reconnecting", "waiting_for_network")
            retryAt=0
            if (wasWaiting && !protectedTransition) stop(true)
        } else if (!paused && preferences.getBoolean("requested",false) && !operation && phase in setOf("unknown", "waiting_for_network", "reconnecting")) {
            attempts=0; retryAt=SystemClock.elapsedRealtime()+1000; startSampling()
        }
    }
    private fun wifiEnabled() = wifiPolicy?.optJSONObject("policy")?.optBoolean("enabled") == true
    @Synchronized fun finishIfIdle() {
        if (handle<0 && !operation && !preferences.getBoolean("requested",false) && !wifiEnabled()) SirinVpnService.instance?.finishSession()
    }
    @Synchronized fun stop(user: Boolean) {
        Native.generation(epoch.incrementAndGet())
        paused=user; pausedNetwork=network; phase="disconnecting"; retryAt=0; retryEnabled=false; systemStartRequested=false
        pendingServer=null; wifiRequested=false; reconnectOverride=null; lastArguments="{}"; lastCommand="connect_saved"
        sampling?.cancel(false); sampling=null
        preferences.edit().putBoolean("requested", false).putBoolean("paused", user).putBoolean("wifi_requested",false)
            .remove("requested_arguments")
            .putString("paused_wifi", if(user && wifiPolicy?.optBoolean("can_trust_current")==true) wifiPolicy?.optString("current_network_token") else null).commit()
        stopEngine()
        active=null; tunnelConfiguration=null; rx=null; tx=null; phase=if(user) "paused" else "disconnected"
        VpnNotifications.clearFailure(context)
        publish()
        finishIfIdle()
    }
    @Synchronized fun restart(systemStart:Boolean=false) {
        // Android 10's isAlwaysOn() is false until the caller has established a
        // TUN. The permission-protected OS start is itself an explicit request.
        // Null sticky restarts still obey the persisted pause/connection intent.
        if(systemStart || SirinVpnService.instance?.isAlwaysOn==true) {
            systemStartRequested=true
            paused=false;preferences.edit().putBoolean("paused",false).putBoolean("requested",true).commit()
        }
        refreshWifi()
        if(wifiPolicy?.optJSONObject("policy")?.optBoolean("enabled")==true && !preferences.getBoolean("requested",false)) return
        if (paused || !preferences.getBoolean("requested", false) && SirinVpnService.instance?.isAlwaysOn != true) {
            SirinVpnService.instance?.finishSession(); return
        }
        if(operation || handle>=0) return
        val id = preferences.getString("active_profile",null) ?: preferences.getString("profile",null)
        val arguments=JSONObject(preferences.getString("requested_arguments",null) ?: JSONObject().put("serverId",id).toString())
        // Recovery must not revive a retry preference disabled since this intent was recorded.
        val saved=JSONObject(Native.call("get_connection_preferences",JSONObject().put("serverId",id).toString(),epoch.get())).optJSONObject("ok")
        val reconnect=saved?.optJSONObject("policy")?.optBoolean("automatic_reconnect")==true
        if (!reconnect && !systemStartRequested && SirinVpnService.instance?.isAlwaysOn!=true) { stop(true); return }
        arguments.optJSONObject("preferences")?.optJSONObject("policy")?.put("automatic_reconnect",reconnect)
        execute("connect_saved", arguments.toString(), UUID.randomUUID().toString(), epoch.get(), ignoreResult)
    }
    private fun networkChanged() {
        SirinVpnService.instance?.setUnderlyingNetworks(network?.let { arrayOf(it) })
        synchronized(this) {
            if (handle >= 0 && network == null) phase = "waiting_for_network"
            if (network != null && preferences.getBoolean("requested",false) && !paused && retryRequested()) {
                attempts = 0; retryAt = SystemClock.elapsedRealtime() + 1000; phase = "reconnecting"
            } else if(handle>=0 && network!=null) {
                // Existing sockets are bound to the previous network; await an explicit reconnect.
                stopEngine();phase="unknown";error="The underlying network changed. Reconnect to resume VPN traffic."
            }
            publish()
        }
        refreshWifi()
    }
    @Synchronized private fun wifiStatus(policy:JSONObject):String = when {
        policy.getJSONObject("policy").optBoolean("enabled").not() -> "disabled"
        handle>=0 -> "session_active"
        operation -> "connecting"
        paused -> "waiting_for_network_change"
        policy.optString("current_network")=="trusted_wifi" -> "trusted"
        VpnService.prepare(context)!=null -> "needs_authorization"
        else -> "waiting_for_wifi"
    }
    @Synchronized private fun refreshWifi() {
        if (!initialized) return
        wifiRevision++
        if (settingsUpdating || !wifiReading.compareAndSet(false,true)) { wifiRefreshPending=true; return }
        val revision=wifiRevision
        val observedNetwork=network
        wifiRefreshPending=false
        try { readers.execute {
            try {
                val state=JSONObject(Native.call("get_wifi_policy","{}",epoch.get())).optJSONObject("ok") ?: return@execute
                synchronized(this) {
                    if(revision!=wifiRevision || observedNetwork!=network) return@synchronized
                    wifiPolicy=state
                    if(!wifiEnabled()) { finishIfIdle(); publish(); return@synchronized }
                    if(wifiRequested && state.optString("current_network")=="trusted_wifi" && phase!="connected" && !protectedTransition && SirinVpnService.instance?.isAlwaysOn!=true) stop(true)
                    val token=state.optString("current_network_token")
                    // Redaction or late identity availability on the same connection never undoes Stop.
                    if(paused && pausedNetwork!=network && state.optBoolean("can_trust_current") && preferences.contains("paused_wifi") && token!=preferences.getString("paused_wifi",null)) {
                        paused=false;preferences.edit().putBoolean("paused",false).remove("paused_wifi").commit()
                    }
                    if(SirinVpnService.instance==null && VpnService.prepare(context)==null && !paused) {
                        try { context.startForegroundService(Intent(context,SirinVpnService::class.java).setAction("org.sirinvpn.WIFI")) } catch (_:Exception) { return@synchronized }
                    }
                    if(!paused && handle<0 && !operation && !settingsUpdating && !preferences.getBoolean("requested",false) && (wifiAttempt!=token || wifiAttemptNetwork!=network) && state.optString("current_network")=="untrusted_wifi") {
                        val id=state.getJSONObject("policy").optString("server_id")
                        wifiAttempt=token; wifiAttemptNetwork=network
                        execute("connect_saved",JSONObject().put("serverId",id).toString(),UUID.randomUUID().toString(),epoch.get(),ignoreResult,wifi=true)
                    }
                    publish()
                }
            } catch (_:Exception) { /* Missing identity or permission cannot become trusted. */ }
            finally { synchronized(this) {
                wifiReading.set(false)
                if(wifiRefreshPending && !settingsUpdating) refreshWifi()
            } }
        }} catch (_:java.util.concurrent.RejectedExecutionException) { wifiReading.set(false) }
    }
    @Synchronized private fun refreshStatistics() {
        if (handle < 0) return
        try {
            val data = checkNotNull(WireGuard.statistics(handle))
            rx = data[0]; tx = data[1]; handshake = data[2].takeIf { it > 0 }
            counterSampledAt = SystemClock.elapsedRealtime()
            if (handshake != null && network != null && phase != "reconnecting") {
                val healthy = health.record(counterSampledAt, data[0], data[2])
                // A read succeeded: lack of peer progress is degraded reachability,
                // not an unknown local tunnel or protection state.
                if (healthy) retryAt = 0
                phase = if (healthy) "connected" else "degraded"
                if (!healthy && !operation && retryAt == 0L && retryRequested()) retryAt = counterSampledAt + 1000
            }
        } catch (_: Exception) { rx = null; tx = null; phase = "unknown" }
    }
    private fun sample() {
        try {
            val retry = synchronized(this) {
                // Read and apply the same engine's counters under one lock. New
                // authenticated progress cancels a pending inactivity retry.
                refreshStatistics()
                if (!operation && !settingsUpdating && !paused && retryRequested() && preferences.getBoolean("requested",false) && retryAt > 0 && network != null && SystemClock.elapsedRealtime() >= retryAt) {
                    retryAt = 0; Triple(lastCommand,lastArguments,epoch.get())
                } else {
                    if(phase=="connected" && measuredGeneration!=epoch.get()) {
                        val generation=epoch.get();measuredGeneration=generation
                        val config=tunnelConfiguration?.let { JSONObject(it.toString()) }
                        if(config!=null) try { readers.execute {
                            try {
                                val result=PathMeasurements.measure(config) { current(generation) && handle>=0 }
                                synchronized(Controller) { if(current(generation) && handle>=0) {
                                    quality=result.first;mtu=result.second;publish()
                                    val suggested=result.second.optInt("suggested",0)
                                    val minimum=if(config.optBoolean("ipv6_tunneled")) 1280 else 576
                                    if(!operation && config.optBoolean("mtu_automatic") && suggested in minimum until config.getInt("mtu")) {
                                        measuredMtu=Triple(network,config.getString("server_id"),suggested)
                                        execute(lastCommand,lastArguments,UUID.randomUUID().toString(),generation,ignoreResult)
                                    }
                                } }
                                if(current(generation) && config.optBoolean("automatic_transport")) {
                                    Native.call("android_measure_quality","{}",generation)
                                }
                            } catch (_:Exception) { /* Unavailable probes never invent a quality sample. */ }
                        } } catch (_:java.util.concurrent.RejectedExecutionException) { measuredGeneration=-1L }
                    }
                    publish()
                    null
                }
            }
            if (retry != null) execute(retry.first,retry.second,UUID.randomUUID().toString(),retry.third,ignoreResult,retry=true)
        } catch (_: Exception) { synchronized(this) { rx = null; tx = null; phase = "unknown"; publish() } }
    }
    val ignoreResult = object : IResult.Stub() { override fun complete(result: String) {} }
    fun success(value: Any = JSONObject.NULL) = JSONObject().put("ok", value).toString()
    fun failure(message: String) = JSONObject().put("error", message).toString()
}
