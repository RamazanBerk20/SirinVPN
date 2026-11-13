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
    // Widget rendering reads profiles from disk; keep it off the controller lock, in order.
    private val widgetWorker = Executors.newSingleThreadExecutor()
    // Monotonic across process recreation as well as within this process.
    private val epoch = AtomicLong(SystemClock.elapsedRealtime() * 1000)
    private var sequence = 0L
    private val listeners = RemoteCallbackList<IStatus>()
    val engineLock: Any get() = this
    @Volatile var network: Network? = null
    @Volatile var handle = -1
    /** The connection lifecycle; it changes only through [on]. */
    @Volatile private var session: Session = Session.Idle
    /** The worker's command or an endpoint switch. */
    private var task: Task = Task.None
    /** A settings save runs on its own worker, beside a connection attempt. */
    private var preferenceTask: Task = Task.None
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
    private var operationState:JSONObject?=null
    private var attempts = 0
    private var retryAt = 0L
    private var networkHandoff = false
    private var sampling: java.util.concurrent.ScheduledFuture<*>? = null
    private var tileState = ""
    private var widgetState = ""
    private var lastCommand = "connect_saved"
    private var lastArguments = "{}"
    private var retryEnabled = false
    private var reconnectOverride: Boolean? = null
    private var pendingServer: String? = null
    private var systemStartRequested = false
    private fun retryRequested() = retryEnabled || systemStartRequested || SirinVpnService.instance?.isAlwaysOn == true
    private val requests = LinkedHashMap<String, String>()
    private val exports=LinkedHashMap<String,Long>()
    private val networks = LinkedHashMap<Network,NetworkCapabilities>()
    private val preferences get() = context.getSharedPreferences("connection-intent", Context.MODE_PRIVATE)
    /** Context for user-visible text: the app language also on Android 12/12L. */
    private val text get() = AppLanguage.wrap(context)
    private fun on(event: SessionEvent) { session = session.next(event) }
    private val runningCommand get() = task as? Task.Command
    private val operation get() = task is Task.Command
    private val protectedTransition get() = runningCommand?.protected == true

    /** Saved connection intent. One value, written to both legacy keys that receivers read without native code. */
    private enum class Wanted { NONE, REQUESTED, PAUSED }
    private val intent get() = when {
        preferences.getBoolean("paused", false) -> Wanted.PAUSED
        preferences.getBoolean("requested", false) -> Wanted.REQUESTED
        else -> Wanted.NONE
    }
    private val requested get() = intent == Wanted.REQUESTED
    private val paused get() = intent == Wanted.PAUSED
    private fun saveIntent(value: Wanted, edit: android.content.SharedPreferences.Editor = preferences.edit()) =
        edit.putBoolean("requested", value == Wanted.REQUESTED).putBoolean("paused", value == Wanted.PAUSED).commit()

    // Command classes. A command in none of these sets is an operation: serialized on the worker and busy-checked.
    // Runtime errors arrive as {"error","code","params"} and reach the WebView unchanged.
    /** Connection commands that also change server or key state; Disconnect must not interrupt them. */
    private val transitions = setOf("rotate_device_keys","apply_endpoint_update","publish_endpoint_update")
    private val connections = transitions + setOf("connect_server", "connect_server_with_policy", "connect_saved", "reconnect_server", "resume_server", "join_server", "recover_owner_access")
    /** Finite server or file work that keeps MaintenanceService in the foreground. */
    private val maintenances = transitions + setOf("provision_server","repair_server","uninstall_server","export_server_backup","import_server_backup","export_vps_backup","restore_vps_backup","export_recovery_package","import_recovery_package","inspect_server_network","check_release_update","install_release_update","prepare_vps_baseline","install_vps_baseline","manage_vps_release","save_ssh_login","create_hetzner_server","wait_hetzner_server","delete_hetzner_server","run_scheduled_vps_backup","find_hetzner_server","resolve_install_transaction","abandon_install_transaction","plan_server_operation")
    // The speed test changes nothing on this device, so Disconnect and reconnects need not wait for it.
    private val readOnlyCommands = setOf("list_servers", "get_connection_preferences", "key_rotation_pending", "preshared_key_rotation_recommended", "server_status", "server_configuration", "membership", "get_ssh_login", "recovery_settings", "dns_blocklist_settings", "alert_settings", "available_endpoint_update", "local_component_update_status", "current_network_profile", "cancel_hetzner_wait", "vps_backup_schedules", "run_speed_test", "get_wifi_policy", "install_transaction_status")
    private val wifiSettings = setOf("set_wifi_policy", "trust_current_wifi", "forget_trusted_wifi")
    private val settings = wifiSettings + setOf("set_connection_preferences", "android_set_reconnect")

    @Synchronized fun initialize(application: Context) {
        if (initialized) return
        context = application.applicationContext
        WifiAutomation.initialize(context)
        check(Native.initialize(context.noBackupFilesDir.absolutePath, NativePlatform(context)))
        val appPrefs = context.getSharedPreferences("application-preferences", 0)
        if (!appPrefs.contains("notifications")) {
            val legacy = context.getSharedPreferences("presentation", 0)
            check(appPrefs.edit().putBoolean("notifications", legacy.getBoolean("notifications", true))
                .putBoolean("animations", legacy.getBoolean("animations", true)).commit())
        }
        if (preferences.contains("maintenance")) {
            error = text.getString(R.string.error_server_task_interrupted)
            operationState=JSONObject().put("command",preferences.getString("maintenance","")).put("phase","interrupted")
        }
        initialized = true
        val last=context.getSystemService(android.app.ActivityManager::class.java).getHistoricalProcessExitReasons(null,0,16)
            .firstOrNull { it.processName.endsWith(":vpn") }
        if (last?.reason==android.app.ApplicationExitInfo.REASON_USER_REQUESTED && last.timestamp >= preferences.getLong("request_time_ms",0)) {
            saveIntent(Wanted.PAUSED)
        }
        val interrupted=last!=null && last.timestamp>=preferences.getLong("request_time_ms",0) && last.reason in setOf(
            android.app.ApplicationExitInfo.REASON_CRASH,android.app.ApplicationExitInfo.REASON_CRASH_NATIVE,
            android.app.ApplicationExitInfo.REASON_LOW_MEMORY,android.app.ApplicationExitInfo.REASON_SIGNALED)
        val manager = context.getSystemService(ConnectivityManager::class.java)
        // Know the current underlay now: a Wi-Fi wake or boot check must not see "no network" before callbacks arrive.
        @Suppress("DEPRECATION") for (value in manager.allNetworks) manager.getNetworkCapabilities(value)?.let {
            if (it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)) networks[value]=it
        }
        selectNetwork()
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
            catch (_:Exception) {error=text.getString(R.string.error_vpn_recovery_deferred)}
        }
        // Android 13+ applies a per-app language (also one chosen in Android settings) as a configuration change.
        var locales = context.resources.configuration.locales
        context.registerComponentCallbacks(object : android.content.ComponentCallbacks {
            override fun onConfigurationChanged(configuration: android.content.res.Configuration) {
                if (configuration.locales != locales) { locales = configuration.locales; languageChanged() }
            }
            @Suppress("OVERRIDE_DEPRECATION") override fun onLowMemory() {}
        })
        // Desktop's rule also acts when the app starts, not only on a change.
        WifiAutomation.changed()
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
        if(changed) networkChanged()
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
    /** "engine" names the WireGuard handle, so a refused rollback can still reach the same engine. */
    @Synchronized fun qualityState(generation:Long):JSONObject? =
        if(current(generation) && !operation && session==Session.Connected && handle>=0)
            tunnelConfiguration?.let {JSONObject(it.toString()).put("engine",handle)} else null
    /**
     * Moves the engine's peer to a measured carrier. "mode":"force" is the quality rollback the
     * ordinary checks refused: it needs only the same engine and generation. "mode":"reconnect"
     * rebuilds a tunnel whose engine still points at a stopped relay.
     */
    @Synchronized fun handoff(config:JSONObject,generation:Long):Boolean = when(config.optString("mode")) {
        "force" -> current(generation) && handle>=0 && handle==config.getInt("engine") && moveEndpoint(config.getString("endpoint"))
        "reconnect" -> reconnectEngine(config.getInt("engine"))
        else -> qualityState(generation)?.let { current ->
            current.optBoolean("automatic_transport") && current.getString("endpoint")==config.getString("previous") &&
                current.getInt("mtu")<=config.getInt("maximum_mtu") && moveEndpoint(config.getString("endpoint"))
        } ?: false
    }
    private fun moveEndpoint(endpoint:String):Boolean {
        val configuration=tunnelConfiguration ?: return false
        if(!WireGuard.endpoint(handle,"public_key=${configuration.getString("peer")}\nendpoint=$endpoint\n")) return false
        if(!operation) task=Task.QualitySwitch
        configuration.put("endpoint",endpoint)
        return true
    }
    /** As a carrier handoff after a network change: allowed even when failure retries are off. */
    private fun reconnectEngine(engine:Int):Boolean {
        if(handle<0 || handle!=engine || operation || !requested) return false
        networkHandoff=true;attempts=0;retryAt=SystemClock.elapsedRealtime()
        on(if(network==null) SessionEvent.NetworkLost else SessionEvent.Reconnect)
        startSampling();publish()
        return true
    }
    @Synchronized fun qualityResult(value:JSONObject?,generation:Long) {
        if(!current(generation)) return
        if(task==Task.QualitySwitch) task=Task.None
        if(value==null || qualityState(generation)==null) return
        quality=value
        value.optString("selected_transport").takeIf {it.isNotEmpty()}?.let {tunnelConfiguration?.put("transport",it)}
        publish()
    }

    @Synchronized private fun startSampling() {
        if (sampling == null && requested) sampling = monitor.scheduleWithFixedDelay({ sample() }, 1, 1, TimeUnit.SECONDS)
    }
    // Not the saved intent: it outlives a reboot that, without Always-on, never revives the session. Retries keep the service.
    @Synchronized fun sessionActive() = handle>=0 || SirinVpnService.instance!=null
    @Synchronized fun busy() = operation || preferenceTask != Task.None
    @Synchronized fun failed() = session==Session.Failed
    @Synchronized fun wifiPresent() = networks.values.any { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
    fun current(generation: Long) = epoch.get() == generation
    fun generation() = epoch.get()
    @Synchronized fun needsReconstruction() = initialized && session==Session.Idle && handle<0 && !operation && requested
    @Synchronized fun exported(uri:String) {
        exports[uri]=SystemClock.elapsedRealtime()
        while(exports.size>8) exports.remove(exports.keys.first())
    }
    @Synchronized fun snapshot(): JSONObject {
        val service = SirinVpnService.instance
        val lockdown = service?.isLockdownEnabled == true
        val config = tunnelConfiguration
        val state = when (session) {
            Session.WaitingForNetwork, Session.Recovering -> "connecting"
            Session.Stopped, Session.PermissionRequired, Session.Failed -> "disconnected"
            else -> session.wire
        }
        val server = active ?: pendingServer
        val phase = session.phase(server, networkHandoff || retryAt > 0 || runningCommand?.connection == true)
        val local = JSONObject().put("state", state).put("interface_name", "SirinVPN")
            .put("server_id", if(state=="disconnected") JSONObject.NULL else server ?: JSONObject.NULL)
            // Additive: desktop's LocalTunnelStatus `phase` (Rust TunnelPhase). The top-level `phase` string stays.
            .put("phase", JSONObject().put("kind", phase.kind).apply {
                if (phase.kind != "idle") put("server_id", phase.serverId ?: JSONObject.NULL)
                phase.recovering?.let { put("recovering", it) }
            })
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
            .put("recovery_in_progress", networkHandoff || session == Session.Recovering)
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
        return JSONObject().put("status", local).put("phase", session.wire).put("generation", epoch.get())
            .put("sequence", sequence).put("stale", false).put("always_on", service?.isAlwaysOn == true)
            .put("lockdown", lockdown).put("operation_in_progress", operation)
            .put("operation",operationState ?: JSONObject.NULL)
            .put("error", error ?: JSONObject.NULL).put("quick_profile", preferences.getString("profile", null) ?: JSONObject.NULL)
            .put("observed_elapsed_ms", SystemClock.elapsedRealtime())
    }

    @Synchronized fun activated(config: JSONObject, generation: Long) {
        check(current(generation))
        active = config.getString("server_id")
        // Never retain WireGuard configuration (contains a private key) as presentation state.
        tunnelConfiguration = JSONObject(config.toString()).apply { remove("wireguard") }
        reconnectOverride?.let { tunnelConfiguration!!.put("automatic_reconnect",it) }
        started = SystemClock.elapsedRealtime(); rx = null; tx = null; handshake = null
        health = TunnelHealth()
        on(SessionEvent.Activated); error = null
        quality=null;mtu=null
        publish()
    }
    fun stopWireGuard() {
        if (task == Task.QualitySwitch) task = Task.None
        if (handle >= 0) { val previous = handle; handle = -1; WireGuard.stop(previous) }
    }
    fun stopEngine() {
        stopWireGuard()
        Native.stopTransport()
        rx = null; tx = null; handshake = null
        health = TunnelHealth()
        on(SessionEvent.EngineStopped)
    }
    @Synchronized fun serviceDestroyed() {
        if(handle>=0) Native.generation(epoch.incrementAndGet())
        stopEngine()
        if (initialized) { publish(); WifiAutomation.changed() }
    }
    @Synchronized fun subscribe(listener: IStatus) { listeners.register(listener); listener.changed(snapshot().toString()) }
    fun unsubscribe(listener: IStatus) { listeners.unregister(listener) }
    @Synchronized fun publish() {
        sequence++
        val current = snapshot()
        val value = current.toString()
        val count = listeners.beginBroadcast()
        try { for (i in 0 until count) try { listeners.getBroadcastItem(i).changed(value) } catch (_: Exception) {} }
        finally { listeners.finishBroadcast() }
        val tile = "${session.wire}:${preferences.getString("profile", null)}:${SirinVpnService.instance?.isAlwaysOn}"
        if (tile != tileState) { tileState = tile; TileService.requestListeningState(context, ComponentName(context, SirinTileService::class.java)) }
        SirinVpnService.instance?.let { VpnNotifications.update(it, current) }
        val widget = "${current.getString("phase")}:${current.getJSONObject("status").opt("server_id")}:${current.opt("quick_profile")}:${current.getBoolean("always_on")}:${current.getLong("generation")}"
        if (widget != widgetState) {
            widgetState = widget
            widgetWorker.execute { try { SirinWidget.render(text, current) } catch (_: Exception) { /* A widget must never stop the VPN process. */ } }
        }
    }
    @Synchronized fun refreshWidget() { widgetState = ""; publish() }
    /** Re-render native surfaces in the current app language: channel names, the VPN notice, tile and widget. */
    fun languageChanged() {
        VpnNotifications.channels(context)
        synchronized(this) { tileState = ""; widgetState = ""; VpnNotifications.refresh(); publish() }
    }

    fun execute(command: String, arguments: String, requestId: String, expected: Long, callback: IResult,
                retry: Boolean = false) {
        if (arguments.length > 131072 || requestId.length > 80) { callback.complete(failure(R.string.error_request_too_large)); return }
        // A cancel must not queue behind the reader that runs the speed test.
        if (command == "cancel_speed_test") { callback.complete(Native.call(command, arguments, -1)); return }
        if (command in setOf("get_app_preferences", "set_app_preferences")) {
            try {
                val prefs = context.getSharedPreferences("application-preferences", 0)
                synchronized(this) {
                    if (command == "set_app_preferences") {
                        val value = JSONObject(arguments).getJSONObject("preferences")
                        val theme = value.optString("theme", "system")
                        check(theme in setOf("system", "light", "dark"))
                        // Optional: older UIs omit it. "system" or a BCP-47 tag, validated before anything is saved.
                        val language = if (value.isNull("language")) null else value.get("language") as? String ?: ""
                        check(language == null || AppLanguage.valid(language))
                        check(prefs.edit().putBoolean("notifications", value.getBoolean("notifications"))
                            .putBoolean("animations", value.getBoolean("animations")).putString("theme", theme).commit())
                        if (!value.getBoolean("notifications")) VpnNotifications.clearFailure(context)
                        if (language != null && AppLanguage.set(context, language)) languageChanged()
                    }
                    callback.complete(success(JSONObject().put("preferences", JSONObject()
                        .put("notifications", prefs.getBoolean("notifications", true))
                        .put("animations", prefs.getBoolean("animations", true))
                        .put("theme", prefs.getString("theme", "system"))
                        .put("language", AppLanguage.current(context))
                        .put("start_on_login", false).put("launch_minimized", false).put("close_to_tray", false))
                        .put("startup_available", false).put("tray_available", false)
                        .put("notification_permission", if (context.getSystemService(android.app.NotificationManager::class.java).areNotificationsEnabled()) "granted" else "denied")
                        .put("font_scale", context.resources.configuration.fontScale)))
                }
            } catch (_: Exception) { callback.complete(failure(R.string.error_preferences)) }
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
            callback.complete(if(allowed) success() else failure(R.string.error_share_expired));return
        }
        if (command == "remember_secret") {
            // The field it was typed for is the only argument that may redeem the handle.
            try { JSONObject(arguments).let { callback.complete(success(SecretInputs.remember(it.getString("value"), null, it.getString("field")))) } }
            catch (_: Exception) { callback.complete(failure(R.string.error_protected_input)) }
            return
        }
        if (command == "reveal_secret") {
            try { callback.complete(success(SecretInputs.reveal(JSONObject(arguments).getString("reference")))) }
            catch (_: Exception) { callback.complete(failure(R.string.error_protected_value_expired)) }
            return
        }
        synchronized(this) {
            requests[requestId]?.let { callback.complete(it); return }
        }
        if (command in setOf("disconnect_server", "cancel_connection")) {
            synchronized(this) {
            if (SirinVpnService.instance?.isAlwaysOn == true) { callback.complete(failure(R.string.error_always_on)); return }
            if (expected >= 0 && !current(expected)) { callback.complete(failure(R.string.error_connection_changed)); return }
            if (operation && (protectedTransition || !session.attempting)) { callback.complete(failure(R.string.error_busy_disconnect)); return }
            stop(true); callback.complete(success(snapshot().getJSONObject("status"))); return
            }
        }
        if (command == "local_status") {
            synchronized(this) {
                refreshStatistics()
                publish()
                callback.complete(success(snapshot().getJSONObject("status")))
            }
            return
        }
        val transition = command in transitions
        val connection = command in connections
        val maintenance = command in maintenances
        val readOnly = command in readOnlyCommands
        val wifiSetting = command in wifiSettings
        val setting = command in settings
        var previousHandle=-1
        var previousSession: Session = Session.Unhealthy(false)
        var handoff=false
        val generation: Long
        synchronized(this) {
            if ((operation && !readOnly && (!setting || protectedTransition || !session.attempting)) || preferenceTask != Task.None && !readOnly) {
                callback.complete(failure(R.string.error_busy)); return
            }
            if (retry && (paused || !requested || !retryRequested() && !networkHandoff)) { callback.complete(success()); return }
            if(task==Task.QualitySwitch && !connection && !readOnly && !setting) {callback.complete(failure(R.string.error_switching_method));return}
            if (expected >= 0 && !current(expected)) { callback.complete(failure(R.string.error_connection_changed)); return }
            if (connection && VpnService.prepare(context) != null) {
                // Only the user can grant consent: consume the pending retry or handoff
                // so sample() does not re-run this attempt every second.
                retryAt = 0; networkHandoff = false
                on(SessionEvent.ConsentMissing); publish(); callback.complete(failure(R.string.error_vpn_permission_required)); return
            }
            if (setting) preferenceTask=Task.Settings
            else if (!readOnly) task=Task.Command(command,connection,transition)
            if (connection) {
                previousHandle=handle;previousSession=session
                handoff=networkHandoff
                networkHandoff=false
                if(callback !== ignoreResult) {
                    attempts=0;measuredMtu=null
                    if(SirinVpnService.instance?.isAlwaysOn!=true) systemStartRequested=false
                }
                pendingServer=try { JSONObject(arguments).optString("serverId").takeIf { it.isNotEmpty() }
                    ?: preferences.getString("profile", null) } catch (_: Exception) { null }
                retryAt=0; retryEnabled=false; reconnectOverride=null
                Native.generation(epoch.incrementAndGet()); error = null
                on(SessionEvent.Connect(network != null))
                saveIntent(Wanted.REQUESTED, preferences.edit().putLong("request_time_ms",System.currentTimeMillis()))
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
            synchronized(this) { task=Task.None;publish() }
            callback.complete(failure(R.string.error_server_task_background));return
        }
        if (connection) try {
            context.startForegroundService(Intent(context, SirinVpnService::class.java).setAction("org.sirinvpn.START").putExtra("generation",generation))
        } catch (_: Exception) {
            synchronized(this) { task = Task.None; on(SessionEvent.StartFailed); error = text.getString(R.string.error_vpn_start_failed); publish() }
            callback.complete(failure(R.string.error_vpn_start_failed)); return
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
                if (wifiSetting || command=="remove_server") { if (JSONObject(response).has("ok")) WifiAutomation.policyChanged() }
                else if (setting && JSONObject(response).has("ok")) synchronized(this) {
                    applyReconnectPreference(args.getString("serverId"), JSONObject(response).getJSONObject("ok").getJSONObject("policy").getBoolean("automatic_reconnect"))
                }
                if(command=="get_wifi_policy") response=WifiAutomation.decorate(response)
                if(command=="android_set_quick_profile" && JSONObject(response).has("ok")) preferences.edit().putString("profile",args.getString("serverId")).commit()
                if(command=="remove_server" && JSONObject(response).has("ok")) {
                    val removed=args.getString("serverId")
                    val update=preferences.edit()
                    if(preferences.getString("profile",null)==removed) update.remove("profile")
                    if(preferences.getString("active_profile",null)==removed) update.remove("active_profile")
                    update.commit()
                }
                if (command in setOf("create_invitation","create_recovery_key","import_recovery_package")) {
                    val protected = JSONObject(response)
                    protected.optJSONObject("ok")?.let { output ->
                        for (key in listOf("code","key")) if (output.has(key)) output.put(key,SecretInputs.remember(output.getString(key),output.optJSONArray("qr_modules"),key))
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
                        attempts = 0
                        on(SessionEvent.Established(networkHandoff, network != null))
                        error = null
                    }
                }
                if (connection && !transition && effective !in setOf("join_server", "recover_owner_access") && JSONObject(response).has("ok")) success(snapshot().getJSONObject("status")) else response
            } catch (_: Exception) { failure(R.string.error_operation_failed) }
            synchronized(this) {
                if (setting) preferenceTask=Task.None else if (!readOnly) task = Task.None
                // Renames, removals and restores can change the widget's server name.
                if (!readOnly) widgetState = ""
                if (maintenance) {
                    operationState=JSONObject().put("command",command).put("phase",if(JSONObject(result).has("error")) "failed" else "completed")
                    preferences.edit().remove("maintenance").commit()
                    MaintenanceService.stop(context)
                }
                if (connection && current(generation) && JSONObject(result).has("error")) {
                    if(!handoff && previousHandle>=0 && handle==previousHandle) {
                        // Local validation can reject a command before touching the
                        // existing engine. Its counters and traffic remain authoritative.
                        on(SessionEvent.Rejected(previousSession));error=null
                        retryEnabled=tunnelConfiguration?.optBoolean("automatic_reconnect")==true
                    } else {
                        val shouldRetry=(retryRequested() || networkHandoff || handoff) && !paused && attempts < 8
                        error = JSONObject(result).optString("error")
                        synchronized(engineLock) { stopEngine() }
                        on(SessionEvent.AttemptFailed(shouldRetry, network != null))
                        if (shouldRetry) {
                            // A handoff to a not-yet-usable carrier stays a bounded handoff
                            // even when failure retries are off; the retry consumes it again.
                            if (handoff) networkHandoff = true
                            retryAt = SystemClock.elapsedRealtime() + (1000L shl attempts.coerceAtMost(5)); attempts++
                        } else {
                            networkHandoff=false
                            saveIntent(Wanted.NONE)
                            sampling?.cancel(false); sampling = null
                            SirinVpnService.instance?.finishSession()
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
            // A finished session, task or save can leave Wi-Fi without a VPN; checks during it saw the controller busy.
            if (!readOnly) WifiAutomation.changed()
            try { callback.complete(result) } catch (_: Exception) { /* UI lifetime does not own this operation. */ }
        } } catch (_:java.util.concurrent.RejectedExecutionException) {
            synchronized(this) {
                if(setting) preferenceTask=Task.None else if(!readOnly) task=Task.None
                if (maintenance) {
                    // The foreground service started above; never leave it running for work that was not queued.
                    operationState=JSONObject().put("command",command).put("phase","failed")
                    preferences.edit().remove("maintenance").commit()
                    MaintenanceService.stop(context)
                }
                if (connection) {
                    // The attempt never ran: undo what was prepared for it, as a non-retried failure does.
                    if (previousHandle >= 0) on(SessionEvent.Rejected(previousSession)) else {
                        on(SessionEvent.StartFailed); error = text.getString(R.string.error_queue_full)
                        saveIntent(Wanted.NONE)
                        sampling?.cancel(false); sampling = null
                        SirinVpnService.instance?.finishSession()
                    }
                }
                publish()
            }
            callback.complete(failure(R.string.error_queue_full))
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
            val wasWaiting=retryAt>0 || session.attempting
            retryAt=0
            if (wasWaiting && !protectedTransition) stop(true)
        } else if (requested && !operation && session in setOf(Session.Unhealthy(false), Session.WaitingForNetwork, Session.Recovering)) {
            attempts=0; retryAt=SystemClock.elapsedRealtime()+1000; startSampling()
        }
    }
    @Synchronized fun finishIfIdle() {
        if (handle<0 && !operation && !requested) SirinVpnService.instance?.finishSession()
    }
    @Synchronized fun stop(user: Boolean) {
        Native.generation(epoch.incrementAndGet())
        retryAt=0; retryEnabled=false; systemStartRequested=false
        networkHandoff=false
        pendingServer=null; reconnectOverride=null; lastArguments="{}"; lastCommand="connect_saved"
        sampling?.cancel(false); sampling=null
        saveIntent(if (user) Wanted.PAUSED else Wanted.NONE, preferences.edit().remove("requested_arguments"))
        stopEngine()
        active=null; tunnelConfiguration=null; rx=null; tx=null; on(SessionEvent.Stop(user))
        VpnNotifications.clearFailure(context)
        publish()
        finishIfIdle()
        WifiAutomation.changed()
    }
    @Synchronized fun restart(systemStart:Boolean=false) {
        // isAlwaysOn() is false until the caller has established a TUN (Android
        // answers only for a running VPN). The permission-protected OS start is itself an explicit request.
        // Null sticky restarts still obey the persisted pause/connection intent.
        if(systemStart || SirinVpnService.instance?.isAlwaysOn==true) {
            systemStartRequested=true
            saveIntent(Wanted.REQUESTED)
        }
        if (paused || !requested && SirinVpnService.instance?.isAlwaysOn != true) {
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
            // Moving an active session to a new carrier is allowed even when failure retries are off.
            if((handle>=0 || operation && session.attempting) && requested && !protectedTransition) networkHandoff=true
            if (handle >= 0 && network == null) on(SessionEvent.NetworkLost)
            if (network != null && requested && (retryRequested() || networkHandoff)) {
                attempts = 0; retryAt = SystemClock.elapsedRealtime() + 1000; on(SessionEvent.Reconnect)
            }
            publish()
        }
        WifiAutomation.changed()
    }
    @Synchronized private fun refreshStatistics() {
        if (handle < 0) { on(SessionEvent.NoEngine(operation || retryAt != 0L, network != null)); return }
        try {
            val data = checkNotNull(WireGuard.statistics(handle))
            rx = data[0]; tx = data[1]; handshake = data[2].takeIf { it > 0 }
            counterSampledAt = SystemClock.elapsedRealtime()
            if (handshake == null) on(SessionEvent.NoHandshake(network != null, operation))
            if (handshake != null && network != null && session != Session.Recovering && !networkHandoff && !operation) {
                val healthy = health.record(counterSampledAt, data[0], data[2])
                // A read succeeded: lack of peer progress is degraded reachability,
                // not an unknown local tunnel or protection state.
                if (healthy) retryAt = 0
                on(SessionEvent.Health(healthy))
                if (!healthy && !operation && retryAt == 0L && retryRequested()) retryAt = counterSampledAt + 1000
            }
        } catch (_: Exception) { rx = null; tx = null; on(SessionEvent.Unreadable) }
    }
    private fun sample() {
        try {
            val retry = synchronized(this) {
                // Read and apply the same engine's counters under one lock. New
                // authenticated progress cancels a pending inactivity retry.
                refreshStatistics()
                if (!operation && preferenceTask == Task.None && (retryRequested() || networkHandoff) && requested && retryAt > 0 && network != null && SystemClock.elapsedRealtime() >= retryAt) {
                    // execute consumes the deadline only after accepting the connection.
                    Triple(lastCommand,lastArguments,epoch.get())
                } else {
                    if(session==Session.Connected && measuredGeneration!=epoch.get()) {
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
        } catch (_: Exception) { synchronized(this) { rx = null; tx = null; on(SessionEvent.Unreadable); publish() } }
    }
    val ignoreResult = object : IResult.Stub() { override fun complete(result: String) {} }
    fun success(value: Any = JSONObject.NULL) = JSONObject().put("ok", value).toString()
    fun failure(message: String) = JSONObject().put("error", message).toString()
    private fun failure(@androidx.annotation.StringRes message: Int) = failure(text.getString(message))
}
