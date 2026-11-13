package org.sirinvpn.client

import android.net.wifi.WifiInfo

/**
 * Desktop's Wi-Fi auto-connect rule (src-tauri/src/wifi_automation.rs) without Android types:
 * one attempt per network entry, never a disconnect. WifiAutomation applies the decision.
 */
object WifiRule {
    /** What keeps auto-connect able to see the next network once this check returns. */
    enum class Watch { NONE, WIFI_JOIN, MONITOR }
    /** [wifiPresent]: any Wi-Fi is up, even one that loses to validated mobile data before it validates (or never does). */
    data class Input(val enabled: Boolean, val network: String, val entry: String?, val attempted: String?,
                     val session: Boolean, val busy: Boolean, val consent: Boolean, val failed: Boolean, val wifiPresent: Boolean)
    data class Decision(val status: String, val watch: Watch, val connect: Boolean = false, val remember: Boolean = false)

    fun decide(input: Input): Decision {
        if (!input.enabled) return Decision("disabled", Watch.NONE)
        val wifi = input.entry != null && input.network in setOf("trusted_wifi", "untrusted_wifi")
        // Off Wi-Fi a one-shot system callback wakes the app; on Wi-Fi only a running process sees the next one.
        // Armed while any Wi-Fi is up, that callback would fire again at once, forever.
        val watch = if (!wifi && !input.wifiPresent) Watch.WIFI_JOIN else if (input.session) Watch.NONE else Watch.MONITOR
        val attempted = input.entry == input.attempted
        return when {
            !wifi -> Decision("waiting_for_wifi", watch)
            input.network == "trusted_wifi" -> Decision("trusted", watch)
            // Any session owns this entry, so a later Disconnect is never undone on the same network.
            input.session -> Decision("session_active", watch, remember = !attempted)
            attempted -> Decision(if (input.failed) "needs_attention" else "waiting_for_network_change", watch)
            !input.consent -> Decision("needs_authorization", watch)
            // Another task holds the controller; the check after it ends decides, as desktop's acquire_connection.
            input.busy -> Decision("session_active", watch)
            else -> Decision("connecting", Watch.NONE, connect = true, remember = true)
        }
    }

    /** Android's own saved-network key is SSID plus security; the class keeps a WPA2 to WPA3 upgrade trusted. */
    fun securityClass(type: Int): String? = when (type) {
        WifiInfo.SECURITY_TYPE_OPEN, WifiInfo.SECURITY_TYPE_OWE -> "open"
        WifiInfo.SECURITY_TYPE_WEP, WifiInfo.SECURITY_TYPE_PSK, WifiInfo.SECURITY_TYPE_SAE,
        WifiInfo.SECURITY_TYPE_WAPI_PSK, WifiInfo.SECURITY_TYPE_DPP -> "personal"
        WifiInfo.SECURITY_TYPE_EAP, WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE, WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT,
        WifiInfo.SECURITY_TYPE_WAPI_CERT, WifiInfo.SECURITY_TYPE_OSEN,
        WifiInfo.SECURITY_TYPE_PASSPOINT_R1_R2, WifiInfo.SECURITY_TYPE_PASSPOINT_R3 -> "enterprise"
        else -> null
    }

    /** Null when Android hides the name (no precise location, Location off, or in the background without "all the time"). */
    fun identifier(ssid: String?, security: String?): String? =
        if (ssid.isNullOrBlank() || ssid == "<unknown ssid>" || security == null) null else "android-wifi:v2:$security:$ssid"
}

/**
 * What Wi-Fi auto-connect has armed to see the next network, as one value. WifiRule.Watch is what a
 * check wants; this is what runs. Null until the first check after a process start re-applies it.
 */
sealed interface WifiWatch {
    data object None : WifiWatch
    /** The one-shot Wi-Fi join callback whose PendingIntent URI carries number [n] (saved as `wifi_join`). */
    data class JoinCallback(val n: Long) : WifiWatch
    /** WifiWatchService runs; it reports its own start and stop. */
    data object Monitor : WifiWatch

    /** One transition's side effects, applied in field order: cancel, register, then start or stop the monitor. */
    data class Step(val next: WifiWatch?, val cancelJoin: Long? = null, val registerJoin: Long? = null, val monitor: Boolean? = null)

    companion object {
        /**
         * Moves [current] towards [wanted]. Android releases a join callback after one delivery, so every
         * arming uses a new number above [lastJoin]. A monitor counts as running only once it reports it.
         */
        fun arm(current: WifiWatch?, wanted: WifiRule.Watch, lastJoin: Long): Step {
            val join = wanted == WifiRule.Watch.WIFI_JOIN
            val register = if (join && current !is JoinCallback) lastJoin + 1 else null
            val cancel = if (current == null || register != null || current is JoinCallback && !join) lastJoin else null
            val monitor = when {
                wanted == WifiRule.Watch.MONITOR && current != Monitor -> true
                wanted != WifiRule.Watch.MONITOR && current == Monitor -> false
                // Unknown after a process start: nothing of ours runs, so there is nothing to stop.
                else -> null
            }
            val next = when {
                register != null -> JoinCallback(register)
                join -> current
                wanted == WifiRule.Watch.MONITOR && current == Monitor -> Monitor
                else -> None
            }
            return Step(next, cancel, register, monitor)
        }
        /** A running monitor replaces any join callback; the check it triggers re-arms what is wanted. */
        fun monitorStarted(current: WifiWatch?, lastJoin: Long) =
            Step(Monitor, cancelJoin = if (current == null) lastJoin else (current as? JoinCallback)?.n)
        fun monitorStopped(current: WifiWatch?) = if (current == Monitor) None else current
        /** Android delivered the join callback and released it. */
        fun joinDelivered(current: WifiWatch?) = if (current is JoinCallback || current == null) None else current
    }
}
