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

    /** Android 10 and 11 report security only in the access point's scan result, for example "[RSN-PSK+SAE-CCMP]". */
    fun securityClass(capabilities: String): String = when {
        Regex("EAP|802\\.1X|SUITE_B|WAPI-CERT|OSEN").containsMatchIn(capabilities) -> "enterprise"
        Regex("PSK|SAE|WEP|DPP").containsMatchIn(capabilities) -> "personal"
        else -> "open"
    }

    /** Null when Android hides the name (no precise location, Location off, or in the background without "all the time"). */
    fun identifier(ssid: String?, security: String?): String? =
        if (ssid.isNullOrBlank() || ssid == "<unknown ssid>" || security == null) null else "android-wifi:v2:$security:$ssid"
}
