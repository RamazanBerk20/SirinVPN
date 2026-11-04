package org.sirinvpn.client

import org.junit.Assert.*
import org.junit.Test
import org.sirinvpn.client.WifiRule.Watch

class WifiRuleTest {
    private val idle = WifiRule.Input(enabled = true, network = "untrusted_wifi", entry = "1:100", attempted = null,
        session = false, busy = false, consent = true, failed = false, wifiPresent = true)
    private fun decide(change: WifiRule.Input.() -> WifiRule.Input = { this }) = WifiRule.decide(idle.change())

    @Test fun untrustedWifiConnectsOncePerNetworkEntryAndSavesTheEntryFirst() {
        val first = decide()
        assertEquals(WifiRule.Decision("connecting", Watch.NONE, connect = true, remember = true), first)
        // Cancelled, failed or disconnected by hand: the same entry never connects again.
        assertEquals(WifiRule.Decision("waiting_for_network_change", Watch.MONITOR), decide { copy(attempted = "1:100") })
        assertEquals(WifiRule.Decision("needs_attention", Watch.MONITOR), decide { copy(attempted = "1:100", failed = true) })
        // Rejoining, even the same name, is a new Android network and a new entry; so is a reboot.
        assertTrue(decide { copy(attempted = "1:100", entry = "1:101") }.connect)
        assertTrue(decide { copy(attempted = "1:100", entry = "2:100") }.connect)
    }

    @Test fun aSessionOwnsTheEntrySoALaterDisconnectIsNotUndone() {
        assertEquals(WifiRule.Decision("session_active", Watch.NONE, remember = true), decide { copy(session = true) })
        assertEquals(WifiRule.Decision("session_active", Watch.NONE), decide { copy(session = true, attempted = "1:100") })
        assertFalse(decide { copy(attempted = "1:100") }.connect)
    }

    @Test fun trustedWifiAndOtherNetworksNeverConnectOrDisconnect() {
        assertEquals(WifiRule.Decision("trusted", Watch.MONITOR), decide { copy(network = "trusted_wifi") })
        assertEquals(WifiRule.Decision("trusted", Watch.NONE), decide { copy(network = "trusted_wifi", session = true) })
        for (network in listOf("other_network", "unavailable"))
            assertEquals(WifiRule.Decision("waiting_for_wifi", Watch.WIFI_JOIN), decide { copy(network = network, entry = null, wifiPresent = false) })
        // A VPN on mobile data still arms the join callback: it costs nothing and survives the process.
        assertEquals(Watch.WIFI_JOIN, decide { copy(network = "other_network", session = true, wifiPresent = false) }.watch)
    }

    @Test fun aWifiThatLosesToMobileDataIsWatchedNotReArmed() {
        // Unvalidated or no-internet Wi-Fi beside validated mobile data: the join callback would fire at once, in a loop.
        assertEquals(WifiRule.Decision("waiting_for_wifi", Watch.MONITOR), decide { copy(network = "other_network") })
        assertEquals(Watch.NONE, decide { copy(network = "other_network", session = true) }.watch)
    }

    @Test fun missingConsentOrABusyControllerWaitsWithoutUsingTheAttempt() {
        assertEquals(WifiRule.Decision("needs_authorization", Watch.MONITOR), decide { copy(consent = false) })
        assertEquals(WifiRule.Decision("session_active", Watch.MONITOR), decide { copy(busy = true) })
    }

    @Test fun offLeavesNothingRunning() {
        for (network in listOf("untrusted_wifi", "trusted_wifi", "other_network"))
            assertEquals(WifiRule.Decision("disabled", Watch.NONE), decide { copy(enabled = false, network = network) })
    }

    @Test fun identityIsTheNameAndSecurityClassAndHiddenNamesHaveNone() {
        assertEquals("android-wifi:v2:personal:\"Home\"", WifiRule.identifier("\"Home\"", WifiRule.securityClass(android.net.wifi.WifiInfo.SECURITY_TYPE_SAE)))
        assertEquals(WifiRule.securityClass(android.net.wifi.WifiInfo.SECURITY_TYPE_PSK), WifiRule.securityClass("[WPA2-PSK-CCMP][RSN-PSK+SAE-CCMP][ESS]"))
        assertEquals("open", WifiRule.securityClass("[RSN-OWE-CCMP][ESS]"))
        assertEquals("open", WifiRule.securityClass("[ESS]"))
        assertEquals("enterprise", WifiRule.securityClass("[WPA2-EAP/SHA1-CCMP][RSN-EAP/SHA1-CCMP][ESS]"))
        assertEquals("enterprise", WifiRule.securityClass(android.net.wifi.WifiInfo.SECURITY_TYPE_PASSPOINT_R3))
        assertNull(WifiRule.securityClass(android.net.wifi.WifiInfo.SECURITY_TYPE_UNKNOWN))
        for (hidden in listOf(null, "", "<unknown ssid>")) assertNull(WifiRule.identifier(hidden, "personal"))
        assertNull(WifiRule.identifier("\"Home\"", null))
    }
}
