package org.sirinvpn.client

import org.junit.Assert.*
import org.junit.Test

class ProtectedInputTest {
    @Test fun aHandleIsRedeemableOnlyAsTheFieldItWasEnteredFor() {
        assertTrue(SecretInputs.redeemable("password", "password"))
        for (other in listOf("sudo_password", "apiToken", "key", "code", "backup_password", "private_key_passphrase"))
            assertFalse(other, SecretInputs.redeemable("password", other))
        assertFalse(SecretInputs.redeemable("password", null))
        assertFalse("Not a protected argument", SecretInputs.redeemable("host", "host"))
    }

    @Test fun everyNotificationHasItsOwnId() {
        val ids = listOf(VpnNotifications.VPN_ID, VpnNotifications.TEST_ID, VpnNotifications.MAINTENANCE_ID,
            VpnNotifications.FAILURE_ID, VpnNotifications.WIFI_WATCH_ID, VpnNotifications.UPDATE_ID)
        assertEquals(ids.size, ids.toSet().size)
    }
}
