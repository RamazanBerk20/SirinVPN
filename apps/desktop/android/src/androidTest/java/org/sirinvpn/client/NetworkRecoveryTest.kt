package org.sirinvpn.client

import android.content.Context
import android.content.ContextWrapper
import android.net.Network
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exercise the controller in the test process, without a VPN, real sockets or saved profiles. */
@RunWith(AndroidJUnit4::class)
class NetworkRecoveryTest {
    private fun fixture(test: () -> Unit) {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated emulators", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        assertNull(SirinVpnService.instance)
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = target.getSharedPreferences("network-recovery-test", 0)
        val fields = listOf("context", "phase", "handle", "network", "active", "paused", "retryEnabled",
            "retryAt", "networkHandoff", "operation", "protectedTransition", "sequence", "tileState")
            .associateWith { Controller::class.java.getDeclaredField(it).apply { isAccessible = true } }
        val saved = fields.mapValues { it.value.get(Controller) }
        assertFalse("Use a fresh test process", Controller::class.java.getDeclaredField("initialized").apply { isAccessible = true }.getBoolean(Controller))
        try {
            fields.getValue("context").set(Controller, object : ContextWrapper(target) {
                override fun getSharedPreferences(name: String, mode: Int) = prefs
            })
            assertTrue(prefs.edit().clear().putBoolean("requested", true).commit())
            set("paused", false); set("retryEnabled", false); set("retryAt", 0L)
            set("operation", false); set("protectedTransition", false); set("networkHandoff", false)
            test()
        } finally {
            saved.forEach { (name, value) -> fields.getValue(name).set(Controller, value) }
            target.deleteSharedPreferences("network-recovery-test")
        }
    }
    private fun set(name: String, value: Any?) = Controller::class.java.getDeclaredField(name)
        .apply { isAccessible = true }.set(Controller, value)
    private fun changed() = Controller::class.java.getDeclaredMethod("networkChanged")
        .apply { isAccessible = true }.invoke(Controller)
    private fun retryAt() = Controller::class.java.getDeclaredField("retryAt")
        .apply { isAccessible = true }.getLong(Controller)
    private fun network(index: Int): Network {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val live = checkNotNull(context.getSystemService(android.net.ConnectivityManager::class.java).activeNetwork)
        // Preserve Android's handle encoding while using distinct, unused network IDs.
        return Network.fromNetworkHandle(live.networkHandle + (index.toLong() shl 32))
    }

    @Test fun activeSessionFollowsNetworksWithFailureRetriesDisabled() = fixture {
        set("handle", 42); set("phase", "connected"); set("network", network(1))
        changed()
        assertEquals("reconnecting", Controller.snapshot().getString("phase"))
        assertEquals("connecting", Controller.snapshot().getJSONObject("status").getString("state"))
        assertTrue(Controller.snapshot().getJSONObject("status").getBoolean("recovery_in_progress"))
        assertFalse(Controller.snapshot().getJSONObject("status").getBoolean("auto_reconnect_enabled"))
        assertTrue(retryAt() > SystemClock.elapsedRealtime())
        assertEquals("Do not destroy the old tunnel during handover", 42, Controller.handle)
        // A campus Wi-Fi gap must retain the handover intent until a carrier returns.
        set("network", null); changed()
        assertEquals("waiting_for_network", Controller.snapshot().getString("phase"))
        set("network", network(2)); changed()
        assertEquals("reconnecting", Controller.snapshot().getString("phase"))
        // Another roam while the previous carrier is being replaced must not get lost.
        set("handle", -1); set("operation", true); set("phase", "connecting")
        set("networkHandoff", false); set("retryAt", 0L); changed()
        assertTrue(Controller.snapshot().getJSONObject("status").getBoolean("recovery_in_progress"))
        assertTrue(retryAt() > SystemClock.elapsedRealtime())
        set("operation", false)
        // No inactive or explicitly stopped session may be revived by a callback.
        for (paused in listOf(false, true)) {
            set("handle", -1); set("networkHandoff", false); set("retryAt", 0L)
            set("phase", "disconnected"); set("paused", paused); changed()
            assertEquals(0L, retryAt())
            assertEquals("disconnected", Controller.snapshot().getString("phase"))
        }
        set("networkHandoff", true)
        var completed = false
        Controller.execute("connect_saved", "{}", "late-handoff", -1, object : IResult.Stub() {
            override fun complete(value: String) { completed = true; assertTrue(JSONObject(value).has("ok")) }
        }, retry = true)
        assertTrue("A late handover must obey Stop before starting work", completed)
        assertEquals("disconnected", Controller.snapshot().getString("phase"))
    }

    @Test fun refreshReconcilesMissingEngineAndPublishesFreshStatus() = fixture {
        set("handle", -1); set("phase", "unknown"); set("network", network(1)); set("active", "previous-server")
        val before = Controller.snapshot().getLong("sequence")
        var result: JSONObject? = null
        Controller.execute("local_status", "{}", "refresh-test", -1, object : IResult.Stub() {
            override fun complete(value: String) { result = JSONObject(value) }
        })
        assertEquals("disconnected", result!!.getJSONObject("ok").getString("state"))
        assertTrue("The previous server must not block Connect", result!!.getJSONObject("ok").isNull("server_id"))
        assertEquals("disconnected", Controller.snapshot().getString("phase"))
        assertTrue("Refresh must notify subscribers too", Controller.snapshot().getLong("sequence") > before)
        set("phase", "failed")
        assertEquals("disconnected", Controller.snapshot().getJSONObject("status").getString("state"))
    }
}
