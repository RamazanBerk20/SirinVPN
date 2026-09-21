package org.sirinvpn.client

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Intent
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.TimeUnit

/** Run with tests/android/notification-shade.mjs, which taps SystemUI through shell UI Automator. */
@RunWith(AndroidJUnit4::class)
class NotificationActionTest {
    @Test fun disconnectKeepsShadeOpen() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated emulators", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val manager = context.getSystemService(NotificationManager::class.java)
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        assertFalse("Do not replace an existing credential", keyguard.isDeviceSecure)
        assertTrue("Allow emulator notifications first", manager.areNotificationsEnabled())
        val stage = File(context.noBackupFilesDir, "notification-test-stage")
        fun until(message: String, condition: () -> Boolean) {
            val deadline = SystemClock.uptimeMillis() + 60000
            while (SystemClock.uptimeMillis() < deadline) { if (condition()) return; SystemClock.sleep(100) }
            fail(message)
        }
        val link = ServiceLink(context)
        instrumentation.runOnMainSync { link.bind() }
        try {
            val control = link.ready.get(10, TimeUnit.SECONDS)
            fun snapshot() = JSONObject(control.snapshot())
            // Let initial network callbacks finish before starting an idle service.
            until("Initial network state was not published") { snapshot().getLong("sequence") > 0 }
            SystemClock.sleep(1000)
            val before = snapshot()
            assertTrue(before.getString("phase") in setOf("disconnected", "paused", "failed"))
            assertFalse(before.optBoolean("always_on") || before.optBoolean("wifi_automation_enabled") || before.optBoolean("operation_in_progress"))
            assertNull("Grant VPN consent on this isolated emulator first", android.net.VpnService.prepare(context))
            VpnNotifications.channels(context)
            for (phase in listOf("connected", "reconnecting")) {
                val state = snapshot()
                // The real foreground service runs without an engine or endpoint.
                context.startForegroundService(Intent(context, SirinVpnService::class.java)
                    .putExtra("generation", state.getLong("generation")))
                until("Foreground notification did not appear") { manager.activeNotifications.any { it.id == VpnNotifications.VPN_ID } }
                VpnNotifications.update(context, state.put("phase", phase))
                val label = if (phase == "connected") "Disconnect" else "Stop attempts"
                until("Notification controls were not published") {
                    manager.activeNotifications.any { it.id == VpnNotifications.VPN_ID && it.notification.actions?.singleOrNull()?.title == label }
                }
                val action = manager.activeNotifications.single { it.id == VpnNotifications.VPN_ID }.notification.actions.single()
                assertTrue(action.actionIntent.isBroadcast)
                if (android.os.Build.VERSION.SDK_INT >= 31) assertFalse(action.isAuthenticationRequired)
                stage.writeText(phase)
                until("Disconnect was not delivered") { snapshot().getLong("generation") > state.getLong("generation") }
                until("VPN notification was not removed") { manager.activeNotifications.none { it.id == VpnNotifications.VPN_ID } }
                stage.writeText("$phase-done")
                until("SystemUI assertion was not acknowledged") { stage.readText().trim() == "continue" }
            }
            val state = snapshot().put("phase", "connected")
            VpnNotifications.update(context, state)
            until("Stop notification was not published") { manager.activeNotifications.any { it.id == VpnNotifications.VPN_ID } }
            val unlockedAction = manager.activeNotifications.single { it.id == VpnNotifications.VPN_ID }.notification.actions.single()
            VpnNotifications.failed(context, state)
            until("Retry notification was not published") { manager.activeNotifications.any { it.id == 73 } }
            if (android.os.Build.VERSION.SDK_INT >= 31) assertFalse(manager.activeNotifications.single { it.id == 73 }.notification.actions.single().isAuthenticationRequired)
            stage.writeText("lock")
            until("Emulator did not lock") { keyguard.isDeviceLocked }
            // An action created before locking must still refuse an unauthenticated stop.
            unlockedAction.actionIntent.send()
            SystemClock.sleep(1000)
            assertEquals(state.getLong("generation"), snapshot().getLong("generation"))
            VpnNotifications.update(context, state)
            VpnNotifications.failed(context, state)
            if (android.os.Build.VERSION.SDK_INT >= 31) {
                for (id in listOf(VpnNotifications.VPN_ID, 73)) {
                    until("Locked notification must require authentication") {
                        manager.activeNotifications.single { it.id == id }.notification.actions.single().isAuthenticationRequired
                    }
                }
            }
        } finally {
            stage.delete()
            manager.cancel(VpnNotifications.VPN_ID)
            VpnNotifications.clearFailure(context)
            instrumentation.runOnMainSync { link.close() }
        }
    }
}
