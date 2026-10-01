package org.sirinvpn.client

import android.app.Notification
import android.app.NotificationManager
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationTrafficTest {
    @Test fun ratesScaleAndUpdateWithEachCounterSample() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated emulators", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = context.getSystemService(NotificationManager::class.java)
        assertTrue(manager.areNotificationsEnabled())
        assertFalse("Disconnect the emulator first", manager.activeNotifications.any { it.id == VpnNotifications.VPN_ID })
        VpnNotifications.channels(context)
        var sampledAt = 10000L
        var rx = 0L
        var tx = 0L
        val status = JSONObject().put("counter_epoch", "traffic-test").put("byte_counters_available", true)
        val state = JSONObject().put("phase", "connected").put("generation", 1).put("status", status)
        fun publish() {
            status.put("rx_bytes", rx).put("tx_bytes", tx).put("counter_sampled_at_ms", sampledAt)
            VpnNotifications.update(context, state)
        }
        fun expectText(expected: String): android.service.notification.StatusBarNotification {
            val deadline = SystemClock.uptimeMillis() + 750
            while (SystemClock.uptimeMillis() < deadline) {
                manager.activeNotifications.firstOrNull { it.id == VpnNotifications.VPN_ID }?.let {
                    if (it.notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() == expected) return it
                }
                SystemClock.sleep(20)
            }
            throw AssertionError("Notification did not update promptly to: $expected")
        }
        try {
            publish()
            expectText("Connected")
            val readings = listOf(
                Triple(512L, 128L, "512 B/s · ↑ 128 B/s"),
                Triple(1536L, 3L * 1024 * 1024, "1.5 KB/s · ↑ 3.0 MB/s"),
                Triple(12L * 1024 * 1024, 1536L * 1024 * 1024, "12 MB/s · ↑ 1.5 GB/s"),
                Triple(1L shl 40, 0L, "1.0 TB/s · ↑ 0 B/s"),
            )
            for ((download, upload, expected) in readings) {
                SystemClock.sleep(1000)
                sampledAt += 1000; rx += download; tx += upload
                publish()
                val notice = expectText("Connected · ↓ $expected")
                assertEquals("Disconnect", notice.notification.actions.single().title)
                // Lookup proves this is the existing broadcast token on API 29 too;
                // PendingIntent.isBroadcast() was only added in API 31.
                val broadcast = android.app.PendingIntent.getBroadcast(context, 3,
                    android.content.Intent(context, VpnActionReceiver::class.java)
                        .setAction("org.sirinvpn.STOP")
                        .setData(android.net.Uri.parse("sirin-control://stop/1")),
                    android.app.PendingIntent.FLAG_NO_CREATE or android.app.PendingIntent.FLAG_IMMUTABLE)
                assertNotNull(broadcast)
                assertEquals(broadcast, notice.notification.actions.single().actionIntent)
                assertFalse(manager.getNotificationChannel(notice.notification.channelId).canShowBadge())
                repeat(3) { SystemClock.sleep(40); publish() }
                assertEquals("Repeated status must not replace the notification", notice.postTime,
                    expectText("Connected · ↓ $expected").postTime)
            }
            // A new counter epoch must not reuse the previous connection's totals.
            status.put("counter_epoch", "reconnected")
            sampledAt += 1000; rx = 0; tx = 0
            publish()
            expectText("Connected")
            SystemClock.sleep(1000)
            sampledAt += 1000
            publish()
            expectText("Connected · ↓ 0 B/s · ↑ 0 B/s")
            state.put("phase", "degraded")
            publish()
            assertEquals("Disconnect", expectText("Connection interrupted").notification.actions.single().title)
        } finally { manager.cancel(VpnNotifications.VPN_ID) }
    }
}
