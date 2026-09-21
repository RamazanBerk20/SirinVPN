package org.sirinvpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationBadgeTest {
    @Test fun existingNotificationsMoveToChannelsWithoutBadges() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated emulators", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = context.getSystemService(NotificationManager::class.java)
        assertTrue(manager.areNotificationsEnabled())
        // Recreate the pre-update channel to exercise migration of an already posted notification.
        manager.createNotificationChannel(NotificationChannel("vpn", "VPN connection", NotificationManager.IMPORTANCE_LOW))
        val old = manager.getNotificationChannel("vpn")
        assertTrue("The old channel must reproduce the badge", old.canShowBadge())
        val open = VpnNotifications.openApp(context)
        fun awaitNotification(channel: String): Notification {
            repeat(100) {
                manager.activeNotifications.firstOrNull { it.id == 76 && it.notification.channelId == channel }?.let { return it.notification }
                SystemClock.sleep(100)
            }
            throw AssertionError("Notification did not appear on $channel")
        }
        try {
            manager.notify(76, Notification.Builder(context, "vpn").setSmallIcon(R.drawable.ic_sirin_vpn)
                .setContentTitle("Badge migration test").setContentIntent(open).setAutoCancel(true).build())
            awaitNotification("vpn")
            VpnNotifications.channels(context)
            val migrated = awaitNotification(VpnNotifications.CHANNEL)
            assertEquals(open, migrated.contentIntent)
            assertEquals(Notification.BADGE_ICON_NONE, migrated.badgeIconType)
            val vpn = manager.getNotificationChannel(VpnNotifications.CHANNEL)
            assertEquals(old.importance, vpn.importance)
            assertEquals(old.sound, vpn.sound)
            VpnNotifications.channels(context)
            assertNull(manager.getNotificationChannel("vpn"))
            for (id in listOf(VpnNotifications.CHANNEL, VpnNotifications.MAINTENANCE_CHANNEL, VpnNotifications.UPDATE_CHANNEL)) {
                assertFalse(manager.getNotificationChannel(id).canShowBadge())
            }
        } finally { manager.cancel(76) }
    }
}
