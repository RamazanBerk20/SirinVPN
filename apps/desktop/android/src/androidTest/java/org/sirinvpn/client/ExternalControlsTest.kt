package org.sirinvpn.client

import android.appwidget.AppWidgetHost
import android.appwidget.AppWidgetHostView
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProviderInfo
import android.content.ComponentName
import android.content.Intent
import android.content.pm.FeatureInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Widget, automation and TV entry points on the real service, with an unreachable loopback profile. */
@RunWith(AndroidJUnit4::class)
class ExternalControlsTest {
    @Test fun televisionLauncherNeedsNoTouchscreen() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val packages = context.packageManager
        assertEquals(MainActivity::class.java.name, packages.getLeanbackLaunchIntentForPackage(context.packageName)?.component?.className)
        assertNotEquals(0, packages.getApplicationInfo(context.packageName, 0).banner)
        val features = packages.getPackageInfo(context.packageName, PackageManager.GET_CONFIGURATIONS).reqFeatures.orEmpty()
        for (name in listOf(PackageManager.FEATURE_TOUCHSCREEN, PackageManager.FEATURE_LEANBACK, PackageManager.FEATURE_CAMERA, PackageManager.FEATURE_CAMERA_AUTOFOCUS))
            assertEquals(name, 0, features.single { it.name == name }.flags and FeatureInfo.FLAG_REQUIRED)
    }

    @Test fun widgetAndAutomationUseTheServiceControls() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated emulators", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val shell = instrumentation.uiAutomation
        val permission = "org.sirinvpn.permission.CONTROL_VPN"
        val relay = "org.sirinvpn.client.test"
        assertEquals(PermissionInfo.PROTECTION_DANGEROUS, context.packageManager.getPermissionInfo(permission, 0).protection)
        assertNull("Grant VPN consent on this emulator first", android.net.VpnService.prepare(context))
        val link = ServiceLink(context)
        instrumentation.runOnMainSync { link.bind() }
        val host = AppWidgetHost(context, 0x5157)
        val user = android.os.Process.myUid() / 100000  // `--user current` is killed on API 36 images.
        // Read to the end: the command has finished only when its output closes.
        fun shellCommand(command: String) = android.os.ParcelFileDescriptor.AutoCloseInputStream(shell.executeShellCommand(command)).use { it.readBytes() }
        var id: String? = null
        try {
            val control = link.ready.get(10, TimeUnit.SECONDS)
            fun state() = JSONObject(control.snapshot())
            fun call(command: String, args: JSONObject = JSONObject()): Any {
                val result = CompletableFuture<JSONObject>()
                control.execute(command, args.toString(), UUID.randomUUID().toString(), -1, object : IResult.Stub() {
                    override fun complete(value: String) { result.complete(JSONObject(value)) }
                })
                val value = result.get(30, TimeUnit.SECONDS)
                assertFalse("$command: ${value.optString("error")}", value.has("error"))
                return value.get("ok")
            }
            fun until(message: String, condition: () -> Boolean) {
                val deadline = SystemClock.elapsedRealtime() + 30000
                while (SystemClock.elapsedRealtime() < deadline) { if (condition()) return; SystemClock.sleep(100) }
                fail(message)
            }
            fun automate(action: String, server: String? = null) = context.sendBroadcast(Intent()
                .setClassName(relay, "org.sirinvpn.client.AutomationRelay").putExtra("action", action)
                .apply { server?.let { putExtra("server", it) } })
            assertFalse("Disable emulator Always-on first", state().getBoolean("always_on"))
            call("disconnect_server")
            until("Disconnect did not finish") { !state().getBoolean("operation_in_progress") }

            val profiles = call("list_servers") as JSONArray
            val fixture = UUID.randomUUID().toString().also { id = it }
            val reference = "widget-$fixture"
            fun key() = android.util.Base64.encodeToString(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }, android.util.Base64.NO_WRAP)
            SecretVault(context).put(reference, JSONObject().put("wireguard_private_key", key())
                .put("management_private_key_pem", "").toString().toByteArray())
            profiles.put(JSONObject().put("schema_version", 1).put("id", fixture).put("name", "Widget fixture")
                .put("endpoint", JSONObject().put("host", "10.0.2.2").put("wireguard_port", 9))
                .put("client_tunnel_address", "10.77.0.2").put("server_tunnel_address", "10.77.0.1")
                .put("server_wireguard_public_key", key()).put("pinned_server_certificate_pem", "")
                .put("client_management_certificate_pem", "").put("identity_reference", reference).put("role", "member"))
            val file = android.util.AtomicFile(java.io.File(context.noBackupFilesDir, "servers.json"))
            val output = file.startWrite()
            try { output.write(JSONObject().put("schema_version", 1).put("servers", profiles).toString().toByteArray()); file.finishWrite(output) }
            catch (error: Exception) { file.failWrite(output); throw error }

            // Neither the shell nor an app without the user's grant reaches the receiver.
            shell.revokeRuntimePermission(relay, permission)
            val before = state().getLong("generation")
            automate(AutomationReceiver.SELECT_SERVER, "Widget fixture")
            automate(AutomationReceiver.DISCONNECT)
            shellCommand("am broadcast -a ${AutomationReceiver.DISCONNECT} -p ${context.packageName}")
            SystemClock.sleep(3000)
            assertEquals(before, state().getLong("generation"))
            assertNotEquals(fixture, state().opt("quick_profile"))
            shell.grantRuntimePermission(relay, permission)
            automate(AutomationReceiver.SELECT_SERVER, "Widget fixture")
            until("Automation did not select the server") { state().opt("quick_profile") == fixture }
            automate(AutomationReceiver.DISCONNECT)
            until("Automation did not disconnect") { state().getLong("generation") > before }

            val manager = AppWidgetManager.getInstance(context)
            lateinit var view: AppWidgetHostView
            instrumentation.runOnMainSync { host.startListening() }
            val widget = host.allocateAppWidgetId()
            shellCommand("appwidget grantbind --package ${context.packageName} --user $user")
            assertTrue(manager.bindAppWidgetIdIfAllowed(widget, ComponentName(context, SirinWidget::class.java)))
            val info = manager.getAppWidgetInfo(widget)
            assertEquals("Never offered on the lock screen", AppWidgetProviderInfo.WIDGET_CATEGORY_HOME_SCREEN, info.widgetCategory)
            instrumentation.runOnMainSync { view = host.createView(context, widget, info) }
            fun text(viewId: Int): String { var value = ""; instrumentation.runOnMainSync { value = view.findViewById<TextView>(viewId)?.text?.toString() ?: "" }; return value }
            fun shown(): List<String> {
                val texts = mutableListOf<String>()
                fun walk(node: View) { if (node is TextView) texts += node.text.toString(); if (node is ViewGroup) for (i in 0 until node.childCount) walk(node.getChildAt(i)) }
                instrumentation.runOnMainSync { walk(view) }
                return texts
            }
            fun showing(status: Int, toggle: Int, server: String) = text(R.id.widget_status) == context.getString(status) &&
                text(R.id.widget_toggle) == context.getString(toggle) && text(R.id.widget_server) == server
            until("Widget did not render the paused state") { showing(R.string.status_disconnected, R.string.widget_action_connect, "Widget fixture") }

            // The toggle uses the notification receiver: Connect, then Stop connecting.
            val paused = state().getLong("generation")
            instrumentation.runOnMainSync { view.findViewById<View>(R.id.widget_toggle).performClick() }
            until("Widget toggle did not connect") { state().getLong("generation") > paused && state().getString("phase") != "paused" }
            until("Widget did not render the attempt") { text(R.id.widget_toggle) in setOf(context.getString(R.string.notification_action_stop_connecting), context.getString(R.string.notification_action_disconnect)) }
            assertTrue("Widget showed the server address", shown().none { "10.0.2.2" in it })
            val attempt = state().getLong("generation")
            instrumentation.runOnMainSync { view.findViewById<View>(R.id.widget_toggle).performClick() }
            until("Widget toggle did not stop") { state().getLong("generation") > attempt && state().getString("phase") == "paused" }
            until("Widget did not render the stop") { showing(R.string.status_disconnected, R.string.widget_action_connect, "Widget fixture") }

            until("The stopped attempt did not finish") { !state().getBoolean("operation_in_progress") }
            // Automation connects to the selected server through the same controller command.
            val stopped = state().getLong("generation")
            automate(AutomationReceiver.CONNECT)
            until("Automation did not connect") { state().getLong("generation") > stopped && state().getString("phase") != "paused" }
            automate(AutomationReceiver.DISCONNECT)
            until("Automation did not stop the attempt") { state().getString("phase") == "paused" }
            until("Widget did not render the second stop") { showing(R.string.status_disconnected, R.string.widget_action_connect, "Widget fixture") }
            until("The automated attempt did not finish") { !state().getBoolean("operation_in_progress") }
            call("update_server_presentation", JSONObject().put("serverId", fixture).put("name", "Renamed fixture"))
            until("Widget kept the old name") { text(R.id.widget_server) == "Renamed fixture" }
            call("remove_server", JSONObject().put("serverId", fixture)); id = null
            until("Widget kept a removed server") { showing(R.string.status_disconnected, R.string.widget_action_open, context.getString(R.string.widget_no_server)) }
            assertTrue(shown().none { "10.0.2.2" in it })
            host.deleteAppWidgetId(widget)
        } finally {
            shell.revokeRuntimePermission(relay, permission)
            shellCommand("appwidget revokebind --package ${context.packageName} --user $user")
            instrumentation.runOnMainSync { host.stopListening(); host.deleteHost() }
            link.ready.getNow(null)?.let { control ->
                for ((command, args) in listOfNotNull("disconnect_server" to JSONObject(), id?.let { "remove_server" to JSONObject().put("serverId", it) })) {
                    val done = CompletableFuture<String>()
                    control.execute(command, args.toString(), UUID.randomUUID().toString(), -1,
                        object : IResult.Stub() { override fun complete(value: String) { done.complete(value) } })
                    done.get(30, TimeUnit.SECONDS)
                }
            }
            instrumentation.runOnMainSync { link.close() }
        }
    }
}
