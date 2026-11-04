package org.sirinvpn.client

import android.app.NotificationManager
import android.os.SystemClock
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

/**
 * Wi-Fi auto-connect against the emulator's open "AndroidWifi" and an unreachable loopback server. The harness
 * grants precise and background location, turns Location on, and drives the reboot, update and kill steps.
 */
@RunWith(AndroidJUnit4::class)
class WifiAutoConnectTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun shell(command: String) = android.os.ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes().decodeToString() }
    private fun until(message: String, seconds: Int = 30, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + seconds * 1000L
        while (SystemClock.elapsedRealtime() < deadline) { if (condition()) return; SystemClock.sleep(200) }
        fail(message)
    }
    private fun notice(id: Int) = context.getSystemService(NotificationManager::class.java).activeNotifications.any { it.id == id }
    private fun watching() = notice(74)
    private fun withControl(block: (IControl) -> Unit) {
        assertTrue("Only isolated emulators", android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val link = ServiceLink(context)
        instrumentation.runOnMainSync { link.bind() }
        try { block(link.ready.get(10, TimeUnit.SECONDS)) } finally { instrumentation.runOnMainSync { link.close() } }
    }
    private fun IControl.call(command: String, args: JSONObject = JSONObject()): Any {
        val result = CompletableFuture<JSONObject>()
        execute(command, args.toString(), UUID.randomUUID().toString(), -1, object : IResult.Stub() {
            override fun complete(value: String) { result.complete(JSONObject(value)) }
        })
        return result.get(30, TimeUnit.SECONDS).also { assertFalse("$command: ${it.optString("error")}", it.has("error")) }.get("ok")
    }
    private fun IControl.policy() = call("get_wifi_policy") as JSONObject
    private fun IControl.phase() = JSONObject(snapshot()).getString("phase")
    private fun IControl.running() = phase() in setOf("connecting", "reconnecting", "waiting_for_network", "connected", "degraded")
    private fun wifi(on: Boolean) {
        shell("svc wifi ${if (on) "enable" else "disable"}")
        if (on) shell("cmd wifi connect-network AndroidWifi open")
    }
    private fun IControl.joined() = until("AndroidWifi did not come back", 90) { policy().getString("current_network").endsWith("_wifi") }

    /** An unreachable server: the rule's connection starts, and a test sees it without any VPS. */
    private fun IControl.fixture(): String {
        val id = UUID.randomUUID().toString()
        val reference = "wifi-$id"
        fun key() = android.util.Base64.encodeToString(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }, android.util.Base64.NO_WRAP)
        SecretVault(context).put(reference, JSONObject().put("wireguard_private_key", key()).put("management_private_key_pem", "").toString().toByteArray())
        val profiles = (call("list_servers") as JSONArray).put(JSONObject().put("schema_version", 1).put("id", id).put("name", "Wi-Fi fixture")
            .put("endpoint", JSONObject().put("host", "10.0.2.2").put("wireguard_port", 9))
            .put("client_tunnel_address", "10.77.0.2").put("server_tunnel_address", "10.77.0.1")
            .put("server_wireguard_public_key", key()).put("pinned_server_certificate_pem", "")
            .put("client_management_certificate_pem", "").put("identity_reference", reference).put("role", "member"))
        val file = android.util.AtomicFile(java.io.File(context.noBackupFilesDir, "servers.json"))
        val output = file.startWrite()
        try { output.write(JSONObject().put("schema_version", 1).put("servers", profiles).toString().toByteArray()); file.finishWrite(output) }
        catch (error: Exception) { file.failWrite(output); throw error }
        return id
    }
    private fun IControl.enable(id: String) =
        call("set_wifi_policy", JSONObject().put("policy", JSONObject().put("enabled", true).put("server_id", id)))
    private fun IControl.trustCurrent() =
        call("trust_current_wifi", JSONObject().put("expectedNetworkToken", policy().getString("current_network_token")).put("label", "Emulator"))
    // The cancelled attempt to the unreachable fixture returns later; only then is the controller idle.
    private fun IControl.stopped() {
        call("disconnect_server")
        until("Disconnect did not finish", 60) { !running() && !JSONObject(snapshot()).getBoolean("operation_in_progress") }
    }
    private fun IControl.cleanup() {
        val state = policy()
        call("set_wifi_policy", JSONObject().put("policy", JSONObject().put("enabled", false).put("server_id", JSONObject.NULL)))
        for (i in 0 until state.getJSONArray("trusted_networks").length())
            call("forget_trusted_wifi", JSONObject().put("id", state.getJSONArray("trusted_networks").getJSONObject(i).getString("id")))
        stopped()
        state.getJSONObject("policy").optString("server_id").takeIf { it.isNotEmpty() && it != "null" }?.let { call("remove_server", JSONObject().put("serverId", it)) }
        until("The monitor outlived auto-connect") { !watching() }
    }

    @Test fun ruleFollowsTheNetworkLikeDesktop() = withControl { control ->
        assertNull("Grant VPN consent first", android.net.VpnService.prepare(context))
        assertFalse("Disable emulator Always-on first", JSONObject(control.snapshot()).getBoolean("always_on"))
        control.stopped()
        control.joined()
        var state = control.policy()
        assertEquals("untrusted_wifi", state.getString("current_network"))
        assertTrue("Grant precise location and turn Location on", state.getBoolean("can_trust_current"))
        assertEquals("AndroidWifi", state.getJSONObject("network_names").getString(state.getString("current_network_token")))
        assertEquals("always", state.getJSONObject("android_access").getString("location"))
        // Location off hides the name: the same Wi-Fi is then unidentified and untrusted, never trusted.
        shell("cmd location set-location-enabled false")
        try {
            until("Location off still identified the Wi-Fi") { !control.policy().getBoolean("can_trust_current") }
            assertEquals("untrusted_wifi", control.policy().getString("current_network"))
        } finally { shell("cmd location set-location-enabled true") }
        until("Location on did not identify the Wi-Fi again") { control.policy().getBoolean("can_trust_current") }
        val id = control.fixture()
        try {
            control.enable(id)
            until("Untrusted Wi-Fi did not auto-connect") { control.running() && JSONObject(control.snapshot()).getJSONObject("status").optString("server_id") == id }
            // "Connecting" until the attempt returns, as desktop's status during connect_native.
            until("Status did not follow the session") { control.policy().getString("automation_status") in setOf("connecting", "session_active") }
            // Disconnect wins for the rest of this network entry.
            control.stopped()
            until("Disconnect did not pause the rule") { control.policy().getString("automation_status") == "waiting_for_network_change" }
            SystemClock.sleep(5000)
            assertFalse("Auto-connect undid Disconnect on the same network", control.running())
            until("Paused on Wi-Fi without the monitor") { watching() }
            // Mobile data or nothing: the rule waits and needs no monitor.
            wifi(false)
            until("Off Wi-Fi the rule did not wait") { control.policy().getString("automation_status") == "waiting_for_wifi" }
            until("The monitor stayed off Wi-Fi") { !watching() }
            assertFalse(control.running())
            // Rejoining is a new entry: connect again.
            wifi(true)
            until("Rejoined Wi-Fi did not auto-connect", 90) { control.running() }
            control.stopped()
            // Trusted Wi-Fi never connects, and changing trust is a new entry.
            control.trustCurrent()
            until("Trusted Wi-Fi status") { control.policy().getString("automation_status") == "trusted" }
            wifi(false); until("Off Wi-Fi") { control.policy().getString("automation_status") == "waiting_for_wifi" }
            wifi(true); control.joined()
            until("Trusted Wi-Fi needs the monitor") { watching() }
            SystemClock.sleep(5000)
            assertFalse("Auto-connect connected on trusted Wi-Fi", control.running())
            // Android keeps this notice visible until the user turns its channel off; its one action does that.
            val notice = context.getSystemService(NotificationManager::class.java).activeNotifications.first { it.id == 74 }.notification
            assertEquals(context.getString(R.string.notification_action_hide), notice.actions.single().title.toString())
            state = control.policy()
            assertEquals("trusted_wifi", state.getString("current_network"))
            control.call("forget_trusted_wifi", JSONObject().put("id", state.getJSONArray("trusted_networks").getJSONObject(0).getString("id")))
            until("Removing trust did not connect", 60) { control.running() }
        } finally { control.cleanup() }
    }

    // Host-driven steps, like UpgradeAcceptanceTest: the emulator script kills, reboots, updates and
    // force-stops between them and checks which service runs without opening the app.
    @Test fun seedPausedOnUntrustedWifi() = withControl { control ->
        control.stopped(); control.joined()
        control.enable(control.fixture())
        until("Untrusted Wi-Fi did not auto-connect") { control.running() }
        control.stopped()
        until("Paused on Wi-Fi without the monitor") { watching() }
    }

    @Test fun verifyAutoConnectedThenTrust() = withControl { control ->
        until("Auto-connect did not start the VPN") { control.running() }
        assertEquals(control.policy().getJSONObject("policy").getString("server_id"), JSONObject(control.snapshot()).getJSONObject("status").getString("server_id"))
        control.stopped()
        control.trustCurrent()
        until("Trusted Wi-Fi needs the monitor") { watching() }
    }

    @Test fun cleanupWifiAutoConnect() = withControl { control -> control.cleanup() }
}
