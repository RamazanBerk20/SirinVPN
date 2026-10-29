package org.sirinvpn.client

import android.app.NotificationManager
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Real service/settings/notification paths with an emulator-only, unreachable loopback profile. */
@RunWith(AndroidJUnit4::class)
class OptionHandlingTest {
    @Test fun packageReplacementUsesOrdinaryRecovery() {
        assertTrue("Only isolated emulators",android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val target=InstrumentationRegistry.getInstrumentation().targetContext
        val prefs=target.getSharedPreferences("option-test-replacement",0)
        assertTrue(prefs.edit().putBoolean("requested",true).putBoolean("paused",false).commit())
        var action:String?=null
        val context=object:android.content.ContextWrapper(target) {
            override fun getSharedPreferences(name:String,mode:Int)=if(name=="connection-intent") prefs else super.getSharedPreferences(name,mode)
            override fun startForegroundService(service:android.content.Intent):android.content.ComponentName? {action=service.action;return null}
        }
        try {
            assertNull("Grant VPN consent first",android.net.VpnService.prepare(context))
            ReplacementReceiver().onReceive(context,android.content.Intent(android.content.Intent.ACTION_MY_PACKAGE_REPLACED))
            assertEquals("org.sirinvpn.RECOVER",action)
            prefs.edit().putBoolean("paused",true).commit();action=null
            ReplacementReceiver().onReceive(context,android.content.Intent(android.content.Intent.ACTION_MY_PACKAGE_REPLACED))
            assertNull("An update must preserve Stop",action)
        } finally {target.deleteSharedPreferences("option-test-replacement")}
    }

    @Test fun optionsControlTheRunningService() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated emulators",android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        val notices=context.getSystemService(NotificationManager::class.java)
        assertTrue("Grant notification permission first",notices.areNotificationsEnabled())
        assertNull("Grant VPN consent on this emulator first",android.net.VpnService.prepare(context))
        val link=ServiceLink(context)
        instrumentation.runOnMainSync {link.bind()}
        try {
            val control=link.ready.get(10,TimeUnit.SECONDS)
            fun state()=JSONObject(control.snapshot())
            fun begin(command:String,args:JSONObject=JSONObject(),expected:Long=-1):CompletableFuture<JSONObject> {
                val result=CompletableFuture<JSONObject>()
                control.execute(command,args.toString(),UUID.randomUUID().toString(),expected,object:IResult.Stub() {
                    override fun complete(value:String) {result.complete(JSONObject(value))}
                })
                return result
            }
            fun call(command:String,args:JSONObject=JSONObject()):Any {
                val result=begin(command,args).get(30,TimeUnit.SECONDS)
                assertFalse("$command: ${result.optString("error")}",result.has("error"))
                return result.get("ok")
            }
            fun until(message:String,condition:()->Boolean) {
                val deadline=SystemClock.elapsedRealtime()+30000
                while(SystemClock.elapsedRealtime()<deadline) {if(condition())return;SystemClock.sleep(100)}
                fail(message)
            }
            fun idle()=until("Connection operation did not stop") {!state().getBoolean("operation_in_progress")}
            assertFalse("Disable emulator Always-on first",state().getBoolean("always_on"))
            call("disconnect_server");idle()
            val profiles=call("list_servers") as org.json.JSONArray
            val id=UUID.randomUUID().toString()
            val reference="options-$id"
            fun key()=android.util.Base64.encodeToString(ByteArray(32).also {java.security.SecureRandom().nextBytes(it)},android.util.Base64.NO_WRAP)
            SecretVault(context).put(reference,JSONObject().put("wireguard_private_key",key())
                .put("management_private_key_pem","").toString().toByteArray())
            profiles.put(JSONObject().put("schema_version",1).put("id",id).put("name","Option handling fixture")
                .put("endpoint",JSONObject().put("host","10.0.2.2").put("wireguard_port",9))
                .put("client_tunnel_address","10.77.0.2").put("server_tunnel_address","10.77.0.1")
                .put("server_wireguard_public_key",key()).put("pinned_server_certificate_pem","")
                .put("client_management_certificate_pem","").put("identity_reference",reference).put("role","member"))
            val file=android.util.AtomicFile(java.io.File(context.noBackupFilesDir,"servers.json"))
            val output=file.startWrite()
            try {output.write(JSONObject().put("schema_version",1).put("servers",profiles).toString().toByteArray());file.finishWrite(output)}
            catch(error:Exception) {file.failWrite(output);throw error}
            val server=JSONObject().put("serverId",id)
            val original=call("get_connection_preferences",server) as JSONObject
            val originalApp=(call("get_app_preferences") as JSONObject).getJSONObject("preferences")
            val prefs=JSONObject(original.toString()).put("transport","direct_udp").put("network_profile","normal")
                .put("routing",JSONObject().put("mode","full_tunnel").put("included_routes",org.json.JSONArray()).put("allow_lan",false))
            prefs.remove("android_applications")
            prefs.getJSONObject("policy").put("automatic_reconnect",true)
            try {
                // Other saved options survive a reconnect-only write; invalid saves retain the last valid settings.
                for (mode in listOf("selected_routes","include","exclude")) {
                    val options=JSONObject(prefs.toString()).put("manual_mtu",1300).put("network_profile","restricted")
                    if(mode=="selected_routes") options.put("routing",JSONObject().put("mode",mode)
                        .put("included_routes",org.json.JSONArray().put("198.18.0.1/32")).put("allow_lan",true))
                    else {
                        options.getJSONObject("routing").put("mode","selected_applications")
                        options.put("android_applications",JSONObject().put("mode",mode).put("packages",org.json.JSONArray().put("org.sirinvpn.client.test")))
                    }
                    val saved=call("set_connection_preferences",JSONObject().put("serverId",id).put("preferences",options)) as JSONObject
                    call("android_set_reconnect",JSONObject().put("serverId",id).put("enabled",false))
                    saved.getJSONObject("policy").put("automatic_reconnect",false)
                    assertEquals(saved.toString(),(call("get_connection_preferences",server) as JSONObject).toString())
                    val invalid=JSONObject(options.toString()).put("manual_mtu",1)
                    assertTrue(begin("set_connection_preferences",JSONObject().put("serverId",id).put("preferences",invalid)).get(5,TimeUnit.SECONDS).has("error"))
                    assertEquals(saved.toString(),(call("get_connection_preferences",server) as JSONObject).toString())
                }
                call("set_connection_preferences",JSONObject().put("serverId",id).put("preferences",prefs))
                // A missing localhost fixture is intentional: interruption/retry tests need no live VPS.
                val attempt=begin("connect_saved",server)
                until("Native reconnect preference was not applied") {state().getJSONObject("status").getBoolean("auto_reconnect_enabled")}
                val before=state().getLong("generation")
                val started=SystemClock.elapsedRealtime()
                call("android_set_reconnect",JSONObject().put("serverId",id).put("enabled",false))
                assertTrue("Local switch waited behind the connection",SystemClock.elapsedRealtime()-started<3000)
                assertFalse((call("get_connection_preferences",server) as JSONObject).getJSONObject("policy").getBoolean("automatic_reconnect"))
                assertFalse(state().getJSONObject("status").getBoolean("auto_reconnect_enabled"))
                assertEquals("paused",state().getString("phase"))
                attempt.get(30,TimeUnit.SECONDS);idle()
                val stopped=state().getLong("generation")
                assertTrue(stopped>before)
                assertTrue(begin("connect_saved",server,before).get(5,TimeUnit.SECONDS).has("error"))
                SystemClock.sleep(2500)
                assertEquals("Late retry resurrected the session",stopped,state().getLong("generation"))

                // Full preference saves use the same live cancellation path as the switch.
                call("set_connection_preferences",JSONObject().put("serverId",id).put("preferences",prefs))
                val second=begin("connect_saved",server)
                until("Second connection did not prepare") {state().getJSONObject("status").getBoolean("auto_reconnect_enabled")}
                val disabled=JSONObject(prefs.toString())
                disabled.getJSONObject("policy").put("automatic_reconnect",false)
                call("set_connection_preferences",JSONObject().put("serverId",id).put("preferences",disabled))
                assertEquals("paused",state().getString("phase"))
                second.get(30,TimeUnit.SECONDS);idle()

                // Both app switches round-trip through the service; disabling alerts removes its old alert.
                val app=JSONObject(originalApp.toString()).put("notifications",false).put("animations",false)
                call("set_app_preferences",JSONObject().put("preferences",app))
                val stored=(call("get_app_preferences") as JSONObject).getJSONObject("preferences")
                assertFalse(stored.getBoolean("notifications"));assertFalse(stored.getBoolean("animations"))
                call("android_set_reconnect",JSONObject().put("serverId",id).put("enabled",false))
                assertTrue(begin("connect_saved",server).get(30,TimeUnit.SECONDS).has("error"));idle()
                assertTrue("Disabled connection alert was posted",notices.activeNotifications.none {it.id==73})
            } finally {
                call("disconnect_server");idle()
                call("set_connection_preferences",JSONObject().put("serverId",id).put("preferences",original))
                call("set_app_preferences",JSONObject().put("preferences",originalApp))
                call("remove_server",server)
            }
        } finally { instrumentation.runOnMainSync {link.close()} }
    }
}
