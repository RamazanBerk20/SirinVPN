package org.sirinvpn.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Installed only in the separate, debug-signed test APK. No test entry point ships in the app. */
@RunWith(AndroidJUnit4::class)
class ServiceAcceptanceTest {
    @Test fun nativeService() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue("Only isolated Android emulators",android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val link = ServiceLink(context)
        instrumentation.runOnMainSync { link.bind() }
        try {
            val control = link.ready.get(10,TimeUnit.SECONDS)
            fun call(command: String, args: JSONObject = JSONObject(), expectFailure:Boolean=false): Any {
                val done = CountDownLatch(1)
                var result = JSONObject()
                control.execute(command,args.toString(),UUID.randomUUID().toString(),-1,object : IResult.Stub() {
                    override fun complete(value: String) { result = JSONObject(value); done.countDown() }
                })
                assertTrue("Timed out: $command",done.await(if(command in setOf("provision_server","repair_server","restore_vps_backup","export_vps_backup")) 900 else 150,TimeUnit.SECONDS))
                if(expectFailure) {assertTrue("Expected rejection: $command",result.has("error"));return JSONObject.NULL}
                assertFalse("Failed: $command: ${result.optString("error")}", result.has("error"))
                return result.get("ok")
            }
            fun status(id:String):JSONObject {
                for(attempt in 0..2) {
                    try {return call("server_status",JSONObject().put("serverId",id)) as JSONObject}
                    catch(error:AssertionError) {
                        if(attempt==2) {
                            val state=JSONObject(control.snapshot())
                            println("Management failure evidence: phase=${state.optString("phase")}, handleAvailable=${state.getJSONObject("status").optBoolean("byte_counters_available")}, operation=${state.optBoolean("operation_in_progress")}")
                            throw error
                        }
                        Thread.sleep(1000)
                    }
                }
                error("Unreachable")
            }
            when (InstrumentationRegistry.getArguments().getString("action","snapshot")) {
                "maintenance" -> {
                    val inputFile=java.io.File(context.noBackupFilesDir,"acceptance-vps-input")
                    val input=try {JSONObject(inputFile.readText())} finally {inputFile.delete()}
                    val enrolled=JSONObject(java.io.File(context.noBackupFilesDir,"acceptance-vps-result.json").readText())
                    assertEquals(enrolled.getString("fixture"),input.getString("fixture"))
                    assertEquals("10.0.2.2",input.getString("host"))
                    val id=enrolled.getString("server_id")
                    val profiles=call("list_servers") as org.json.JSONArray
                    val profile=(0 until profiles.length()).map {profiles.getJSONObject(it)}.single {it.getString("id")==id}
                    assertEquals("10.0.2.2",profile.getJSONObject("endpoint").getString("host"))
                    assertEquals("Android isolated VPS",profile.getString("name"))
                    val rows=org.json.JSONArray()
                    fun passed(name:String) {
                        rows.put(JSONObject().put("name",name).put("passed",true))
                        java.io.File(context.noBackupFilesDir,"acceptance-maintenance.json").writeText(rows.toString())
                    }
                    fun args(vararg pairs:Pair<String,Any>)=JSONObject().put("input",JSONObject().put("server_id",id).apply {pairs.forEach {put(it.first,it.second)}})
                    fun connected() {
                        call("connect_saved",JSONObject().put("serverId",id))
                        assertEquals("owner",status(id).getString("caller_role"))
                    }
                    val uris=mutableListOf<android.net.Uri>()
                    fun document(extension:String):String {
                        val values=android.content.ContentValues().apply {
                            put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME,"sirin-acceptance-${UUID.randomUUID()}.$extension")
                            put(android.provider.MediaStore.MediaColumns.MIME_TYPE,"application/octet-stream")
                        }
                        return context.contentResolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,values)!!.also {uris.add(it)}.toString()
                    }
                    val rescue=SecretVault(context)
                    rescue.get("acceptance-owner-rescue")?.let {bytes ->
                        val saved=try {JSONObject(String(bytes))} finally {bytes.fill(0)}
                        assertEquals(input.getString("fixture"),saved.getString("fixture"))
                        if(profile.getString("role")!="owner") {
                            call("disconnect_server")
                            val key=call("remember_secret",JSONObject().put("value",saved.getString("key"))) as String
                            call("recover_owner_access",args("key" to key,"device_name" to "Resumed fixture owner","confirmed" to true,"replace_existing" to true))
                        }
                        rescue.delete("acceptance-owner-rescue")
                    }
                    try {
                        connected()
                        val password=call("remember_secret",JSONObject().put("value",UUID.randomUUID().toString())) as String
                        val wrong=call("remember_secret",JSONObject().put("value",UUID.randomUUID().toString())) as String
                        val priorRecovery=(call("recovery_settings",JSONObject().put("serverId",id)) as JSONObject).optJSONObject("key")
                        val recovery=call("create_recovery_key",args("confirmed" to true,"replace_recovery_id" to (priorRecovery?.getString("recovery_id") ?: JSONObject.NULL))) as JSONObject
                        val protectedKey=call("reveal_secret",JSONObject().put("reference",recovery.getString("key"))) as JSONObject
                        val checkpoint=JSONObject().put("fixture",input.getString("fixture")).put("key",protectedKey.getString("value")).toString().toByteArray()
                        try {rescue.put("acceptance-owner-rescue",checkpoint)} finally {checkpoint.fill(0)}
                        val recoveryFile=document("sirrec")
                        call("export_recovery_package",args("key" to recovery.getString("key"),"password" to password,"path" to recoveryFile,"confirmed" to true))
                        call("import_recovery_package",args("password" to wrong,"path" to recoveryFile),true)
                        val recoveredKey=call("import_recovery_package",args("password" to password,"path" to recoveryFile)) as JSONObject
                        assertEquals(recovery.getString("recovery_id"),recoveredKey.getString("recovery_id"))
                        call("authorize_document_share",JSONObject().put("uri",recoveryFile))
                        passed("Encrypted recovery document roundtrip, wrong password and share authorization")
                        val backup=document("sirinbackup")
                        call("export_server_backup",args("password" to password,"path" to backup,"confirmed" to true))
                        call("import_server_backup",args("password" to wrong,"path" to backup),true)
                        call("import_server_backup",args("password" to password,"path" to backup),true)
                        call("disconnect_server")
                        call("remove_server",JSONObject().put("serverId",id))
                        call("import_server_backup",args("password" to password,"path" to backup))
                        connected();passed("Encrypted device backup roundtrip and duplicate protection")
                        val invitation=call("create_invitation",args("member_name" to "Disposable member","device_name" to "Disposable device","expires_in_seconds" to 1800,"recipient_names" to true,"max_uses" to 1,"member_policy" to JSONObject())) as JSONObject
                        call("disconnect_server")
                        call("remove_server",JSONObject().put("serverId",id))
                        val member=call("join_server",args("code" to invitation.getString("code"),"member_name" to "Disposable member","device_name" to "Disposable device")) as JSONObject
                        assertEquals("member",member.getString("role"))
                        assertEquals("member",status(id).getString("caller_role"))
                        call("create_recovery_key",args("confirmed" to true),true)
                        call("update_recovery_policy",JSONObject().put("serverId",id).put("administratorMemberIds",org.json.JSONArray()),true)
                        passed("Member enrollment and server-side Owner restrictions")
                        call("disconnect_server")
                        val restored=call("recover_owner_access",args("key" to recoveredKey.getString("key"),"device_name" to "Recovered Android owner","confirmed" to true,"replace_existing" to true)) as JSONObject
                        assertEquals("owner",restored.getString("role"))
                        assertEquals("owner",status(id).getString("caller_role"))
                        rescue.delete("acceptance-owner-rescue")
                        passed("Offline Owner recovery and authenticated traffic")
                        call("disconnect_server")
                        val ssh=JSONObject(input.toString()).put("server_id",id).put("authentication","saved").put("confirmed",true)
                        val bad=JSONObject(ssh.toString()).put("host_key_sha256","SHA256:"+"A".repeat(43))
                        call("repair_server",JSONObject().put("input",bad),true)
                        call("repair_server",JSONObject().put("input",ssh))
                        connected();call("disconnect_server");passed("Pinned SSH repair with Owner identity preserved")
                        val vpsBackup=document("sirvps")
                        ssh.put("path",vpsBackup).put("backup_password",password)
                        call("export_vps_backup",JSONObject().put("input",ssh))
                        call("restore_vps_backup",JSONObject().put("input",JSONObject(ssh.toString()).put("replace_existing",false)),true)
                        call("restore_vps_backup",JSONObject().put("input",JSONObject(ssh.toString()).put("replace_existing",true)))
                        connected();passed("Encrypted VPS backup and explicit replacement restore")
                    } finally {uris.forEach {context.contentResolver.delete(it,null,null)}}
                }
                "provision" -> {
                    val inputFile=java.io.File(context.noBackupFilesDir,"acceptance-vps-input")
                    val input=try {JSONObject(inputFile.readText())} finally {inputFile.delete()}
                    assertEquals("10.0.2.2",input.getString("host"))
                    assertEquals("Android isolated VPS",input.getString("name"))
                    assertFalse(input.getBoolean("replace_existing_installation"))
                    val key=call("remember_secret",JSONObject().put("value",input.getString("private_key_pem"))) as String
                    input.put("private_key_pem",key)
                    val inspection=call("inspect_ssh_host",JSONObject().put("input",JSONObject().put("host",input.getString("host")).put("port",input.getInt("ssh_port")))) as JSONObject
                    assertEquals(input.getString("host_key_sha256"),inspection.getString("fingerprint"))
                    call("trust_ssh_host",JSONObject().put("input",JSONObject().put("host",input.getString("host")).put("port",input.getInt("ssh_port"))).put("fingerprint",inspection.getString("fingerprint")))
                    call("save_ssh_login",JSONObject().put("input",input))
                    val result=call("provision_server",JSONObject().put("input",input)) as JSONObject
                    assertEquals("owner",result.getJSONObject("profile").getString("role"))
                    java.io.File(context.noBackupFilesDir,"acceptance-vps-result.json").writeText(JSONObject()
                        .put("server_id",result.getJSONObject("profile").getString("id")).put("fixture",input.getString("fixture")).toString())
                }
                "fixture_invitation" -> {
                    val enrolled=JSONObject(java.io.File(context.noBackupFilesDir,"acceptance-vps-result.json").readText())
                    val id=enrolled.getString("server_id")
                    val profiles=call("list_servers") as org.json.JSONArray
                    val profile=(0 until profiles.length()).map {profiles.getJSONObject(it)}.single {it.getString("id")==id}
                    assertEquals("10.0.2.2",profile.getJSONObject("endpoint").getString("host"))
                    assertEquals("Android isolated VPS",profile.getString("name"))
                    call("connect_saved",JSONObject().put("serverId",id))
                    val invitation=call("create_invitation",JSONObject().put("input",JSONObject().put("server_id",id)
                        .put("member_name","API boundary acceptance").put("device_name","Isolated emulator").put("expires_in_seconds",3600)
                        .put("max_uses",1).put("recipient_names",true).put("administrator",false)
                        .put("member_policy",JSONObject().put("device_limit",1)))) as JSONObject
                    val code=(call("reveal_secret",JSONObject().put("reference",invitation.getString("code"))) as JSONObject).getString("value")
                    java.io.File(context.noBackupFilesDir,"acceptance-api29-invitation").writeText(code)
                }
                "join" -> {
                    val input = java.io.File(context.noBackupFilesDir,"acceptance-invitation")
                    val invitation = input.readText().trim()
                    try {
                        val reference = call("remember_secret",JSONObject().put("value",invitation)) as String
                        call("preview_invitation",JSONObject().put("code",reference))
                        call("join_server",JSONObject().put("input",JSONObject().put("code",reference)
                            .put("member_name","Android acceptance").put("device_name","SirinVPN emulator")))
                    } finally { input.delete() }
                }
                "connect" -> call("connect_saved")
                "disconnect" -> call("disconnect_server")
                "traffic" -> {
                    val status = JSONObject(control.snapshot()).getJSONObject("status")
                    val result = call("server_status",JSONObject().put("serverId",status.getString("server_id"))) as JSONObject
                    assertTrue("Pinned private management endpoint responded", result.length() > 0)
                }
                "stale_action" -> {
                    val before = JSONObject(control.snapshot()).getLong("generation")
                    val done = CountDownLatch(1)
                    control.execute("disconnect_server","{}",UUID.randomUUID().toString(),before-1,object:IResult.Stub(){
                        override fun complete(result:String) { assertTrue(JSONObject(result).has("error"));done.countDown() }
                    })
                    assertTrue(done.await(5,TimeUnit.SECONDS))
                    assertEquals(before,JSONObject(control.snapshot()).getLong("generation"))
                }
                "snapshot" -> Unit
                else -> throw IllegalArgumentException("Unknown acceptance action")
            }
            val status = JSONObject(control.snapshot())
            val local = status.getJSONObject("status")
            val evidence = JSONObject().put("phase",status.getString("phase")).put("generation",status.getLong("generation"))
                .put("rx_bytes",local.optLong("rx_bytes")).put("tx_bytes",local.optLong("tx_bytes"))
                .put("uptime",local.optLong("tunnel_uptime_seconds")).put("observer_pid",android.os.Process.myPid())
            java.io.File(context.noBackupFilesDir,"acceptance-result.json").writeText(evidence.toString())
        } finally { instrumentation.runOnMainSync { link.close() } }
    }
}
