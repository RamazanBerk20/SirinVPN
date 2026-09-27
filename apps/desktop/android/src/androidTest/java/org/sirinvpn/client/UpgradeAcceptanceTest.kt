package org.sirinvpn.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Only synthetic state in a fresh AVD; host installs the exact old and candidate APKs. */
@RunWith(AndroidJUnit4::class)
class UpgradeAcceptanceTest {
    private fun context(): android.content.Context {
        assertTrue(BuildConfig.DEBUG)
        assertTrue(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        return InstrumentationRegistry.getInstrumentation().targetContext
    }
    private val reference = "acceptance-upgrade"
    private val deleted = "acceptance-upgrade-deleted"
    private val value = "Public synthetic upgrade identity".toByteArray()
    private fun hash(file: File) = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }

    @Test fun seed() {
        val c=context(); val root=c.noBackupFilesDir
        val profiles=File(root,"servers.json")
        assertTrue(!profiles.exists() || JSONObject(profiles.readText()).getJSONArray("servers").length()==0)
        val metadata=File(root,"acceptance-upgrade.json"); assertFalse(metadata.exists())
        val vault=SecretVault(c); vault.put(reference,value); vault.put(deleted,value); vault.delete(deleted)
        fun key()=android.util.Base64.encodeToString(ByteArray(32).also {java.security.SecureRandom().nextBytes(it)},android.util.Base64.NO_WRAP)
        val id=UUID.randomUUID().toString()
        val profile=JSONObject().put("schema_version",1).put("id",id).put("name","Upgrade fixture")
            .put("endpoint",JSONObject().put("host","10.0.2.2").put("wireguard_port",9))
            .put("client_tunnel_address","10.77.0.2").put("server_tunnel_address","10.77.0.1")
            .put("server_wireguard_public_key",key()).put("pinned_server_certificate_pem","")
            .put("client_management_certificate_pem","").put("identity_reference",reference).put("role","member")
        profiles.writeText(JSONObject().put("schema_version",1).put("servers",JSONArray().put(profile)).toString())
        assertTrue(c.getSharedPreferences("connection-intent",0).edit().putBoolean("requested",true).putBoolean("paused",true).commit())
        metadata.writeText(JSONObject().put("id",id).put("version",c.packageManager.getPackageInfo(c.packageName,0).longVersionCode)
            .put("profile_sha256",hash(profiles)).put("ciphertext_sha256",hash(File(root,"credentials/$reference.enc"))).toString())
    }

    @Test fun verifyPreserved() {
        val c=context(); val root=c.noBackupFilesDir
        val metadata=JSONObject(File(root,"acceptance-upgrade.json").readText())
        val version=c.packageManager.getPackageInfo(c.packageName,0).longVersionCode
        if(InstrumentationRegistry.getArguments().getString("expectation")=="old") assertEquals(metadata.getLong("version"),version)
        else assertTrue("Candidate must increase the installed version",version>metadata.getLong("version"))
        assertEquals(metadata.getString("profile_sha256"),hash(File(root,"servers.json")))
        assertEquals(metadata.getString("ciphertext_sha256"),hash(File(root,"credentials/$reference.enc")))
        val vault=SecretVault(c); assertArrayEquals(value,vault.get(reference)); assertNull(vault.get(deleted))
        assertTrue("Deleted reference must remain unwritable",runCatching {vault.put(deleted,value)}.isFailure)
        assertTrue(c.getSharedPreferences("connection-intent",0).getBoolean("paused",false))
        assertTrue(Native.initialize(root.absolutePath,NativePlatform(c)))
        val result=JSONObject(Native.call("list_servers","{}",0))
        assertFalse(result.toString(),result.has("error"))
        assertEquals(metadata.getString("id"),result.getJSONArray("ok").getJSONObject(0).getString("id"))
    }

    @Test fun cleanup() {
        val c=context(); val vault=SecretVault(c)
        vault.delete(reference);vault.delete(deleted)
        assertTrue(File(c.noBackupFilesDir,"servers.json").delete())
        assertTrue(File(c.noBackupFilesDir,"acceptance-upgrade.json").delete())
        assertTrue(c.getSharedPreferences("connection-intent",0).edit().clear().commit())
    }
}
