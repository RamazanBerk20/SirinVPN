package org.sirinvpn.client

import android.content.Context
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import org.json.JSONObject
import java.net.InetAddress

/** Called inside :vpn. Protected forms use native Binder; Tauri receives opaque handles. */
class NativePlatform(private val context: Context) {
    init {
        val hashes=JSONObject(context.assets.open("server-payloads/sha256.json").bufferedReader().use { it.readText() })
        for(arch in listOf("x86_64","aarch64")) {
            val file=java.io.File(context.noBackupFilesDir,"server-payloads/$arch/sirinvpn-server")
            val expected=hashes.getString(arch)
            fun digest(value:java.io.File)=value.inputStream().use { input ->
                val hash=java.security.MessageDigest.getInstance("SHA-256");val buffer=ByteArray(8192)
                while(true) {val count=input.read(buffer);if(count<0)break;hash.update(buffer,0,count)}
                hash.digest().joinToString("") { "%02x".format(it) }
            }
            if(!file.isFile || digest(file)!=expected) {
                file.parentFile!!.mkdirs();val atomic=android.util.AtomicFile(file);val output=atomic.startWrite()
                try {context.assets.open("server-payloads/$arch/sirinvpn-server").use { it.copyTo(output) };atomic.finishWrite(output)}
                catch(error:Exception){atomic.failWrite(output);throw error}
                check(digest(file)==expected)
            }
        }
    }
    fun installedApk(): String = context.applicationInfo.sourceDir
    fun installApk(path: String) = ApkInstaller.install(context,path)
    fun abandonApk() = ApkInstaller.abandon(context)
    private val vault = SecretVault(context)
    fun secretGet(reference: String): ByteArray? = vault.get(reference)
    fun secretPut(reference: String, value: ByteArray) = vault.put(reference, value)
    fun secretDelete(reference: String) = vault.delete(reference)
    // Rewritable runtime state; identity deletion stays permanent above.
    fun blobPut(reference: String, value: ByteArray) = vault.replace(reference, value)
    fun blobDelete(reference: String) = vault.discard(reference)
    fun readDocument(value: String): ByteArray {
        val uri = android.net.Uri.parse(value); require(uri.scheme == "content")
        return context.contentResolver.openInputStream(uri)!!.use { stream ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                require(output.size() + count <= 8 * 1024 * 1024)
                output.write(buffer, 0, count)
            }
            buffer.fill(0); output.toByteArray()
        }
    }
    fun writeDocument(value: String, bytes: ByteArray) {
        val uri = android.net.Uri.parse(value); require(uri.scheme == "content")
        context.contentResolver.openOutputStream(uri,"wt")!!.use { stream -> stream.write(bytes); stream.flush() }
        Controller.exported(value)
    }
    /** Regular documents directly inside an Owner-chosen tree, by display name. */
    private fun treeChildren(value: String): List<Pair<String, android.net.Uri>> {
        val tree = android.net.Uri.parse(value); require(tree.scheme == "content")
        val columns = arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        val result = mutableListOf<Pair<String, android.net.Uri>>()
        context.contentResolver.query(children, columns, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) if (cursor.getString(2) != Document.MIME_TYPE_DIR)
                result += cursor.getString(1) to DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(0))
        }
        return result
    }
    fun listTree(value: String): String = org.json.JSONArray(treeChildren(value).map { it.first }).toString()
    fun writeTreeDocument(value: String, name: String, bytes: ByteArray) {
        val tree = android.net.Uri.parse(value); require(tree.scheme == "content")
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        val uri = DocumentsContract.createDocument(context.contentResolver, parent, "application/octet-stream", name) ?: error("Backup folder unavailable")
        try { context.contentResolver.openOutputStream(uri, "wt")!!.use { stream -> stream.write(bytes); stream.flush() } }
        catch (error: Exception) { DocumentsContract.deleteDocument(context.contentResolver, uri); throw error }
    }
    fun deleteTreeDocument(value: String, name: String) {
        for ((_, uri) in treeChildren(value).filter { it.first == name }) DocumentsContract.deleteDocument(context.contentResolver, uri)
    }
    fun isCurrent(generation: Long): Boolean = Controller.current(generation)
    fun prepareConnection(arguments:String,generation:Long) = Controller.prepareConnection(JSONObject(arguments),generation)
    fun connectionPreferences(id:String):String? {
        val args=JSONObject(context.getSharedPreferences("connection-intent",Context.MODE_PRIVATE).getString("requested_arguments","{}")!!)
        return if(args.optString("serverId")==id) args.optJSONObject("preferences")?.toString() else null
    }
    fun qualityState(generation:Long):String? = Controller.qualityState(generation)?.toString()
    fun qualityResult(value:String?,generation:Long) = Controller.qualityResult(value?.let(::JSONObject),generation)
    fun handoff(value:String,generation:Long):Boolean = Controller.handoff(JSONObject(value),generation)
    fun measure(value:String,generation:Long):String? {
        val c=JSONObject(value)
        if(Controller.qualityState(generation)==null) return null
        if(c.optString("mode")=="active") {
            val result=PathMeasurements.sample(Controller.qualityState(generation) ?: return null)
            return if(Controller.qualityState(generation)!=null) result?.toString() else null
        }
        val handle=WireGuard.probeStart(c.getString("wireguard"))
        if(handle<0) return null
        try {
            for(fd in intArrayOf(WireGuard.socket4(handle),WireGuard.socket6(handle))) if(fd>=0 && !protectSocket(fd)) return null
            if(!WireGuard.commit(handle)) return null
            val deadline=android.os.SystemClock.elapsedRealtime()+3000
            while((WireGuard.statistics(handle)?.get(2) ?: 0)==0L) {
                if(Controller.qualityState(generation)==null || android.os.SystemClock.elapsedRealtime()>deadline) return null
                Thread.sleep(25)
            }
            val sample=WireGuard.probeSample(handle,c.getString("source"),c.getString("destination")) ?: return null
            if(Controller.qualityState(generation)==null) return null
            return JSONObject().put("transport",c.getString("transport")).put("probes_sent",8).put("probes_received",sample[0])
                .put("latency_micros",sample[1]).put("jitter_micros",sample[2]).toString()
        } finally {WireGuard.stop(handle)}
    }
    fun hasHandshake(): Boolean = synchronized(Controller.engineLock) { Controller.handle >= 0 && (WireGuard.statistics(Controller.handle)?.get(2) ?: 0) > 0 }
    fun isActive(id: String): Boolean = Controller.snapshot().getJSONObject("status").let { it.optString("server_id") == id && Controller.handle >= 0 }
    fun isInactive(id: String): Boolean = Controller.snapshot().getJSONObject("status").let { Controller.handle < 0 || id.isNotEmpty() && it.optString("server_id") != id }
    fun protectSocket(fd: Int): Boolean {
        if (SirinVpnService.instance?.protect(fd) != true) return false
        val underlying = Controller.network ?: return false
        return try { ParcelFileDescriptor.fromFd(fd).use { underlying.bindSocket(it.fileDescriptor) }; true } catch (_: Exception) { false }
    }
    fun resolve(host: String): String {
        val network = Controller.network ?: error("No underlying network")
        return network.getAllByName(host).first().hostAddress ?: error("Endpoint unavailable")
    }
    fun activate(configuration: String, generation: Long): Boolean = synchronized(Controller.engineLock) {
        if (!Controller.current(generation)) return false
        val service = SirinVpnService.instance ?: return false
        if(!service.accepts(generation)) return false
        val c = JSONObject(configuration)
        c.put("mtu",Controller.effectiveMtu(c))
        val builder = service.Builder().setSession("SirinVPN").setMtu(c.getInt("mtu")).setBlocking(true)
        builder.setMetered(false)
        builder.setConfigureIntent(VpnNotifications.openApp(context))
        for (key in listOf("addresses", "routes")) {
            val list = c.getJSONArray(key)
            for (i in 0 until list.length()) {
                val parts = list.getString(i).split('/')
                if (key == "addresses") builder.addAddress(parts[0], parts[1].toInt())
                else builder.addRoute(parts[0], parts[1].toInt())
            }
        }
        builder.addDnsServer(c.getString("dns"))
        val apps = c.optJSONObject("applications")
        if (apps != null) {
            val packages = apps.getJSONArray("packages")
            for (i in 0 until packages.length()) {
                val name = packages.getString(i)
                // Never exclude SirinVPN as a shortcut for transport protection.
                require(name != context.packageName)
                // A selected application may since have been uninstalled.
                try {
                    if (apps.getString("mode") == "include") builder.addAllowedApplication(name)
                    else if (apps.getString("mode") == "exclude") builder.addDisallowedApplication(name)
                } catch (_: android.content.pm.PackageManager.NameNotFoundException) {}
            }
            if (apps.getString("mode") == "include") builder.addAllowedApplication(context.packageName)
        }
        builder.setUnderlyingNetworks(Controller.network?.let { arrayOf(it) })
        val tun = builder.establish() ?: return false
        Controller.stopWireGuard()
        val handle = WireGuard.start(tun.detachFd(), c.getString("wireguard"))
        if (handle < 0) return false
        Controller.handle = handle
        for (fd in intArrayOf(WireGuard.socket4(handle), WireGuard.socket6(handle))) {
            if (fd >= 0 && !protectSocket(fd)) { Controller.stopEngine(); return false }
        }
        if (!WireGuard.commit(handle)) { Controller.stopEngine(); return false }
        Controller.activated(c, generation)
        true
    }
    fun deactivate(generation: Long) = synchronized(Controller.engineLock) {
        if (Controller.current(generation)) Controller.stopEngine()
    }
}
