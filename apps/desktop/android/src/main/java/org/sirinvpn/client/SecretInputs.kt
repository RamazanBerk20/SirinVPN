package org.sirinvpn.client

import android.os.SystemClock
import org.json.JSONObject
import org.json.JSONArray
import java.util.UUID

/** Ephemeral native form values, bounded and never persisted as an input history. */
object SecretInputs {
    /** [field] binds a service-generated secret to the only argument that may consume it. */
    private data class Entry(val value: CharArray, val expires: Long, val qr: JSONArray?, val field: String?)
    private val entries = LinkedHashMap<String, Entry>()
    // Arguments that carry protected values. A handle anywhere else (a name, a
    // label) could be stored or echoed back, revealing its plaintext to the WebView.
    private val secretFields = setOf("password", "backup_password", "private_key_passphrase", "sudo_password", "key", "code", "apiToken")
    @Synchronized fun remember(value: String, qr: JSONArray? = null, field: String? = null): String {
        require(value.length in 1..131072)
        purge()
        val expires = SystemClock.elapsedRealtime() + 600000
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ purge() },600001)
        // Confirmation fields can compare opaque handles without seeing the password.
        // Entering a value again starts its lifetime again.
        entries.entries.firstOrNull { it.value.field == field && it.value.value.contentEquals(value.toCharArray()) }?.let { it.setValue(it.value.copy(expires = expires)); return it.key }
        check(entries.size < 16) { "Too many protected values. Finish the current operation." }
        val reference = "native-secret:" + UUID.randomUUID()
        entries[reference] = Entry(value.toCharArray(), expires, qr, field)
        return reference
    }
    @Synchronized fun reveal(reference: String): JSONObject {
        purge()
        val entry=entries[reference] ?: error("Protected input expired")
        return JSONObject().put("value",String(entry.value)).put("qr",entry.qr ?: JSONObject.NULL)
    }
    @Synchronized private fun purge() {
        val expired = entries.filterValues { it.expires < SystemClock.elapsedRealtime() }.keys
        expired.forEach { entries.remove(it)?.value?.fill('\u0000') }
    }
    @Synchronized fun resolve(value: Any, field: String? = null): Any {
        purge()
        return when (value) {
            is String -> if (value.startsWith("native-secret:")) {
                require(field != null && field in secretFields) { "Protected input is not accepted here" }
                val entry = entries[value] ?: error("Protected input expired")
                require(entry.field == null || entry.field == field) { "Protected input is not accepted here" }
                String(entry.value)
            } else value
            is JSONObject -> JSONObject().also { output -> value.keys().forEach { key -> output.put(key,resolve(value.get(key),key)) } }
            is JSONArray -> JSONArray().also { output -> for (i in 0 until value.length()) output.put(resolve(value.get(i))) }
            else -> value
        }
    }
}
