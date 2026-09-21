package org.sirinvpn.client

import android.os.SystemClock
import org.json.JSONObject
import org.json.JSONArray
import java.util.UUID

/** Ephemeral native form values, bounded and never persisted as an input history. */
object SecretInputs {
    private data class Entry(val value: CharArray, val expires: Long, val qr: JSONArray?)
    private val entries = LinkedHashMap<String, Entry>()
    @Synchronized fun remember(value: String, qr: JSONArray? = null): String {
        require(value.length in 1..131072)
        purge()
        // Confirmation fields can compare opaque handles without seeing the password.
        entries.entries.firstOrNull { it.value.value.contentEquals(value.toCharArray()) }?.let { return it.key }
        check(entries.size < 16) { "Too many protected values. Finish the current operation." }
        val reference = "native-secret:" + UUID.randomUUID()
        entries[reference] = Entry(value.toCharArray(), SystemClock.elapsedRealtime() + 600000, qr)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ purge() },600001)
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
    @Synchronized fun resolve(value: Any): Any {
        purge()
        return when (value) {
            is String -> if (value.startsWith("native-secret:")) String(entries[value]?.value ?: error("Protected input expired")) else value
            is JSONObject -> JSONObject().also { output -> value.keys().forEach { key -> output.put(key,resolve(value.get(key))) } }
            is JSONArray -> JSONArray().also { output -> for (i in 0 until value.length()) output.put(resolve(value.get(i))) }
            else -> value
        }
    }
}
