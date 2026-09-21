package org.sirinvpn.client

import android.os.SystemClock
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** Bounded probes to the private VPS address. Output is consumed, never logged or stored. */
object PathMeasurements {
    private fun ping(source:String,destination:String,size:Int,count:Int):String? {
        require(source.matches(Regex("[0-9.]+")) && destination.matches(Regex("[0-9.]+")))
        val process=ProcessBuilder("/system/bin/ping","-n","-c",count.toString(),"-i","0.2","-W","1","-w",if(count==8) "4" else "1",
            "-M","do","-I",source,"-s",size.toString(),destination).redirectErrorStream(true).apply {environment()["LC_ALL"]="C"}.start()
        return try {
            if(!process.waitFor(if(count==8) 5 else 2,TimeUnit.SECONDS)) {process.destroyForcibly();null}
            else process.inputStream.use { stream -> val bytes=ByteArray(8192);val countRead=stream.read(bytes);if(countRead<0) null else String(bytes,0,countRead) }
        } finally {process.destroy()}
    }
    fun sample(config:JSONObject):JSONObject? {
        val source=config.getJSONArray("addresses").getString(0).substringBefore('/')
        val destination=config.getString("dns")
        val times=ping(source,destination,32,8)?.let { output ->
            Regex("time[=<]([0-9.]+) ?ms").findAll(output).mapNotNull { it.groupValues[1].toDoubleOrNull() }.take(8).toList()
        }.orEmpty()
        val average=if(times.isNotEmpty()) times.average() else 0.0
        val deviation=if(times.isNotEmpty()) kotlin.math.sqrt(times.map { (it-average)*(it-average) }.average()) else 0.0
        return if(times.isEmpty()) null else JSONObject().put("transport",config.getString("transport"))
            .put("probes_sent",8).put("probes_received",times.size).put("latency_micros",(average*1000).toInt()).put("jitter_micros",(deviation*1000).toInt())
    }
    fun measure(config:JSONObject,current:()->Boolean):Pair<JSONObject,JSONObject> {
        val source=config.getJSONArray("addresses").getString(0).substringBefore('/')
        val destination=config.getString("dns")
        val sample=sample(config)
        val quality=JSONObject().put("isolated_measurement_supported",false).put("candidates_checked",1)
            .put("selection",if(sample==null) "icmp_unavailable" else "observing").put("sample",sample ?: JSONObject.NULL)
        val ceiling=config.getInt("mtu");val minimum=if(config.optBoolean("ipv6_tunneled")) 1280 else 576
        val mtu=JSONObject().put("policy",if(config.optBoolean("mtu_automatic")) JSONObject().put("mode","automatic") else JSONObject().put("mode","manual").put("value",ceiling))
            .put("configured",ceiling).put("suggested",JSONObject.NULL).put("outcome",if(sample==null) "icmp_unavailable" else "no_usable_mtu")
        if(sample!=null) {
            val deadline=SystemClock.elapsedRealtime()+8000
            val candidates=(listOf(ceiling,1380,1320,1280,1200,1024,768,576)).filter { it in minimum..ceiling }.distinct()
            for(candidate in candidates) {
                if(!current() || SystemClock.elapsedRealtime()>deadline) break
                if((0..1).all { ping(source,destination,candidate-28,1)?.contains("1 received")==true }) {
                    mtu.put("suggested",candidate).put("outcome","measured");break
                }
            }
        }
        return Pair(quality,mtu)
    }
}
