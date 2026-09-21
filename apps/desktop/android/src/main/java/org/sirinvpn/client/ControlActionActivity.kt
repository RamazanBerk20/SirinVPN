package org.sirinvpn.client

import android.app.Activity
import android.app.KeyguardManager
import android.os.Bundle
import java.util.UUID

/** Transient authentication surface; never starts or owns the VPN engine. */
class ControlActionActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val manager = getSystemService(KeyguardManager::class.java)
        if(!manager.isDeviceLocked) { prepare();return }
        manager.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
            override fun onDismissSucceeded() { prepare() }
            override fun onDismissCancelled() { finish() }
            override fun onDismissError() { finish() }
        })
    }
    private fun prepare() {
        if(intent.getStringExtra("command")=="connect_saved") {
            android.net.VpnService.prepare(this)?.let { startActivityForResult(it,1);return }
        }
        performCommand()
    }
    @Deprecated("Android consent is delivered through the platform Activity callback")
    override fun onActivityResult(requestCode:Int,resultCode:Int,data:android.content.Intent?) {
        super.onActivityResult(requestCode,resultCode,data)
        if(requestCode==1 && resultCode==RESULT_OK) performCommand() else finish()
    }
    private fun performCommand() {
        val command=if(intent.getStringExtra("command")=="connect_saved") "connect_saved" else "disconnect_server"
        val link = ServiceLink(this); link.bind()
        link.ready.whenComplete { service, error ->
            if (error == null) service.execute(command, "{}", UUID.randomUUID().toString(), intent.getLongExtra("generation", -2),
                object : IResult.Stub() { override fun complete(result: String) { runOnUiThread { link.close(); finish() } } })
            else { link.close(); finish() }
        }
    }
}
