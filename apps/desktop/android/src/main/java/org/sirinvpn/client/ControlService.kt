package org.sirinvpn.client

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Process

class ControlService : Service() {
    override fun onCreate() { super.onCreate(); Controller.initialize(this) }
    private fun ownUid() { check(Binder.getCallingUid() == Process.myUid()) }
    private val control = object : IControl.Stub() {
        override fun snapshot(): String { ownUid(); return Controller.snapshot().toString() }
        override fun subscribe(listener: IStatus) { ownUid(); Controller.subscribe(listener) }
        override fun unsubscribe(listener: IStatus) { ownUid(); Controller.unsubscribe(listener) }
        override fun execute(command: String, arguments: String, requestId: String, generation: Long, result: IResult) {
            ownUid(); Controller.execute(command, arguments, requestId, generation, result)
        }
    }
    override fun onBind(intent: Intent): IBinder = control
}
