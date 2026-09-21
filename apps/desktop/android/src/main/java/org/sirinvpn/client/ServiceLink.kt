package org.sirinvpn.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import java.util.concurrent.CompletableFuture

class ServiceLink(context: Context, private val lost: () -> Unit = {}, private val connected: (IControl) -> Unit = {}) : AutoCloseable {
    // ReceiverRestrictedContext cannot bind; bindings also outlive transient Activities.
    private val context=context.applicationContext
    var ready = CompletableFuture<IControl>(); private set
    private var bound = false
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val control=IControl.Stub.asInterface(binder)
            try { connected(control); ready.complete(control) }
            catch (_:Exception) { ready.completeExceptionally(IllegalStateException("Service unavailable"));lost() }
        }
        override fun onServiceDisconnected(name: ComponentName) { ready = CompletableFuture(); lost() }
        override fun onBindingDied(name: ComponentName) { close(); ready=CompletableFuture(); lost(); bind() }
        override fun onNullBinding(name: ComponentName) { ready.completeExceptionally(IllegalStateException("Service unavailable")) }
    }
    fun bind() {
        if (bound) return
        bound = context.bindService(Intent(context, ControlService::class.java), connection, Context.BIND_AUTO_CREATE)
        if (!bound) ready.completeExceptionally(IllegalStateException("Service unavailable"))
    }
    override fun close() {
        if (bound) { context.unbindService(connection); bound = false }
        ready.completeExceptionally(java.util.concurrent.CancellationException())
    }
}
