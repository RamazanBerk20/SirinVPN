package org.sirinvpn.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeoutException

/** A binding to ControlService. Binder callbacks arrive on the main thread; callers wait on other threads or asynchronously. */
class ServiceLink(context: Context, private val lost: () -> Unit = {}, private val connected: (IControl) -> Unit = {}) : AutoCloseable {
    private sealed interface State {
        data object Unbound : State
        class Binding(val future: CompletableFuture<IControl>) : State
        class Bound(val control: IControl) : State
        /** Android keeps the binding and reconnects when the service process returns. */
        class Lost(val future: CompletableFuture<IControl>) : State
    }
    // ReceiverRestrictedContext cannot bind; bindings also outlive transient Activities.
    private val context=context.applicationContext
    private var state: State = State.Unbound
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val control=IControl.Stub.asInterface(binder)
            // A closed link ignores a late connection.
            val waiting=update { s -> if (s is State.Unbound) null else (pending(s) ?: CompletableFuture()).also { state=State.Bound(control) } } ?: return
            try { connected(control); waiting.complete(control) }
            catch (_:Exception) { waiting.completeExceptionally(IllegalStateException("Service unavailable"));lost() }
        }
        override fun onServiceDisconnected(name: ComponentName) { update { if (it is State.Bound) state=State.Lost(CompletableFuture()) }; lost() }
        override fun onBindingDied(name: ComponentName) { close(); lost(); bind() }
        override fun onNullBinding(name: ComponentName) { update { pending(it) }?.completeExceptionally(IllegalStateException("Service unavailable")) }
    }
    private fun <T> update(change: (State) -> T): T = synchronized(this) { change(state) }
    private fun pending(value: State) = when (value) { is State.Binding -> value.future; is State.Lost -> value.future; else -> null }

    fun bind() {
        val failed = update {
            if (it !is State.Unbound) return@update false
            state = State.Binding(CompletableFuture())
            !context.bindService(Intent(context, ControlService::class.java), connection, Context.BIND_AUTO_CREATE)
        }
        if (failed) update { s -> pending(s).also { state = State.Unbound } }?.completeExceptionally(IllegalStateException("Service unavailable"))
    }

    /** The bound control, if any, without waiting. */
    fun current(): IControl? = update { (it as? State.Bound)?.control }

    /**
     * The one way to reach the controller: binds if needed and completes with the control, or
     * exceptionally once [timeoutMs] passes or the link closes. Never block the main thread on it.
     */
    fun control(timeoutMs: Long): CompletableFuture<IControl> {
        bind()
        val result = CompletableFuture<IControl>()
        when (val now = update { it }) {
            is State.Bound -> result.complete(now.control)
            is State.Binding -> now.future.whenComplete { value, error -> if (error == null) result.complete(value) else result.completeExceptionally(error) }
            is State.Lost -> now.future.whenComplete { value, error -> if (error == null) result.complete(value) else result.completeExceptionally(error) }
            State.Unbound -> result.completeExceptionally(IllegalStateException("Service unavailable"))
        }
        Handler(Looper.getMainLooper()).postDelayed({ result.completeExceptionally(TimeoutException()) }, timeoutMs)
        return result
    }

    override fun close() {
        val waiting = update { s ->
            if (s !is State.Unbound) context.unbindService(connection)
            pending(s).also { state = State.Unbound }
        }
        waiting?.completeExceptionally(java.util.concurrent.CancellationException())
    }
}
