package org.sirinvpn.client

/**
 * The :vpn controller's connection lifecycle as one value. Pure Kotlin, so JVM tests run every
 * transition; Controller feeds it events and publishes the result. [wire] is the snapshot's
 * legacy `phase` string, which the UI, tile, widget, notification and automation read.
 */
sealed class Session(val wire: String) {
    /** No session runs and nothing is routed. */
    data object Idle : Session("disconnected")
    /** The user stopped the VPN; automation stays paused until an explicit connect. */
    data object Stopped : Session("paused")
    /** The attempt needs Android's VPN consent, which only the user can give. */
    data object PermissionRequired : Session("permission_required")
    /** Attempts ended without a tunnel and nothing retries. */
    data object Failed : Session("failed")
    data object Connecting : Session("connecting")
    /** A session is wanted but no underlying network can carry it. */
    data object WaitingForNetwork : Session("waiting_for_network")
    /** A retry or carrier handoff is scheduled. */
    data object Recovering : Session("reconnecting")
    data object Connected : Session("connected")
    /**
     * The engine runs but the controller can't vouch for it: [readable] counters show no peer
     * progress ("degraded"), or they could not be read at all ("unknown").
     */
    data class Unhealthy(val readable: Boolean) : Session(if (readable) "degraded" else "unknown")

    /** Tile, widget and automation treat these as a running VPN; an unreadable engine is not. */
    val running get() = attempting || this == Connected || this == Unhealthy(true)
    /** Disconnect, not "stop connecting". */
    val established get() = this == Connected || this == Unhealthy(true)
    /** An attempt is under way, so a Disconnect or a settings save may interrupt it. */
    val attempting get() = this == Connecting || this == Recovering || this == WaitingForNetwork

    /**
     * Rust's `TunnelPhase` for this session. Android holds no traffic block of its own (Always-on
     * lockdown is the system's), so the stopped, failed and consent states are Idle and Paused
     * never occurs. [recovering]: a retry, carrier handoff or connection attempt is pending.
     */
    fun phase(serverId: String?, recovering: Boolean): TunnelPhase = when (this) {
        Idle, Stopped, PermissionRequired, Failed -> TunnelPhase("idle", null)
        Connecting -> TunnelPhase("connecting", serverId)
        WaitingForNetwork -> TunnelPhase(if (recovering) "recovering" else "connecting", serverId)
        Recovering -> TunnelPhase("recovering", serverId)
        Connected -> TunnelPhase("connected", serverId)
        is Unhealthy -> TunnelPhase("unhealthy", serverId, recovering)
    }

    /** The pure transition function; anything not listed keeps the current session. */
    fun next(event: SessionEvent): Session = when (event) {
        is SessionEvent.Connect -> if (event.network) Connecting else WaitingForNetwork
        SessionEvent.ConsentMissing -> PermissionRequired
        SessionEvent.StartFailed -> Failed
        SessionEvent.Activated -> Connecting
        is SessionEvent.Established -> when {
            !event.handoff -> Connected
            !event.network -> WaitingForNetwork
            else -> Recovering
        }
        is SessionEvent.Rejected -> event.previous
        is SessionEvent.AttemptFailed -> when {
            !event.retry -> Failed
            event.network -> Recovering
            else -> WaitingForNetwork
        }
        is SessionEvent.Stop -> if (event.user) Stopped else Idle
        SessionEvent.EngineStopped -> if (this == Connected) Idle else this
        SessionEvent.NetworkLost -> WaitingForNetwork
        SessionEvent.Reconnect -> Recovering
        SessionEvent.Unreadable -> Unhealthy(false)
        // Only an unreadable engine is reclassified by what a later sample finds.
        is SessionEvent.NoEngine -> if (this != Unhealthy(false)) this else when {
            !event.pending -> Idle
            !event.network -> WaitingForNetwork
            else -> Recovering
        }
        is SessionEvent.NoHandshake -> if (this != Unhealthy(false)) this else when {
            !event.network -> WaitingForNetwork
            event.busy -> Connecting
            else -> Unhealthy(true)
        }
        is SessionEvent.Health -> if (event.healthy) Connected else Unhealthy(true)
    }

    companion object {
        private val all by lazy { listOf(Idle, Stopped, PermissionRequired, Failed, Connecting, WaitingForNetwork,
            Recovering, Connected, Unhealthy(true), Unhealthy(false)) }
        /** The session a snapshot's `phase` names; null for none (a lost service) or an unknown name. */
        fun fromWire(value: String?): Session? = all.firstOrNull { it.wire == value }
    }
}

/** What the controller observed or was asked to do. */
sealed interface SessionEvent {
    /** A connection command was accepted. */
    data class Connect(val network: Boolean) : SessionEvent
    data object ConsentMissing : SessionEvent
    /** Android refused the VPN's foreground start, or the queue refused a new attempt. */
    data object StartFailed : SessionEvent
    /** NativePlatform built the TUN and started a new engine. */
    data object Activated : SessionEvent
    /** The connection command succeeded; [handoff]: a network change arrived meanwhile. */
    data class Established(val handoff: Boolean, val network: Boolean) : SessionEvent
    /** The attempt never touched the running engine (local validation, full queue): its session stands. */
    data class Rejected(val previous: Session) : SessionEvent
    /** The attempt failed and its engine stopped; [retry]: another attempt is scheduled. */
    data class AttemptFailed(val retry: Boolean, val network: Boolean) : SessionEvent
    data class Stop(val user: Boolean) : SessionEvent
    data object EngineStopped : SessionEvent
    /** The running engine lost its underlying network. */
    data object NetworkLost : SessionEvent
    /** A retry or carrier handoff is scheduled on an available network. */
    data object Reconnect : SessionEvent
    /** The engine's counters could not be read. */
    data object Unreadable : SessionEvent
    /** No engine runs; [pending]: an attempt or retry is still on its way. */
    data class NoEngine(val pending: Boolean, val network: Boolean) : SessionEvent
    /** Counters were read but the peer never completed a handshake; [busy]: an attempt is running. */
    data class NoHandshake(val network: Boolean, val busy: Boolean) : SessionEvent
    /** Counters with a handshake, sampled while no attempt or handoff drives the session. */
    data class Health(val healthy: Boolean) : SessionEvent
}

/** Rust `TunnelPhase` (crates/tunnel-model/src/phase.rs): `kind` snake_case, `recovering` only when unhealthy. */
data class TunnelPhase(val kind: String, val serverId: String?, val recovering: Boolean? = null)

/** What holds the controller besides the tunnel itself. */
sealed interface Task {
    data object None : Task
    /** A settings save. It has its own worker and may run beside a connection attempt. */
    data object Settings : Task
    /** The engine moved to a measured carrier; until its result only connection commands change it. */
    data object QualitySwitch : Task
    /**
     * A worker command. [connection] starts or replaces the tunnel; [protected] is a key rotation
     * or endpoint change that Disconnect must not interrupt.
     */
    data class Command(val name: String, val connection: Boolean, val protected: Boolean) : Task
}
