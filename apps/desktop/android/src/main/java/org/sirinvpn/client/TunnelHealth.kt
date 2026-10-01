package org.sirinvpn.client

/** Observe authenticated progress using elapsed time, not the peer's wall-clock timestamp. */
internal class TunnelHealth {
    private var sampledAt: Long? = null
    private var received = 0L
    private var handshake = 0L
    private var progressedAt = 0L

    fun record(now: Long, rx: Long, lastHandshake: Long): Boolean {
        require(now >= 0 && rx >= 0 && lastHandshake >= 0)
        val previous = sampledAt
        // Sleep, a stalled sampler or a replaced engine needs a fresh observation window.
        if (previous == null || now < previous || now - previous > 30000 ||
            rx != received || lastHandshake != handshake) progressedAt = now
        sampledAt = now
        received = rx
        handshake = lastHandshake
        return now - progressedAt < 180000
    }
}
