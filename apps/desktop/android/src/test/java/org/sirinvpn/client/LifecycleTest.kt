package org.sirinvpn.client

import org.junit.Assert.*
import org.junit.Test
import org.sirinvpn.client.Session.*
import org.sirinvpn.client.SessionEvent as E

class LifecycleTest {
    private fun Session.after(vararg events: E) = events.fold(this) { session, event -> session.next(event) }

    @Test fun aConnectionWaitsForANetworkThenConnects() {
        assertEquals(WaitingForNetwork, Idle.next(E.Connect(network = false)))
        assertEquals(Connected, Idle.after(E.Connect(true), E.Activated, E.Established(handoff = false, network = true)))
        // A network change during the attempt leaves a pending handoff.
        assertEquals(Recovering, Connecting.next(E.Established(handoff = true, network = true)))
        assertEquals(WaitingForNetwork, Connecting.next(E.Established(handoff = true, network = false)))
    }

    @Test fun failuresRetryOnlyWhenScheduledAndRejectedAttemptsKeepTheRunningSession() {
        assertEquals(Recovering, Connecting.next(E.AttemptFailed(retry = true, network = true)))
        assertEquals(WaitingForNetwork, Connecting.next(E.AttemptFailed(retry = true, network = false)))
        assertEquals(Failed, Recovering.next(E.AttemptFailed(retry = false, network = true)))
        assertEquals(Unhealthy(true), Connecting.next(E.Rejected(Unhealthy(true))))
        assertEquals(Failed, Connecting.next(E.StartFailed))
        assertEquals(PermissionRequired, Stopped.next(E.ConsentMissing))
    }

    @Test fun stoppingAndEngineLoss() {
        assertEquals(Stopped, Connected.next(E.Stop(user = true)))
        // Revoke, Always-on takeover and a reconstruction refusal stop without pausing automation.
        assertEquals(Idle, Recovering.next(E.Stop(user = false)))
        assertEquals(Idle, Connected.next(E.EngineStopped))
        assertEquals(Failed, Failed.next(E.EngineStopped))
        assertEquals(WaitingForNetwork, Connected.next(E.NetworkLost))
        assertEquals(Recovering, WaitingForNetwork.next(E.Reconnect))
    }

    @Test fun samplesReclassifyOnlyAnUnreadableEngine() {
        val unknown = Connected.next(E.Unreadable)
        assertEquals(Unhealthy(false), unknown)
        assertEquals(Idle, unknown.next(E.NoEngine(pending = false, network = true)))
        assertEquals(WaitingForNetwork, unknown.next(E.NoEngine(pending = true, network = false)))
        assertEquals(Recovering, unknown.next(E.NoEngine(pending = true, network = true)))
        assertEquals(Connecting, unknown.next(E.NoHandshake(network = true, busy = true)))
        assertEquals(Unhealthy(true), unknown.next(E.NoHandshake(network = true, busy = false)))
        for (other in listOf(Idle, Stopped, Connecting, Connected, Recovering)) {
            assertEquals(other, other.next(E.NoEngine(pending = false, network = true)))
            assertEquals(other, other.next(E.NoHandshake(network = false, busy = false)))
        }
        assertEquals(Unhealthy(true), Connected.next(E.Health(healthy = false)))
        assertEquals(Connected, Unhealthy(true).next(E.Health(healthy = true)))
    }

    @Test fun theEmittedPhaseHasRustTunnelPhasesShape() {
        for (held in listOf(Idle, Stopped, PermissionRequired, Failed)) assertEquals(TunnelPhase("idle", null), held.phase("s", true))
        assertEquals(TunnelPhase("connecting", "s"), Connecting.phase("s", false))
        assertEquals(TunnelPhase("connecting", "s"), WaitingForNetwork.phase("s", false))
        assertEquals(TunnelPhase("recovering", "s"), WaitingForNetwork.phase("s", true))
        assertEquals(TunnelPhase("recovering", "s"), Recovering.phase("s", false))
        assertEquals(TunnelPhase("connected", "s"), Connected.phase("s", false))
        assertEquals(TunnelPhase("unhealthy", "s", true), Unhealthy(false).phase("s", true))
        assertEquals(TunnelPhase("unhealthy", "s", false), Unhealthy(true).phase("s", false))
    }

    @Test fun wireNamesRoundTripAndKeepTheLegacyStrings() {
        val names = mapOf(Idle to "disconnected", Stopped to "paused", PermissionRequired to "permission_required", Failed to "failed",
            Connecting to "connecting", WaitingForNetwork to "waiting_for_network", Recovering to "reconnecting",
            Connected to "connected", Unhealthy(true) to "degraded", Unhealthy(false) to "unknown")
        for ((session, wire) in names) {
            assertEquals(wire, session.wire)
            assertEquals(session, Session.fromWire(wire))
        }
        assertNull(Session.fromWire(null))
        assertNull(Session.fromWire("disconnecting"))
        // The tile, widget and automation's "running" set, unchanged from their old string lists.
        assertEquals(setOf(Connected, Connecting, Recovering, WaitingForNetwork, Unhealthy(true)), names.keys.filter { it.running }.toSet())
        assertEquals(setOf(Connected, Unhealthy(true)), names.keys.filter { it.established }.toSet())
    }
}
