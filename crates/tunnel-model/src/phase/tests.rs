use super::*;
use TunnelEvent as E;

fn server() -> ServerId {
    ServerId::new()
}

fn phases(server_id: ServerId) -> [TunnelPhase; 7] {
    [
        TunnelPhase::Idle,
        TunnelPhase::Connecting { server_id },
        TunnelPhase::Connected { server_id },
        TunnelPhase::Recovering { server_id },
        TunnelPhase::Paused { server_id },
        TunnelPhase::Unhealthy {
            server_id,
            recovering: false,
        },
        TunnelPhase::Unhealthy {
            server_id,
            recovering: true,
        },
    ]
}

fn events(server_id: ServerId, other: ServerId) -> [TunnelEvent; 10] {
    [
        E::Connect { server_id },
        E::Connect { server_id: other },
        E::HandshakeConfirmed,
        E::PathLost,
        E::AttemptsExhausted,
        E::Pause,
        E::Resume,
        E::ObservationLost,
        E::ObservationRestored,
        E::Disconnect,
    ]
}

/// The whole transition table, one row per phase, one column per event in `events`.
/// `None` is an illegal transition.
#[test]
fn every_phase_and_event_has_exactly_the_tabled_outcome() {
    let s = server();
    let other = ServerId::new();
    let idle = Some(TunnelPhase::Idle);
    let connecting = Some(TunnelPhase::Connecting { server_id: s });
    let connected = Some(TunnelPhase::Connected { server_id: s });
    let recovering = Some(TunnelPhase::Recovering { server_id: s });
    let paused = Some(TunnelPhase::Paused { server_id: s });
    let stale = Some(TunnelPhase::Unhealthy {
        server_id: s,
        recovering: false,
    });
    let stale_recovering = Some(TunnelPhase::Unhealthy {
        server_id: s,
        recovering: true,
    });
    let other_connecting = Some(TunnelPhase::Connecting { server_id: other });
    // Connect(s), Connect(other), Handshake, PathLost, Exhausted, Pause, Resume,
    // ObservationLost, ObservationRestored, Disconnect
    let table = [
        [
            connecting,
            other_connecting,
            None,
            None,
            None,
            None,
            None,
            idle,
            idle,
            idle,
        ],
        [
            connecting,
            None,
            connected,
            connecting,
            paused,
            paused,
            None,
            stale_recovering,
            connecting,
            idle,
        ],
        [
            connected, None, connected, recovering, None, paused, None, stale, connected, idle,
        ],
        [
            recovering,
            None,
            connected,
            recovering,
            paused,
            paused,
            None,
            stale_recovering,
            recovering,
            idle,
        ],
        [
            connecting, None, None, paused, paused, paused, connecting, paused, paused, idle,
        ],
        [
            stale,
            None,
            connected,
            stale_recovering,
            paused,
            paused,
            None,
            stale,
            connected,
            idle,
        ],
        [
            stale_recovering,
            None,
            connected,
            stale_recovering,
            paused,
            paused,
            None,
            stale_recovering,
            recovering,
            idle,
        ],
    ];
    for (phase, row) in phases(s).into_iter().zip(table) {
        for (event, expected) in events(s, other).into_iter().zip(row) {
            assert_eq!(phase.next(event).ok(), expected, "{phase:?} on {event:?}");
        }
    }
}

#[test]
fn legacy_flags_round_trip_and_contradictions_have_no_phase() {
    let s = server();
    for phase in phases(s) {
        assert_eq!(TunnelPhase::from_legacy(&phase.legacy()), Some(phase));
        let mut status = disconnected();
        status.set_phase(phase);
        assert_eq!(status.phase(), Some(phase));
    }
    // Every flag combination either is exactly some phase's projection or has no phase.
    let mut legal = 0;
    for state in [
        ConnectionState::Disconnected,
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Degraded,
    ] {
        for server_id in [None, Some(s)] {
            for waiting_for_user in [false, true] {
                for recovery_in_progress in [false, true] {
                    let legacy = LegacyLifecycle {
                        state: state.clone(),
                        server_id,
                        waiting_for_user,
                        recovery_in_progress,
                    };
                    if let Some(phase) = TunnelPhase::from_legacy(&legacy) {
                        assert_eq!(phase.legacy(), legacy);
                        legal += 1;
                    }
                }
            }
        }
    }
    assert_eq!(legal, phases(s).len());
    // The contradictions the audit listed.
    for (state, server_id, waiting, recovery) in [
        (ConnectionState::Disconnected, None, true, false),
        (ConnectionState::Disconnected, None, false, true),
        (ConnectionState::Connected, Some(s), true, false),
        (ConnectionState::Connected, None, false, false),
    ] {
        let mut status = disconnected();
        status.state = state;
        status.server_id = server_id;
        status.waiting_for_user = waiting;
        status.recovery_in_progress = recovery;
        assert_eq!(status.phase(), None);
    }
}

#[test]
fn the_phase_is_an_additive_wire_field_older_readers_ignore() {
    let mut status = disconnected();
    status.set_phase(TunnelPhase::Paused {
        server_id: server(),
    });
    let wire = serde_json::to_value(&status).unwrap();
    assert_eq!(wire["phase"]["kind"], "paused");
    assert_eq!(wire["waiting_for_user"], true);
    assert_eq!(wire["state"], "degraded");
    // Every legacy field is still written exactly as before.
    let mut without_phase = wire.clone();
    without_phase.as_object_mut().unwrap().remove("phase");
    let legacy: LocalTunnelStatus = serde_json::from_value(without_phase.clone()).unwrap();
    assert_eq!(legacy, status);
    // Readers ignore the field, so a reader of this version accepts it too.
    let read: LocalTunnelStatus = serde_json::from_value(wire).unwrap();
    assert_eq!(read, status);
    // A contradictory snapshot is published without a phase rather than a guessed one.
    status.state = ConnectionState::Connected;
    assert!(
        serde_json::to_value(&status)
            .unwrap()
            .get("phase")
            .is_none()
    );
}

fn disconnected() -> LocalTunnelStatus {
    serde_json::from_value(serde_json::json!({
        "state": "disconnected",
        "interface_name": "sirinvpn0",
        "server_id": null,
        "rx_bytes": 0,
        "tx_bytes": 0,
        "ipv6_blocked": false
    }))
    .unwrap()
}
