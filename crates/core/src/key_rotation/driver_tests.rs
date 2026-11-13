//! The driver against an in-memory VPS that can lose the commit response, keep the old
//! identity or become unreachable; every uncertain-commit path ends recoverable.
use super::remote::RotationCapabilities;
use super::tests::{MemorySecretStore, profile};
use super::*;
use sirinvpn_protocol::{
    KeyRotationCommitResponse, KeyRotationPrepareResponse, MemberId, ServerEndpoint, ServerRole,
};
use std::sync::{Arc, Mutex};

struct Vps {
    /// The management certificate the VPS currently accepts for this device.
    device_certificate: String,
    pending: Option<(KeyRotationId, String)>,
    reachable: bool,
    /// Whether a commit reaches the VPS at all.
    commit_applies: bool,
    /// The VPS commits, but this device never sees the response.
    commit_response_lost: bool,
    /// The network goes down right after a commit.
    unreachable_after_commit: bool,
    /// Endpoint host and certificate of every tunnel the driver brought up.
    connections: Vec<(String, String)>,
}

#[derive(Clone)]
struct FakeRemote {
    vps: Arc<Mutex<Vps>>,
    server_id: ServerId,
    device_id: DeviceId,
    member_id: MemberId,
}

struct FakeClient {
    remote: FakeRemote,
    certificate: String,
}

impl RotationRemote for FakeRemote {
    type Client = FakeClient;
    fn client(
        &self,
        profile: &ServerProfile,
        _secret: &SecretIdentity,
    ) -> Result<FakeClient, ManagementError> {
        Ok(FakeClient {
            remote: self.clone(),
            certificate: profile.client_management_certificate_pem.clone(),
        })
    }
}

impl FakeClient {
    fn vps(&self) -> std::sync::MutexGuard<'_, Vps> {
        self.remote.vps.lock().unwrap()
    }
    fn reach(&self) -> Result<(), ManagementError> {
        if self.vps().reachable {
            Ok(())
        } else {
            Err(ManagementError::ConnectionFailed)
        }
    }
}

impl RotationClient for FakeClient {
    async fn capabilities(&self) -> Result<RotationCapabilities, ManagementError> {
        self.reach()?;
        Ok(RotationCapabilities {
            key_rotation: true,
            preshared_keys: true,
        })
    }

    async fn status(&self) -> Result<ServerStatus, ManagementError> {
        self.reach()?;
        // A removed peer or untrusted certificate never completes the handshake.
        if self.vps().device_certificate != self.certificate {
            return Err(ManagementError::ConnectionFailed);
        }
        Ok(serde_json::from_value(serde_json::json!({
            "api_version": "1",
            "server_name": "Rotation test",
            "connection_state": "connected",
            "interface_up": true,
            "dns_healthy": true,
            "transport": "direct_udp",
            "peer_count": 1,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "uptime_seconds": 1,
            "caller_role": "owner",
            "caller_device_id": self.remote.device_id,
            "caller_identity_fingerprint":
                management_certificate_fingerprint(&self.certificate).unwrap(),
        }))
        .unwrap())
    }

    async fn prepare(
        &self,
        request: &KeyRotationPrepareRequest,
    ) -> Result<KeyRotationPrepareResponse, ManagementError> {
        self.reach()?;
        let mut vps = self.vps();
        if vps.device_certificate != self.certificate {
            return Err(ManagementError::ConnectionFailed);
        }
        vps.pending = Some((
            request.rotation_id,
            request.new_management_certificate_pem.clone(),
        ));
        Ok(KeyRotationPrepareResponse {
            rotation_id: request.rotation_id,
            expires_at_unix: u64::MAX,
        })
    }

    async fn commit(
        &self,
        rotation_id: KeyRotationId,
    ) -> Result<KeyRotationCommitResponse, ManagementError> {
        self.reach()?;
        let mut vps = self.vps();
        // Only the transition identity (new certificate, old peer) may commit.
        if vps.pending != Some((rotation_id, self.certificate.clone())) {
            return Err(ManagementError::ConnectionFailed);
        }
        if !vps.commit_applies {
            return Err(ManagementError::ConnectionFailed);
        }
        vps.device_certificate = self.certificate.clone();
        vps.pending = None;
        if vps.unreachable_after_commit {
            vps.reachable = false;
        }
        if vps.commit_response_lost || !vps.reachable {
            return Err(ManagementError::ConnectionFailed);
        }
        Ok(KeyRotationCommitResponse {
            server_id: self.remote.server_id,
            device_id: self.remote.device_id,
            identity_fingerprint: management_certificate_fingerprint(&self.certificate).unwrap(),
        })
    }

    async fn refresh_membership_ids(
        &self,
        profile: &mut ServerProfile,
        device: DeviceId,
    ) -> Result<(), ManagementError> {
        self.reach()?;
        profile.member_id.get_or_insert(self.remote.member_id);
        profile.device_id = Some(device);
        Ok(())
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    paths: ClientPaths,
    secrets: MemorySecretStore,
    remote: FakeRemote,
    original: ServerProfile,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().join("client"));
        let identity = LocalIdentity::generate("Original").unwrap();
        let server_id = ServerId::new();
        let original = profile(&identity, server_id);
        paths.profile_store().insert(original.clone()).unwrap();
        let secrets = MemorySecretStore::default();
        secrets
            .put(&original.identity_reference, &identity.secret)
            .unwrap();
        let remote = FakeRemote {
            vps: Arc::new(Mutex::new(Vps {
                device_certificate: original.client_management_certificate_pem.clone(),
                pending: None,
                reachable: true,
                commit_applies: true,
                commit_response_lost: false,
                unreachable_after_commit: false,
                connections: Vec::new(),
            })),
            server_id,
            device_id: DeviceId::new(),
            member_id: MemberId::new(),
        };
        Self {
            _directory: directory,
            paths,
            secrets,
            remote,
            original,
        }
    }

    fn vps(&self) -> std::sync::MutexGuard<'_, Vps> {
        self.remote.vps.lock().unwrap()
    }

    async fn run(&self) -> Result<KeyRotationResult, KeyRotationError> {
        let vps = self.remote.vps.clone();
        drive(
            &self.paths,
            &self.secrets,
            &self.remote,
            self.original.id,
            RotationConnectionMode {
                persistent_protection: false,
                transport: TransportKind::DirectUdp,
                transport_fallback_enabled: false,
                connection_policy: None,
            },
            || Ok(()),
            move |profile: &ServerProfile, _: &SecretIdentity, _, _, _, _| {
                let mut vps = vps.lock().unwrap();
                vps.connections.push((
                    profile.endpoint.host.clone(),
                    profile.client_management_certificate_pem.clone(),
                ));
                if vps.reachable {
                    Ok(())
                } else {
                    Err("unreachable".to_owned())
                }
            },
        )
        .await
    }

    fn saved(&self) -> ServerProfile {
        self.paths.profile_store().load().unwrap().remove(0)
    }

    fn journal(&self) -> Option<RotationJournal> {
        RotationJournalStore::new(&self.paths)
            .load(self.original.id)
            .unwrap()
    }

    fn assert_rotated(&self, result: &KeyRotationResult) {
        let saved = self.saved();
        let journal_gone = self.journal().is_none();
        assert!(journal_gone);
        assert_eq!(result.device_id, self.remote.device_id);
        assert_eq!(saved.device_id, Some(self.remote.device_id));
        assert_eq!(saved.member_id, Some(self.remote.member_id));
        assert_eq!(
            saved.client_management_certificate_pem,
            self.vps().device_certificate
        );
        assert_ne!(saved.identity_reference, self.original.identity_reference);
        assert!(self.secrets.get(&saved.identity_reference).is_ok());
        assert!(matches!(
            self.secrets.get(&self.original.identity_reference),
            Err(SecretStoreError::NotFound)
        ));
    }

    fn assert_original_identity_saved(&self) {
        let saved = self.saved();
        assert_eq!(saved.identity_reference, self.original.identity_reference);
        assert_eq!(
            saved.client_management_certificate_pem,
            self.original.client_management_certificate_pem
        );
        assert!(self.secrets.get(&saved.identity_reference).is_ok());
    }
}

#[tokio::test]
async fn a_lost_commit_response_is_resolved_by_the_new_identity() {
    let fixture = Fixture::new();
    fixture.vps().commit_response_lost = true;
    let result = fixture.run().await.unwrap();
    assert!(!result.resumed);
    fixture.assert_rotated(&result);
}

#[tokio::test]
async fn a_vps_that_kept_the_old_identity_restores_it_and_the_commit_is_retried() {
    let fixture = Fixture::new();
    fixture.vps().commit_applies = false;
    let error = fixture.run().await.unwrap_err();
    assert!(
        matches!(&error, KeyRotationError::RecoveryRequired(message) if message.contains("kept the old identity")),
        "{error}"
    );
    assert_eq!(fixture.journal().unwrap().phase, RotationPhase::Prepared);
    fixture.assert_original_identity_saved();

    fixture.vps().commit_applies = true;
    let result = fixture.run().await.unwrap();
    assert!(result.resumed);
    fixture.assert_rotated(&result);
}

#[tokio::test]
async fn an_uncertain_commit_keeps_both_identities_until_one_is_confirmed() {
    let fixture = Fixture::new();
    fixture.vps().unreachable_after_commit = true;
    let error = fixture.run().await.unwrap_err();
    assert!(
        matches!(&error, KeyRotationError::RecoveryRequired(message) if message.contains("uncertain")),
        "{error}"
    );
    let journal = fixture.journal().unwrap();
    assert_eq!(journal.phase, RotationPhase::Committing);
    assert!(
        fixture
            .secrets
            .get(&journal.final_identity_reference)
            .is_ok()
    );
    assert!(
        fixture
            .secrets
            .get(&journal.transition_identity_reference)
            .is_ok()
    );
    fixture.assert_original_identity_saved();

    // Still offline: resuming changes nothing and loses nothing.
    assert!(matches!(
        fixture.run().await,
        Err(KeyRotationError::RecoveryRequired(_))
    ));
    assert_eq!(fixture.journal().unwrap().phase, RotationPhase::Committing);
    fixture.assert_original_identity_saved();

    fixture.vps().reachable = true;
    let result = fixture.run().await.unwrap();
    assert!(result.resumed);
    fixture.assert_rotated(&result);
}

#[tokio::test]
async fn a_resumed_rotation_keeps_renames_and_checkpoints_applied_meanwhile() {
    let fixture = Fixture::new();
    fixture.vps().unreachable_after_commit = true;
    assert!(fixture.run().await.is_err());

    // While the rotation waits, the user renames the server and a signed checkpoint
    // moves it to a new VPS address.
    let store = fixture.paths.profile_store();
    store
        .update_presentation(fixture.original.id, Some("Renamed".into()), Some(true))
        .unwrap();
    store
        .update(fixture.original.id, |current| {
            current.endpoint = ServerEndpoint {
                host: "198.51.100.7".into(),
                wireguard_port: 51_820,
            };
            current.endpoint_generation = 4;
            Ok(())
        })
        .unwrap();

    fixture.vps().reachable = true;
    let result = fixture.run().await.unwrap();
    fixture.assert_rotated(&result);
    let saved = fixture.saved();
    assert_eq!((saved.name.as_str(), saved.favorite), ("Renamed", true));
    assert_eq!(saved.endpoint.host, "198.51.100.7");
    assert_eq!(saved.endpoint_generation, 4);
    assert_eq!(saved.role, ServerRole::Owner);
    // The resumed connection went to the new address, not the staged one.
    let vps = fixture.vps();
    let (host, certificate) = vps.connections.last().unwrap();
    assert_eq!(host, "198.51.100.7");
    assert_eq!(certificate, &saved.client_management_certificate_pem);
}

#[tokio::test]
async fn a_second_runner_cannot_resume_while_another_holds_the_server() {
    let fixture = Fixture::new();
    let _running = ServerOperationLock::acquire(&fixture.paths, fixture.original.id).unwrap();
    let error = rotate_current_device_keys_with_policy(
        &fixture.paths,
        fixture.original.id,
        false,
        TransportKind::DirectUdp,
        false,
        None,
        || panic!("the second runner must not touch the tunnel"),
        |_: &ServerProfile, _: &SecretIdentity, _, _, _, _| {
            panic!("the second runner must not touch the tunnel")
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        KeyRotationError::Operation(ServerOperationError::AlreadyInProgress)
    ));
    assert_eq!(fixture.saved(), fixture.original);
}
