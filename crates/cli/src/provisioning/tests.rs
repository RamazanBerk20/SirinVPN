use super::*;
use sirinvpn_installer::TransactionStep;

fn profile(name: &str) -> ServerProfile {
    ServerProfile {
        favorite: false,
        schema_version: 1,
        id: ServerId::new(),
        name: name.into(),
        endpoint: ServerEndpoint {
            host: "203.0.113.4".into(),
            wireguard_port: 51_820,
        },
        endpoint_generation: 0,
        pending_previous_endpoint: None,
        pending_previous_transports: None,
        endpoint_discovery_port: None,
        alternate_endpoint_hosts: Vec::new(),
        client_tunnel_address: "10.77.0.2".parse().unwrap(),
        server_tunnel_address: "10.77.0.1".parse().unwrap(),
        ipv6_tunnel_enabled: false,
        server_wireguard_public_key: "public".into(),
        pinned_server_certificate_pem: "certificate".into(),
        client_management_certificate_pem: "client-certificate".into(),
        identity_reference: "identity".into(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: None,
        device_id: None,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
        subnet_routes: Default::default(),
    }
}

fn resolved(
    state: RemoteTransactionState,
    committed: Option<ServerProfile>,
) -> ResolvedTransaction {
    ResolvedTransaction {
        entry: JournalEntry {
            schema_version: 1,
            operation: TransactionOperation::Install,
            nonce: "0".repeat(32),
            host: "203.0.113.4".into(),
            port: 22,
            host_key_sha256: "SHA256:pin".into(),
            step: TransactionStep::CommitSent,
            committed_profile: committed,
        },
        state,
    }
}

#[test]
fn a_lost_commit_reply_is_settled_by_what_the_vps_reports() {
    let kept = profile("kept");
    let committed = resolved(RemoteTransactionState::Committed, Some(kept.clone()));
    assert!(matches!(
        settle(Ok(Some(committed))),
        Settlement::Committed(found) if *found == kept
    ));
    let rolled_back = resolved(RemoteTransactionState::RolledBack, None);
    assert!(matches!(
        settle(Ok(Some(rolled_back))),
        Settlement::RolledBack
    ));
}

#[test]
fn anything_but_a_final_answer_keeps_the_keys() {
    for state in [
        RemoteTransactionState::Preparing,
        RemoteTransactionState::Armed,
        RemoteTransactionState::Unknown,
    ] {
        assert!(matches!(
            settle(Ok(Some(resolved(state, None)))),
            Settlement::Unknown(_)
        ));
    }
    // Committed with no profile to keep is not a reason to delete anything either.
    let without_profile = resolved(RemoteTransactionState::Committed, None);
    assert!(matches!(
        settle(Ok(Some(without_profile))),
        Settlement::Unknown(_)
    ));
    assert!(matches!(settle(Ok(None)), Settlement::Unknown(_)));
    let unreachable = InstallerError::PhaseFailed {
        phase: "connection",
        message: "timed out".into(),
    };
    let Settlement::Unknown(reason) = settle(Err(unreachable)) else {
        panic!("an unreachable VPS must stay unresolved")
    };
    assert!(reason.contains("timed out"));
    let message = unresolved_outcome(&reason).to_string();
    assert!(message.contains("sirinvpn server resolve"));
    assert!(message.contains("kept its keys"));
}

#[test]
fn a_confirmed_commit_is_saved_new_for_install_and_merged_for_repair() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    let mut committed = profile("Home");
    save_committed_profile(&paths, &committed, "203.0.113.4").unwrap();
    assert_eq!(paths.profile_store().load().unwrap().len(), 1);

    // A repair moved the endpoint; the local name and identity stay as saved.
    committed.endpoint.host = "198.51.100.7".into();
    committed.endpoint_generation = 3;
    committed.name = "Name on the VPS".into();
    committed.identity_reference = "other".into();
    let saved = save_committed_profile(&paths, &committed, "203.0.113.4").unwrap();
    assert_eq!(saved.endpoint.host, "198.51.100.7");
    assert_eq!(saved.endpoint_generation, 3);
    assert_eq!(saved.name, "Home");
    assert_eq!(saved.identity_reference, "identity");
    assert_eq!(paths.profile_store().load().unwrap().len(), 1);
}

#[test]
fn a_pending_hetzner_creation_offers_resume_or_delete_and_never_a_new_server() {
    assert_eq!(pending_choice("r\n", false), PendingChoice::Resume);
    assert_eq!(pending_choice(" Resume ", true), PendingChoice::Resume);
    assert_eq!(pending_choice("d", true), PendingChoice::Delete);
    // A server Hetzner may not have created cannot be deleted by ID yet.
    assert_eq!(pending_choice("d", false), PendingChoice::Stop);
    assert_eq!(pending_choice("", true), PendingChoice::Stop);
    assert_eq!(pending_choice("n", true), PendingChoice::Stop);
}

#[test]
fn a_failed_host_key_replacement_prints_its_own_text_with_the_replacement_fingerprint() {
    let error = HetznerError::HostKeyReplacement("replacement key SHA256:newkey is active".into());
    let note = host_key_note(&error, "SHA256:seed");
    assert!(note.contains("SHA256:newkey") && note.contains("SHA256:seed"));
    let note = host_key_note(&HetznerError::Timeout("start"), "SHA256:seed");
    assert!(note.contains("SHA256:seed") && !note.contains("replacement"));
}

#[test]
fn a_plan_prints_as_text_or_json_and_changes_nothing() {
    let plan = InstallPlan {
        operation: "install",
        host: "203.0.113.4".into(),
        nonce: "0".repeat(32),
        discovery: None,
        network_preflight: None,
        managed_paths: vec!["etc/sirinvpn".into()],
        steps: Vec::new(),
    };
    assert!(
        plan_output(&plan, false)
            .unwrap()
            .contains("Nothing was changed.")
    );
    let json: serde_json::Value = serde_json::from_str(&plan_output(&plan, true).unwrap()).unwrap();
    assert_eq!(json["operation"], "install");
}

#[test]
fn transaction_commands_report_an_empty_journal_without_contacting_a_vps() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    assert_eq!(
        transaction_journal(&paths).path(),
        directory.path().join("vps-transaction.json")
    );
    for subcommand in ["transaction-status", "resolve"] {
        let cli = Cli::try_parse_from(["sirinvpn", "server", subcommand]).unwrap();
        let Commands::Server { command } = cli.command else {
            panic!("wrong command")
        };
        match *command {
            ServerCommand::Resolve(arguments) => {
                resolve_transaction(&paths, arguments, false).unwrap()
            }
            ServerCommand::TransactionStatus(arguments) => {
                transaction_status(&paths, arguments, true).unwrap()
            }
            _ => panic!("wrong command"),
        }
    }
}

#[test]
fn the_resolve_target_is_the_interrupted_vps_with_its_original_pin() {
    let entry = resolved(RemoteTransactionState::Unknown, None).entry;
    let cli = Cli::try_parse_from(["sirinvpn", "server", "resolve", "--ssh-agent"]).unwrap();
    let Commands::Server { command } = cli.command else {
        panic!("wrong command")
    };
    let ServerCommand::Resolve(arguments) = *command else {
        panic!("wrong command")
    };
    let target = transaction_target(&entry, &arguments.login).unwrap();
    assert_eq!(
        (
            target.host.as_str(),
            target.port,
            target.expected_host_key_sha256.as_deref()
        ),
        ("203.0.113.4", 22, Some("SHA256:pin"))
    );
}

#[test]
fn rolling_back_keeps_a_key_that_a_saved_profile_uses() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    paths.profile_store().upsert(profile("Home")).unwrap();
    record_pending_secret(&paths, "203.0.113.4", "identity").unwrap();
    discard_marked_secret(&paths, "203.0.113.4").unwrap();
    assert!(!pending_secret_marker(&paths, "203.0.113.4").exists());
}

#[test]
fn the_pending_secret_marker_is_owner_only_and_goes_when_the_vps_commits() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    // A leftover wider file must not lend its mode to the new marker.
    std::fs::write(pending_secret_marker(&paths, "203.0.113.4"), "old").unwrap();
    record_pending_secret(&paths, "203.0.113.4", "identity").unwrap();
    assert_eq!(
        std::fs::read_to_string(pending_secret_marker(&paths, "203.0.113.4")).unwrap(),
        "identity"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(pending_secret_marker(&paths, "203.0.113.4"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    save_committed_profile(&paths, &profile("Home"), "203.0.113.4").unwrap();
    assert!(!pending_secret_marker(&paths, "203.0.113.4").exists());
}

/// A journal stuck at `CommitSent` for `host`, written as the previous version did.
fn stuck_journal(paths: &ClientPaths, file: &str, host: &str) {
    let mut entry = resolved(RemoteTransactionState::Unknown, Some(profile("Planned"))).entry;
    entry.host = host.into();
    std::fs::write(
        paths.configuration_directory.join(file),
        serde_json::to_vec(&entry).unwrap(),
    )
    .unwrap();
}

fn server_file(paths: &ClientPaths, host: &str) -> String {
    let path = transaction_journal(paths).server_path(host);
    path.file_name().unwrap().to_str().unwrap().to_owned()
}

fn resolve_arguments(arguments: &[&str]) -> ResolveArguments {
    let cli =
        Cli::try_parse_from(["sirinvpn", "server", "resolve"].iter().chain(arguments)).unwrap();
    let Commands::Server { command } = cli.command else {
        panic!("wrong command")
    };
    let ServerCommand::Resolve(arguments) = *command else {
        panic!("wrong command")
    };
    arguments
}

#[test]
fn one_stuck_transaction_does_not_block_another_server() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    // The previous version's single journal and pending-secret marker.
    stuck_journal(&paths, "vps-transaction.json", "198.51.100.9");
    std::fs::write(directory.path().join("vps-transaction-secret"), "planned").unwrap();
    let journal = transaction_journal(&paths);
    let mut other = profile("Other");
    other.endpoint.host = "203.0.113.4".into();
    assert!(!journal.blocks_server(&other).unwrap());
    let mut stuck = profile("Stuck");
    stuck.endpoint.host = "198.51.100.9".into();
    assert!(journal.blocks_server(&stuck).unwrap());
    // Migrated with its marker; a second stuck server makes `--server` necessary.
    assert!(!directory.path().join("vps-transaction.json").exists());
    assert!(pending_secret_marker(&paths, "198.51.100.9").exists());
    assert!(selected_transaction(&paths, None).unwrap().is_some());
    stuck_journal(&paths, &server_file(&paths, "192.0.2.1"), "192.0.2.1");
    assert!(selected_transaction(&paths, None).is_err());
    let chosen = selected_transaction(&paths, Some("192.0.2.1"))
        .unwrap()
        .unwrap();
    assert_eq!(chosen.host, "192.0.2.1");
}

#[test]
fn abandoning_needs_a_server_and_drops_only_its_record_while_keeping_every_key() {
    assert!(
        Cli::try_parse_from(["sirinvpn", "server", "resolve", "--abandon"]).is_err(),
        "the server must be named"
    );
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    let journal = transaction_journal(&paths);
    for host in ["198.51.100.9", "192.0.2.1"] {
        stuck_journal(&paths, &server_file(&paths, host), host);
        record_pending_secret(&paths, host, "planned").unwrap();
    }
    let key = directory.path().join("owner-key");
    std::fs::write(&key, "unchanged").unwrap();
    let before = std::fs::read_dir(directory.path()).unwrap().count();

    resolve_transaction(
        &paths,
        resolve_arguments(&["--abandon", "198.51.100.9"]),
        true,
    )
    .unwrap();
    assert!(journal.read_server("198.51.100.9").unwrap().is_none());
    assert!(!pending_secret_marker(&paths, "198.51.100.9").exists());
    assert!(journal.read_server("192.0.2.1").unwrap().is_some());
    assert!(pending_secret_marker(&paths, "192.0.2.1").exists());
    // Exactly the journal and its marker went; nothing else in the directory.
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        before - 2
    );
    assert!(key.exists());
    // Abandoning again finds nothing and still succeeds.
    resolve_transaction(
        &paths,
        resolve_arguments(&["--abandon", "198.51.100.9"]),
        false,
    )
    .unwrap();
}

#[test]
fn a_new_install_is_refused_before_its_key_or_marker_is_written() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ClientPaths::under(directory.path().to_owned());
    stuck_journal(&paths, "vps-transaction.json", "198.51.100.9");
    std::fs::write(directory.path().join("vps-transaction-secret"), "planned").unwrap();
    let identity = sirinvpn_installer::new_identity_for_server("New").unwrap();
    let mut request = sirinvpn_installer::default_install_request(
        "New".into(),
        SshTarget {
            host: "198.51.100.9".into(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:pin".into()),
        },
        "/nonexistent/sirinvpn-server".into(),
        &identity,
    );
    request.identity_reference = "new-identity".into();
    let error = install_new_server(&paths, request, &identity.secret, false).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<InstallerError>(),
        Some(InstallerError::TransactionUnresolved { .. })
    ));
    assert_eq!(
        std::fs::read_to_string(pending_secret_marker(&paths, "198.51.100.9")).unwrap(),
        "planned"
    );
    assert!(paths.secret_store().get("new-identity").is_err());
}
