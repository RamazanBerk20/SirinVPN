use super::*;
use sha2::{Digest, Sha256};
use sirinvpn_core::{VpsBackupSchedule, expired_vps_backups, unix_now, vps_backup_file_name};
use sirinvpn_installer::{hetzner::*, *};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

static HETZNER_WAIT_CANCEL: AtomicBool = AtomicBool::new(false);

pub fn accepts(command: &str) -> bool {
    matches!(
        command,
        "probe_host_key"
            | "inspect_ssh_host"
            | "trust_ssh_host"
            | "get_ssh_login"
            | "save_ssh_login"
            | "forget_ssh_login"
            | "inspect_server_network"
            | "provision_server"
            | "repair_server"
            | "export_server_backup"
            | "import_server_backup"
            | "export_vps_backup"
            | "restore_vps_backup"
            | "uninstall_server"
            | "hetzner_catalog"
            | "create_hetzner_server"
            | "wait_hetzner_server"
            | "cancel_hetzner_wait"
            | "delete_hetzner_server"
            | "find_hetzner_server"
            | "install_transaction_status"
            | "resolve_install_transaction"
            | "abandon_install_transaction"
            | "plan_server_operation"
            | "vps_backup_schedules"
            | "set_vps_backup_schedule"
            | "disable_vps_backup_schedule"
            | "run_scheduled_vps_backup"
    )
}
fn reference(host: &str, kind: &str) -> String {
    format!(
        "{kind}-{}",
        hex::encode(Sha256::digest(host.trim().to_lowercase().as_bytes()))
    )
}
pub(super) fn target(runtime: &Runtime, input: &Value, host: &str) -> Result<SshTarget> {
    validate_host(host)?;
    let saved;
    let input = if input["authentication"] == "saved" {
        saved = serde_json::from_slice::<Value>(
            &runtime
                .platform
                .blob(&reference(host, "ssh"))?
                .context("Saved login unavailable")?,
        )?;
        ensure!(
            saved["host_key_sha256"] == input["host_key_sha256"],
            "Saved login belongs to a different SSH identity"
        );
        &saved
    } else {
        input
    };
    let authentication = match text(input, "authentication")? {
        "password" => {
            SshAuthentication::Password(Zeroizing::new(text(input, "password")?.to_owned()))
        }
        "private_key" => {
            let pem = if let Some(pem) = input["private_key_pem"].as_str() {
                Zeroizing::new(pem.to_owned())
            } else {
                Zeroizing::new(String::from_utf8(
                    runtime
                        .platform
                        .document(text(input, "private_key_path")?)?
                        .to_vec(),
                )?)
            };
            ensure!(pem.len() <= 65536, "Private key is too large");
            SshAuthentication::PrivateKeyMemory {
                private_key_pem: pem,
                passphrase: input["private_key_passphrase"]
                    .as_str()
                    .map(|s| Zeroizing::new(s.to_owned())),
            }
        }
        _ => bail!("Select password or an imported SSH key"),
    };
    Ok(SshTarget {
        host: host.to_owned(),
        port: serde_json::from_value(input["ssh_port"].clone())?,
        username: text(input, "username")?.to_owned(),
        authentication,
        sudo_password: input["sudo_password"]
            .as_str()
            .map(|s| Zeroizing::new(s.to_owned())),
        expected_host_key_sha256: Some(text(input, "host_key_sha256")?.to_owned()),
    })
}
fn payload(runtime: &Runtime) -> ServerBinarySource {
    let root = runtime
        .paths
        .configuration_directory
        .join("server-payloads");
    ServerBinarySource::by_architecture(
        root.join("x86_64/sirinvpn-server"),
        root.join("aarch64/sirinvpn-server"),
    )
}
fn metadata(input: &Value) -> Value {
    json!({"username":input["username"],"ssh_port":input["ssh_port"],"authentication":input["authentication"],"private_key_path":if input["authentication"] == "private_key" {json!("Imported key")} else {Value::Null}})
}
fn trust_reference(host: &str, port: u16) -> String {
    reference(
        &format!("{}:{port}", host.trim_end_matches('.')),
        "sshtrust",
    )
}

fn backup_password_reference(id: ServerId) -> String {
    reference(&id.to_string(), "vpsbackup")
}
/// Removing a server also removes its backup schedule and saved password.
pub(super) fn forget_vps_backup_schedule(runtime: &Runtime, id: ServerId) -> Result<()> {
    runtime.paths.vps_backup_schedule_store().forget(id)?;
    runtime.platform.delete_blob(&backup_password_reference(id))
}
fn owner(runtime: &Runtime, input: &Value) -> Result<ServerProfile> {
    let id = input
        .get("server_id")
        .or_else(|| input.get("serverId"))
        .and_then(Value::as_str)
        .context("Missing or invalid field")?;
    let p = profile(runtime, id)?;
    ensure!(
        p.role == ServerRole::Owner,
        "Only the Owner may perform VPS maintenance"
    );
    Ok(p)
}
/// One journal file per VPS host, beside the path the CLI and desktop use.
pub(super) fn journal(runtime: &Runtime) -> TransactionJournal {
    TransactionJournal::new(
        runtime
            .paths
            .configuration_directory
            .join("vps-transaction.json"),
    )
}
/// Every Owner maintenance operation asks the shared rules before it starts.
pub(super) fn ready(
    runtime: &Runtime,
    p: &ServerProfile,
    operation: OwnerMaintenance,
) -> Result<()> {
    let policy = preferences(runtime)
        .get(p.id)
        .map_err(anyhow::Error::msg)?
        .policy;
    let state = OwnerDeviceState {
        role: p.role,
        disconnected: runtime.platform.require_idle().is_ok(),
        kill_switch_enabled: policy.kill_switch,
        auto_reconnect_enabled: policy.automatic_reconnect,
        pending_key_rotation: sirinvpn_core::has_pending_key_rotation(&runtime.paths, p.id)?,
        unresolved_transaction: journal(runtime).blocks_server(p)?,
    };
    owner_maintenance_ready(operation, &state)
        .map_err(|blockers| rules::maintenance_blocked(&blockers).into())
}
fn provision_checkpoint(host: &str, port: impl std::fmt::Display, pin: &str) -> String {
    reference(&format!("{host}:{port}:{pin}"), "provision")
}
fn install_request(
    runtime: &Runtime,
    input: &Value,
    server_id: ServerId,
    identity: sirinvpn_core::PublicIdentity,
) -> Result<InstallRequest> {
    Ok(InstallRequest {
        server_id,
        server_name: text(input, "name")?.to_owned(),
        target: target(runtime, input, text(input, "host")?)?,
        server_binary: payload(runtime),
        identity,
        identity_reference: server_id.to_string(),
        transport: serde_json::from_value(input.get("transport").cloned().unwrap_or(json!({})))?,
        dns_upstream: serde_json::from_value(input["dns_upstream"].clone())?,
        private_dns_records: serde_json::from_value(input["private_dns_records"].clone())?,
        nat64_prefix: input["nat64_prefix"]
            .as_str()
            .map(sirinvpn_installer::parse_nat64_prefix)
            .transpose()?,
        replace_existing_installation: input["replace_existing_installation"]
            .as_bool()
            .unwrap_or(false),
        enable_security_updates: false,
    })
}
/// After a lost commit reply: the profile the VPS confirmed, or the error to show.
/// Nothing is deleted unless the VPS confirms the rollback.
fn settle_lost_reply(runtime: &Runtime, target: &SshTarget) -> Result<ServerProfile> {
    match rules::settle(Provisioner::resolve_transaction(target, &journal(runtime))) {
        rules::Settlement::Committed(profile) => Ok(*profile),
        rules::Settlement::RolledBack => Err(rules::rolled_back().into()),
        rules::Settlement::Unknown(reason) => {
            Err(rules::outcome_unknown(&target.host, &reason).into())
        }
    }
}
/// Saves a profile the VPS confirmed: merged into the saved one, else a new install.
fn save_committed(runtime: &Runtime, committed: &ServerProfile) -> Result<ServerProfile> {
    let store = runtime.paths.profile_store();
    match store.update(committed.id, |current| {
        rules::merge_committed(current, committed);
        Ok(current.clone())
    }) {
        Err(sirinvpn_core::ProfileStoreError::NotFound) => {
            store.upsert(committed.clone())?;
            Ok(committed.clone())
        }
        saved => Ok(saved?),
    }
}
/// A dry run goes back to the UI: never with a secret used for it.
fn plan_output(plan: InstallPlan, ssh: &SshTarget, input: &Value) -> Result<Value> {
    let value = encode(plan)?;
    let mut secrets: Vec<&str> = input["backup_password"].as_str().into_iter().collect();
    secrets.extend(ssh.sudo_password.as_deref().map(String::as_str));
    match &ssh.authentication {
        SshAuthentication::Password(password) => secrets.push(password),
        SshAuthentication::PrivateKeyMemory {
            private_key_pem,
            passphrase,
        } => {
            secrets.push(private_key_pem);
            secrets.extend(passphrase.as_deref().map(String::as_str));
        }
        _ => {}
    }
    rules::ensure_no_secrets(&value, &secrets)?;
    Ok(value)
}
fn staging(runtime: &Runtime) -> Result<(tempfile::TempDir, std::path::PathBuf)> {
    let staging = tempfile::Builder::new()
        .prefix("encrypted-transfer-")
        .tempdir_in(&runtime.paths.configuration_directory)?;
    let path = staging.path().join("transfer.sirvps");
    Ok((staging, path))
}
fn hetzner_key(runtime: &Runtime, name: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(String::from_utf8(
        runtime
            .platform
            .blob(&reference(name, "hetzner"))?
            .context("The new server’s SSH key is missing")?
            .to_vec(),
    )?))
}
/// Drops a Hetzner creation record and its login key (installed or deleted).
fn forget_hetzner(runtime: &Runtime, name: &str) -> Result<()> {
    HetznerProvision::forget(&runtime.paths.configuration_directory, name)?;
    runtime.platform.delete_blob(&reference(name, "hetzner"))
}
/// SirinVPN now runs on `host`: a Hetzner creation that ended there is finished.
fn forget_installed_hetzner(runtime: &Runtime, host: &str) {
    let pending =
        HetznerProvision::pending(&runtime.paths.configuration_directory).unwrap_or_default();
    for provision in pending {
        if matches!(&provision.phase, HetznerPhase::Ready { ready, .. } if ready.ipv4.to_string() == host)
        {
            let _ = forget_hetzner(runtime, &provision.name);
        }
    }
}
fn schedule_status(runtime: &Runtime, id: ServerId) -> Result<Value> {
    encode(
        runtime
            .paths
            .vps_backup_schedule_store()
            .get(id)?
            .context("Turn on scheduled backups for this VPS first")?
            .status(unix_now()),
    )
}
/// Writes into the Owner's document tree and keeps the newest `keep` there.
fn scheduled_backup(
    runtime: &Runtime,
    p: &ServerProfile,
    schedule: &VpsBackupSchedule,
) -> Result<()> {
    let saved = runtime
        .platform
        .blob(&reference(&p.endpoint.host, "ssh"))?
        .context("Scheduled backups need this VPS’s SSH login. Back up the VPS once with Remember login on.")?;
    let pin = serde_json::from_slice::<Value>(&saved)?["host_key_sha256"].clone();
    let ssh = target(
        runtime,
        &json!({"authentication":"saved","host_key_sha256":pin}),
        &p.endpoint.host,
    )?;
    let password = runtime
        .platform
        .blob(&backup_password_reference(p.id))?
        .context("The backup password is no longer saved. Enter it again.")?;
    let password = Zeroizing::new(String::from_utf8(password.to_vec())?);
    let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
    let staging = tempfile::Builder::new()
        .prefix("encrypted-transfer-")
        .tempdir_in(&runtime.paths.configuration_directory)?;
    let path = staging.path().join("transfer.sirvps");
    Provisioner::export_server_backup(ServerBackupRequest {
        profile: p.clone(),
        target: ssh,
        server_binary: payload(runtime),
        identity: secret.public_identity(&p.client_management_certificate_pem)?,
        destination: path.clone(),
        password,
    })?;
    let written = std::fs::read(&path)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| {
            runtime.platform.write_tree_document(
                &schedule.folder,
                &vps_backup_file_name(p.id, unix_now()),
                &bytes,
            )
        });
    let _ = std::fs::remove_file(&path);
    written?;
    runtime
        .paths
        .vps_backup_schedule_store()
        .record_success(p.id, unix_now())?;
    let names = runtime.platform.tree_names(&schedule.folder)?;
    for name in expired_vps_backups(p.id, names.iter().map(String::as_str), schedule.keep) {
        runtime
            .platform
            .delete_tree_document(&schedule.folder, name)?;
    }
    Ok(())
}

pub async fn dispatch(
    runtime: &Runtime,
    command: &str,
    input: &Value,
    generation: i64,
) -> Result<Value> {
    runtime.platform.current(generation)?;
    match command {
        "vps_backup_schedules" => {
            let profiles = runtime.paths.profile_store().load()?;
            let now = unix_now();
            return encode(
                runtime
                    .paths
                    .vps_backup_schedule_store()
                    .load()?
                    .into_iter()
                    .filter(|schedule| profiles.iter().any(|p| p.id == schedule.server_id))
                    .map(|schedule| schedule.status(now))
                    .collect::<Vec<_>>(),
            );
        }
        "set_vps_backup_schedule" => {
            let p = owner(runtime, input)?;
            let folder = text(input, "folder")?;
            ensure!(
                folder.starts_with("content://"),
                "Choose a folder for the VPS backups"
            );
            let reference = backup_password_reference(p.id);
            match input["backup_password"].as_str() {
                Some(password) => {
                    sirinvpn_core::validate_server_backup_password(password)?;
                    runtime.platform.put_blob(&reference, password.as_bytes())?;
                }
                None => {
                    runtime
                        .platform
                        .blob(&reference)?
                        .context("Enter a backup password")?;
                }
            }
            runtime.paths.vps_backup_schedule_store().set(
                p.id,
                folder.to_owned(),
                serde_json::from_value(input["keep"].clone())?,
                serde_json::from_value(input["interval_days"].clone())?,
                unix_now(),
            )?;
            return schedule_status(runtime, p.id);
        }
        "disable_vps_backup_schedule" => {
            forget_vps_backup_schedule(runtime, owner(runtime, input)?.id)?;
            return Ok(Value::Null);
        }
        "run_scheduled_vps_backup" => {
            let p = owner(runtime, input)?;
            let store = runtime.paths.vps_backup_schedule_store();
            let schedule = store
                .get(p.id)?
                .context("Turn on scheduled backups for this VPS first")?;
            // Not a failure: like a manual backup, the run waits until the shared rules allow it.
            ready(runtime, &p, OwnerMaintenance::Backup)?;
            if let Err(error) = scheduled_backup(runtime, &p, &schedule) {
                store.record_failure(p.id, unix_now(), &error.to_string())?;
            }
            return schedule_status(runtime, p.id);
        }
        "get_ssh_login" => {
            return runtime
                .platform
                .blob(&reference(text(input, "host")?, "ssh"))?
                .map(|bytes| Ok(metadata(&serde_json::from_slice(&bytes)?)))
                .unwrap_or(Ok(Value::Null));
        }
        "forget_ssh_login" => {
            runtime
                .platform
                .delete_blob(&reference(text(input, "host")?, "ssh"))?;
            return Ok(Value::Null);
        }
        "save_ssh_login" => {
            let host = text(input, "host")?;
            let ssh = target(runtime, input, host)?;
            Provisioner::verify_ssh_login(&ssh)?;
            let mut saved = input.clone();
            if let SshAuthentication::PrivateKeyMemory {
                private_key_pem, ..
            } = &ssh.authentication
            {
                saved["private_key_pem"] = json!(private_key_pem.as_str());
                saved["private_key_path"] = Value::Null;
            }
            runtime.platform.put_blob(
                &reference(host, "ssh"),
                &Zeroizing::new(serde_json::to_vec(&saved)?),
            )?;
            return Ok(metadata(input));
        }
        "probe_host_key" | "inspect_ssh_host" => {
            let host = text(input, "host")?;
            let port: u16 = serde_json::from_value(input["port"].clone())?;
            let target = SshTarget {
                host: host.to_owned(),
                port,
                username: "unused".into(),
                authentication: SshAuthentication::Agent,
                sudo_password: None,
                expected_host_key_sha256: None,
            };
            let fingerprint = Provisioner::host_key_fingerprint(&target)?;
            if command == "probe_host_key" {
                return encode(fingerprint);
            }
            let saved = runtime.platform.blob(&trust_reference(host, port))?;
            let status = match saved {
                None => "unknown",
                Some(value) if value.as_slice() == fingerprint.as_bytes() => "trusted",
                Some(_) => "changed",
            };
            return Ok(json!({"fingerprint":fingerprint,"status":status}));
        }
        "trust_ssh_host" => {
            // Input is flattened by dispatch: the reviewed fingerprint remains separate.
            let host = text(input, "host")?;
            let port: u16 = serde_json::from_value(input["port"].clone())?;
            let pin = text(input, "fingerprint")?;
            ensure!(
                pin.starts_with("SHA256:") && pin.len() == 50,
                "Invalid SSH fingerprint"
            );
            runtime
                .platform
                .put_blob(&trust_reference(host, port), pin.as_bytes())?;
            return Ok(Value::Null);
        }
        "inspect_server_network" => {
            let ssh = &input["ssh"];
            let host = text(ssh, "host")?;
            return encode(Provisioner::inspect_server(
                &target(runtime, ssh, host)?,
                &serde_json::from_value(input["transport"].clone())?,
                input
                    .get("endpoint_discovery_port")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()?,
            )?);
        }
        "export_server_backup" => {
            confirmed(input)?;
            let p = profile(runtime, text(input, "server_id")?)?;
            ensure!(
                !sirinvpn_core::has_pending_key_rotation(&runtime.paths, p.id)?,
                "Complete key rotation before exporting this identity"
            );
            let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
            let bytes =
                sirinvpn_core::encrypt_device_backup(&p, &secret, None, text(input, "password")?)?;
            runtime
                .platform
                .write_document(text(input, "path")?, &bytes)?;
            return Ok(Value::Null);
        }
        "import_server_backup" => {
            let bytes = runtime.platform.document(text(input, "path")?)?;
            // Only encrypted bytes are staged, retaining the shared transactional importer.
            let staging = tempfile::Builder::new()
                .prefix("encrypted-transfer-")
                .tempdir_in(&runtime.paths.configuration_directory)?;
            let path = staging.path().join("incoming.sirinbackup");
            sirinvpn_platform::files::atomic_write(&path, &bytes, true)?;
            let outcome = runtime
                .paths
                .import_device_backup(&path, text(input, "password")?);
            let _ = std::fs::remove_file(&path);
            return encode(outcome?);
        }
        "provision_server" => {
            let name = text(input, "name")?;
            let host = text(input, "host")?;
            // One encrypted checkpoint per explicitly requested target. Retrying
            // after process loss must reuse the installed Owner's identity.
            let checkpoint =
                provision_checkpoint(host, &input["ssh_port"], text(input, "host_key_sha256")?);
            let saved = runtime.platform.blob(&checkpoint)?;
            let document = if let Some(bytes) = saved {
                serde_json::from_slice::<Value>(&bytes)?
            } else {
                let identity = new_identity_for_server(name)?;
                let value = json!({"server_id":ServerId::new(),"name":name,"public":identity.public,"secret":identity.secret,
                    "replace":input["replace_existing_installation"]});
                runtime
                    .platform
                    .put_blob(&checkpoint, &Zeroizing::new(serde_json::to_vec(&value)?))?;
                value
            };
            ensure!(
                document["name"] == name
                    && document["replace"] == input["replace_existing_installation"],
                "Resume the same provision request before changing its ownership decision"
            );
            let identity = sirinvpn_core::LocalIdentity {
                public: serde_json::from_value(document["public"].clone())?,
                secret: serde_json::from_value(document["secret"].clone())?,
            };
            let server_id: ServerId = serde_json::from_value(document["server_id"].clone())?;
            let request = install_request(runtime, input, server_id, identity.public)?;
            let pinned = request.target.clone();
            // Refused before the key is stored: an unresolved change on this host comes first.
            if journal(runtime).read_server(&pinned.host)?.is_some() {
                return Err(InstallerError::TransactionUnresolved {
                    host: pinned.host.clone(),
                }
                .into());
            }
            let requested_dns = (
                request.dns_upstream.clone(),
                request.private_dns_records.clone(),
            );
            runtime
                .paths
                .secret_store()
                .put(&request.identity_reference, &identity.secret)?;
            // Keep the identity if commit fails: retry/recovery must not orphan the installed owner.
            let (profile, output) = match Provisioner::install_with_journal(
                request,
                &journal(runtime),
            ) {
                Ok(outcome) => (
                    outcome.profile.clone(),
                    json!({"network_preflight":outcome.network_preflight,"profile":outcome.profile,"events":outcome.events,"dns_upstream":outcome.dns_upstream,"private_dns_records":outcome.private_dns_records}),
                ),
                // The install may be live: the identity and checkpoint stay until the VPS answers.
                Err(InstallerError::CommitUncertain { .. }) => {
                    let profile = settle_lost_reply(runtime, &pinned)?;
                    let output = json!({"profile":profile,"events":[],"dns_upstream":requested_dns.0,
                        "private_dns_records":requested_dns.1,"resolved_after_lost_reply":true});
                    (profile, output)
                }
                Err(error) => return Err(error.into()),
            };
            runtime.paths.profile_store().upsert(profile)?;
            runtime.platform.delete_blob(&checkpoint)?;
            forget_installed_hetzner(runtime, host);
            return Ok(output);
        }
        "abandon_install_transaction" => {
            // Forgets this host's record without asking the VPS: it may have committed
            // or rolled back. Every key and saved server is kept.
            let host = text(input, "host")?;
            let journal = journal(runtime);
            let entry = journal.read_server(host).ok().flatten();
            if !journal.abandon(host)? {
                return Ok(Value::Null);
            }
            return Ok(
                json!({"host":host,"transaction":entry.as_ref().map(|e| &e.nonce),
                "operation":entry.as_ref().map(|e| e.operation),"state":"abandoned","keys_kept":true}),
            );
        }
        "install_transaction_status" | "resolve_install_transaction" => {
            let journal = journal(runtime);
            // `host` picks one server's transaction; without it, the first one.
            let entry = match input["host"].as_str() {
                Some(host) => journal.read_server(host)?,
                None => journal.read()?,
            };
            let Some(entry) = entry else {
                return Ok(Value::Null);
            };
            let mut summary = json!({"transaction":entry.nonce,"host":entry.host,"port":entry.port,
                "operation":entry.operation,"step":entry.step,
                "server_id":entry.committed_profile.as_ref().map(|p| p.id),"state":null});
            if command == "install_transaction_status" && input["authentication"].is_null() {
                return Ok(summary);
            }
            // The journal names the VPS and its pin; the login is given or saved.
            let mut login = input.as_object().cloned().unwrap_or_default();
            login.entry("authentication").or_insert(json!("saved"));
            login.insert("ssh_port".into(), json!(entry.port));
            login.insert("host_key_sha256".into(), json!(entry.host_key_sha256));
            let pinned = target(runtime, &Value::Object(login), &entry.host)?;
            if command == "install_transaction_status" {
                summary["state"] = json!(Provisioner::transaction_status(
                    &pinned,
                    entry.operation,
                    &entry.nonce
                )?);
                return Ok(summary);
            }
            match rules::settle(Provisioner::resolve_transaction(&pinned, &journal)) {
                rules::Settlement::Committed(committed) => {
                    summary["profile"] = encode(save_committed(runtime, &committed)?)?;
                    summary["state"] = json!("committed");
                    runtime.platform.delete_blob(&provision_checkpoint(
                        &entry.host,
                        entry.port,
                        &entry.host_key_sha256,
                    ))?;
                    forget_installed_hetzner(runtime, &entry.host);
                }
                rules::Settlement::RolledBack => summary["state"] = json!("rolled_back"),
                rules::Settlement::Unknown(reason) => {
                    return Err(rules::outcome_unknown(&entry.host, &reason).into());
                }
            }
            return Ok(summary);
        }
        "plan_server_operation" if input["operation"] == "install" => {
            let identity = new_identity_for_server(text(input, "name")?)?;
            let request = install_request(runtime, input, ServerId::new(), identity.public)?;
            let pinned = request.target.clone();
            return plan_output(Provisioner::plan_install(request)?, &pinned, input);
        }
        "hetzner_catalog" => {
            return encode(
                HetznerClient::new(text(input, "apiToken")?)?
                    .catalog(payload(runtime).supports("aarch64"))
                    .await?,
            );
        }
        "create_hetzner_server" => {
            let client = HetznerClient::new(text(input, "apiToken")?)?;
            let request: HetznerServerRequest = serde_json::from_value(input["request"].clone())?;
            let directory = &runtime.paths.configuration_directory;
            // Never a second server while an earlier creation is unfinished.
            if let Some(pending) = HetznerProvision::pending(directory)?.into_iter().next() {
                return Err(rules::CommandError::new(
                    "hetzner_provision_pending",
                    format!(
                        "The server {} was not finished. Resume or delete it before creating another.",
                        pending.name
                    ),
                    json!({"name": pending.name}),
                )
                .into());
            }
            let prepared = PreparedServer::generate();
            // Saved first, so the key outlives an interrupted creation.
            let key = reference(&prepared.name, "hetzner");
            runtime.platform.put_blob(
                &key,
                &Zeroizing::new(prepared.login_private_key().as_bytes().to_vec()),
            )?;
            // The record keeps the pre-seeded host key, so an uncertain create stays resumable.
            let mut provision = HetznerProvision::requested(&prepared);
            if let Err(error) = provision.save(directory) {
                let _ = runtime.platform.delete_blob(&key);
                return Err(error.into());
            }
            return match client
                .create_server(&prepared, &request, payload(runtime).supports("aarch64"))
                .await
            {
                Ok(server) => {
                    // Unsaved, the record stays Requested and resuming finds the server by name.
                    let _ = provision.advance(
                        directory,
                        HetznerPhase::Created {
                            server_id: server.id,
                        },
                    );
                    Ok(json!({"server": server, "private_key_path": null}))
                }
                Err(error @ HetznerError::Uncertain(_)) => Err(rules::CommandError::new(
                    "hetzner_create_uncertain",
                    error.to_string(),
                    json!({"name": prepared.name, "server": prepared.name}),
                )
                .into()),
                Err(error) => {
                    let _ = forget_hetzner(runtime, &prepared.name);
                    Err(error.into())
                }
            };
        }
        "find_hetzner_server" => {
            let client = HetznerClient::new(text(input, "apiToken")?)?;
            let directory = &runtime.paths.configuration_directory;
            let Some(mut provision) = HetznerProvision::load(directory, text(input, "name")?)?
            else {
                return Ok(Value::Null);
            };
            if provision.server_id().is_none() {
                // Already cancelled, so `resume` only looks the name up and records the server.
                let lookup_only = AtomicBool::new(true);
                let key = hetzner_key(runtime, &provision.name)?;
                match client
                    .resume(directory, &mut provision, key, &lookup_only)
                    .await
                {
                    Ok(_) | Err(HetznerError::Cancelled) => {}
                    // `resume` dropped the record: Hetzner has no server with this name.
                    Err(HetznerError::InvalidChoice(_)) => {
                        let _ = forget_hetzner(runtime, &provision.name);
                        return Ok(Value::Null);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(
                json!({"server": {"id": provision.server_id(), "name": provision.name,
                "host_key_sha256": provision.pre_seeded_host_key_sha256}, "private_key_path": null}),
            );
        }
        "wait_hetzner_server" => {
            let client = HetznerClient::new(text(input, "apiToken")?)?;
            let server: HetznerServer = serde_json::from_value(input["server"].clone())?;
            let directory = &runtime.paths.configuration_directory;
            let mut provision = HetznerProvision::load(directory, &server.name)?
                .filter(|provision| provision.server_id().is_none_or(|id| id == server.id))
                .context("The new server’s creation record is missing")?;
            let pem = hetzner_key(runtime, &server.name)?;
            HETZNER_WAIT_CANCEL.store(false, Ordering::SeqCst);
            let ready = match client
                .resume(directory, &mut provision, pem.clone(), &HETZNER_WAIT_CANCEL)
                .await
            {
                Ok(ready) => ready,
                // Its own text names the replacement key the server may present now.
                Err(error @ HetznerError::HostKeyReplacement(_)) => {
                    return Err(rules::CommandError::new(
                        "hetzner_host_key_replacement",
                        format!(
                            "{error}. The pre-seeded host key was {}.",
                            provision.pre_seeded_host_key_sha256
                        ),
                        json!({"name": provision.name}),
                    )
                    .into());
                }
                Err(error) => return Err(error.into()),
            };
            // Saved like an imported key: the install and later repairs use this login.
            let host = ready.ipv4.to_string();
            let login = Zeroizing::new(serde_json::to_vec(&json!({
                "host": host, "ssh_port": 22, "username": "root", "authentication": "private_key",
                "private_key_pem": pem.as_str(), "host_key_sha256": ready.host_key_sha256,
            }))?);
            runtime
                .platform
                .put_blob(&reference(&host, "ssh"), &login)?;
            runtime.platform.put_blob(
                &trust_reference(&host, 22),
                ready.host_key_sha256.as_bytes(),
            )?;
            // The record and key stay until SirinVPN is installed there or the server is deleted.
            return encode(ready);
        }
        "cancel_hetzner_wait" => {
            HETZNER_WAIT_CANCEL.store(true, Ordering::SeqCst);
            return Ok(Value::Null);
        }
        "delete_hetzner_server" => {
            let server: HetznerServer = serde_json::from_value(input["server"].clone())?;
            HetznerClient::new(text(input, "apiToken")?)?
                .delete_server(server.id)
                .await?;
            forget_hetzner(runtime, &server.name)?;
            return Ok(Value::Null);
        }
        _ => {}
    }
    // Owner maintenance on a saved profile; `plan_server_operation` dry-runs the same request.
    let plan = command == "plan_server_operation";
    let requested = if plan {
        text(input, "operation")?
    } else {
        command
    };
    let operation = match (plan, requested) {
        (false, "uninstall_server") | (true, "uninstall") => OwnerMaintenance::Uninstall,
        (false, "repair_server") | (true, "repair") => OwnerMaintenance::Repair,
        (false, "export_vps_backup") => OwnerMaintenance::Backup,
        (false, "restore_vps_backup") | (true, "restore") => OwnerMaintenance::Restore,
        _ => bail!("Unknown maintenance command"),
    };
    let p = profile(runtime, text(input, "server_id")?)?;
    if plan {
        ensure!(
            p.role == ServerRole::Owner,
            "Only the Owner may perform VPS maintenance"
        );
    } else {
        confirmed(input)?;
        ready(runtime, &p, operation)?;
    }
    let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
    let identity = secret.public_identity(&p.client_management_certificate_pem)?;
    let host = input["host"].as_str().unwrap_or(&p.endpoint.host);
    let ssh = target(runtime, input, host)?;
    let pinned = ssh.clone();
    match operation {
        OwnerMaintenance::Uninstall => {
            let request = UninstallRequest {
                server_id: p.id,
                target: ssh,
                owner_certificate_pem: p.client_management_certificate_pem.clone(),
            };
            if plan {
                return plan_output(Provisioner::plan_uninstall(request)?, &pinned, input);
            }
            // Journaled like install, repair and restore, so an interruption can be resolved.
            match Provisioner::uninstall_with_journal(request, &journal(runtime)) {
                Ok(()) => {}
                // Removed here only once the VPS confirms; an uninstall commits no profile.
                Err(InstallerError::CommitUncertain { .. }) => {
                    let resolved = Provisioner::resolve_transaction(&pinned, &journal(runtime));
                    if !matches!(&resolved, Ok(Some(done)) if done.state == RemoteTransactionState::Committed)
                    {
                        return Err(match rules::settle(resolved) {
                            rules::Settlement::RolledBack => rules::rolled_back(),
                            rules::Settlement::Unknown(reason) => {
                                rules::outcome_unknown(&pinned.host, &reason)
                            }
                            rules::Settlement::Committed(_) => {
                                rules::outcome_unknown(&pinned.host, "unexpected state")
                            }
                        }
                        .into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
            runtime.paths.secret_store().delete(&p.identity_reference)?;
            runtime.paths.profile_store().remove(p.id)?;
            let _ = forget_vps_backup_schedule(runtime, p.id);
            Ok(Value::Null)
        }
        OwnerMaintenance::Repair => {
            let fingerprint =
                sirinvpn_core::management_identity_fingerprint(&p.pinned_server_certificate_pem)?;
            let request = RepairRequest {
                profile: p.clone(),
                target: ssh,
                server_binary: payload(runtime),
                identity,
                dns_upstream: input
                    .get("dns_upstream")
                    .filter(|v| !v.is_null())
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()?,
                private_dns_records: input
                    .get("private_dns_records")
                    .filter(|v| !v.is_null())
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()?,
                // Omitted keeps the VPS's NAT64 choice; `null` turns NAT64 off.
                nat64_prefix: input
                    .get("nat64_prefix")
                    .map(|v| {
                        serde_json::from_value::<Option<String>>(v.clone())?
                            .as_deref()
                            .map(sirinvpn_installer::parse_nat64_prefix)
                            .transpose()
                            .map_err(anyhow::Error::from)
                    })
                    .transpose()?,
                transport: input
                    .get("transport")
                    .filter(|v| !v.is_null())
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()?,
                enable_security_updates: input["enable_security_updates"] == true,
            };
            if plan {
                return plan_output(Provisioner::plan_repair(request)?, &pinned, input);
            }
            match Provisioner::repair_with_journal(request, &journal(runtime)) {
                Ok(result) => {
                    // Owns the endpoint and transport fields the repair reinstalled.
                    runtime.paths.profile_store().update(p.id, |current| {
                        *current = result.updated_profile(current);
                        Ok(())
                    })?;
                    Ok(
                        json!({"network_preflight":result.network_preflight,"events":result.events,"artifact_sha256":result.artifact_sha256,
                        "server_identity_fingerprint":fingerprint,"dns_upstream":result.dns_upstream,"private_dns_records":result.private_dns_records}),
                    )
                }
                Err(InstallerError::CommitUncertain { .. }) => {
                    save_committed(runtime, &settle_lost_reply(runtime, &pinned)?)?;
                    Ok(
                        json!({"events":[],"server_identity_fingerprint":fingerprint,"dns_upstream":input["dns_upstream"],
                        "private_dns_records":input["private_dns_records"],"resolved_after_lost_reply":true}),
                    )
                }
                Err(error) => Err(error.into()),
            }
        }
        OwnerMaintenance::Backup => {
            let id = p.id;
            let uri = text(input, "path")?;
            let password = Zeroizing::new(text(input, "backup_password")?.to_owned());
            let (_staging, path) = staging(runtime)?;
            let result = Provisioner::export_server_backup(ServerBackupRequest {
                profile: p,
                target: ssh,
                server_binary: payload(runtime),
                identity,
                destination: path.clone(),
                password,
            })?;
            runtime
                .platform
                .write_document(uri, &std::fs::read(&path)?)?;
            let _ = runtime
                .paths
                .vps_backup_schedule_store()
                .record_success(id, unix_now());
            encode(result)
        }
        OwnerMaintenance::Restore => {
            let uri = text(input, "path")?;
            let password = Zeroizing::new(text(input, "backup_password")?.to_owned());
            let (_staging, path) = staging(runtime)?;
            sirinvpn_platform::files::atomic_write(&path, &runtime.platform.document(uri)?, true)?;
            let request = ServerRestoreRequest {
                profile: p.clone(),
                target: ssh,
                server_binary: payload(runtime),
                identity,
                source: path,
                password,
                replace_existing_installation: input["replace_existing"].as_bool().unwrap_or(false),
            };
            if plan {
                return plan_output(
                    Provisioner::plan_restore_server_backup(request)?,
                    &pinned,
                    input,
                );
            }
            match Provisioner::restore_server_backup_with_journal(request, &journal(runtime)) {
                Ok(result) => {
                    // Owns the server side the backup restored; see `merge_committed`.
                    let saved = runtime.paths.profile_store().update(p.id, |current| {
                        rules::merge_committed(current, &result.profile);
                        Ok(current.clone())
                    })?;
                    let mut output = encode(result)?;
                    output["profile"] = encode(saved)?;
                    Ok(output)
                }
                Err(InstallerError::CommitUncertain { .. }) => {
                    let profile = save_committed(runtime, &settle_lost_reply(runtime, &pinned)?)?;
                    Ok(json!({"events":[],"profile":profile,"resolved_after_lost_reply":true}))
                }
                Err(error) => Err(error.into()),
            }
        }
        _ => bail!("Unknown maintenance command"),
    }
}
