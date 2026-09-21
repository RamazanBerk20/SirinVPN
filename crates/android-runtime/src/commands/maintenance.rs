use super::*;
use sha2::{Digest, Sha256};
use sirinvpn_installer::*;
use zeroize::Zeroizing;

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

pub async fn dispatch(
    runtime: &Runtime,
    command: &str,
    input: &Value,
    generation: i64,
) -> Result<Value> {
    runtime.platform.current(generation)?;
    match command {
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
            let checkpoint = reference(
                &format!(
                    "{host}:{}:{}",
                    input["ssh_port"],
                    text(input, "host_key_sha256")?
                ),
                "provision",
            );
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
            let identity_reference = server_id.to_string();
            let request = InstallRequest {
                server_id,
                server_name: name.to_owned(),
                target: target(runtime, input, host)?,
                server_binary: payload(runtime),
                identity: identity.public,
                identity_reference: identity_reference.clone(),
                transport: serde_json::from_value(
                    input.get("transport").cloned().unwrap_or(json!({})),
                )?,
                dns_upstream: serde_json::from_value(input["dns_upstream"].clone())?,
                private_dns_records: serde_json::from_value(input["private_dns_records"].clone())?,
                replace_existing_installation: input["replace_existing_installation"]
                    .as_bool()
                    .unwrap_or(false),
            };
            runtime
                .paths
                .secret_store()
                .put(&identity_reference, &identity.secret)?;
            let outcome = Provisioner::install(request)?;
            // Keep the identity if commit fails: retry/recovery must not orphan the installed owner.
            runtime
                .paths
                .profile_store()
                .upsert(outcome.profile.clone())?;
            runtime.platform.delete_blob(&checkpoint)?;
            return Ok(
                json!({"network_preflight":outcome.network_preflight,"profile":outcome.profile,"events":outcome.events,"dns_upstream":outcome.dns_upstream,"private_dns_records":outcome.private_dns_records}),
            );
        }
        _ => {}
    }
    let p = profile(runtime, text(input, "server_id")?)?;
    ensure!(
        p.role == ServerRole::Owner,
        "Only the Owner may perform VPS maintenance"
    );
    ensure!(
        !sirinvpn_core::has_pending_key_rotation(&runtime.paths, p.id)?,
        "Complete key rotation first"
    );
    let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
    let identity = secret.public_identity(&p.client_management_certificate_pem)?;
    let host = input["host"].as_str().unwrap_or(&p.endpoint.host);
    let ssh = target(runtime, input, host)?;
    match command {
        "uninstall_server" => {
            confirmed(input)?;
            runtime.platform.require_idle()?;
            Provisioner::uninstall(UninstallRequest {
                server_id: p.id,
                target: ssh,
                owner_certificate_pem: p.client_management_certificate_pem,
            })?;
            runtime.paths.secret_store().delete(&p.identity_reference)?;
            runtime.paths.profile_store().remove(p.id)?;
            Ok(Value::Null)
        }
        "repair_server" => {
            confirmed(input)?;
            runtime.platform.require_idle()?;
            let mut p = p;
            let fingerprint =
                sirinvpn_core::management_identity_fingerprint(&p.pinned_server_certificate_pem)?;
            let result = Provisioner::repair(RepairRequest {
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
                transport: input
                    .get("transport")
                    .filter(|v| !v.is_null())
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()?,
            })?;
            p.endpoint = result.endpoint;
            p.endpoint_generation = result.endpoint_generation;
            p.alternate_endpoint_hosts = result.alternate_endpoint_hosts;
            p.endpoint_discovery_port = result.endpoint_discovery_port;
            p.pending_previous_endpoint = None;
            p.pending_previous_transports = None;
            p.ipv6_tunnel_enabled = result.ipv6_tunnel_enabled;
            p.obfuscated_udp = result.obfuscated_udp;
            p.tcp_fallback = result.tcp_fallback;
            p.tls_like = result.tls_like;
            runtime.paths.profile_store().upsert(p)?;
            Ok(
                json!({"network_preflight":result.network_preflight,"events":result.events,"artifact_sha256":result.artifact_sha256,
                "server_identity_fingerprint":fingerprint,"dns_upstream":result.dns_upstream,"private_dns_records":result.private_dns_records}),
            )
        }
        "export_vps_backup" | "restore_vps_backup" => {
            confirmed(input)?;
            let staging = tempfile::Builder::new()
                .prefix("encrypted-transfer-")
                .tempdir_in(&runtime.paths.configuration_directory)?;
            let path = staging.path().join("transfer.sirvps");
            let uri = text(input, "path")?;
            let password = Zeroizing::new(text(input, "backup_password")?.to_owned());
            let outcome = if command == "export_vps_backup" {
                let result = Provisioner::export_server_backup(ServerBackupRequest {
                    profile: p,
                    target: ssh,
                    server_binary: payload(runtime),
                    identity,
                    destination: path.clone(),
                    password,
                });
                match result {
                    Ok(result) => {
                        runtime
                            .platform
                            .write_document(uri, &std::fs::read(&path)?)?;
                        encode(result)
                    }
                    Err(error) => Err(error.into()),
                }
            } else {
                runtime.platform.require_idle()?;
                let bytes = runtime.platform.document(uri)?;
                sirinvpn_platform::files::atomic_write(&path, &bytes, true)?;
                let result = Provisioner::restore_server_backup(ServerRestoreRequest {
                    profile: p,
                    target: ssh,
                    server_binary: payload(runtime),
                    identity,
                    source: path.clone(),
                    password,
                    replace_existing_installation: input["replace_existing"]
                        .as_bool()
                        .unwrap_or(false),
                })?;
                runtime
                    .paths
                    .profile_store()
                    .upsert(result.profile.clone())?;
                encode(result)
            };
            let _ = std::fs::remove_file(path);
            outcome
        }
        _ => bail!("Unknown maintenance command"),
    }
}
