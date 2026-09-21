//! Bounded, isolated measurements using the existing server lease protocol.
use crate::{
    commands::{preferences, profile},
    jni_bridge::Runtime,
    tunnel::carrier,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sirinvpn_core::{LocalIdentity, ManagementClient, SecretStore};
use sirinvpn_protocol::*;
use sirinvpn_transport::TransportEngine;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn measure(runtime: &Runtime, generation: i64) -> Result<Value> {
    let _exclusive = runtime
        .measurement
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Measurement already running"))?;
    let original = runtime.platform.quality_state(generation)?;
    ensure!(
        original["automatic_transport"] == true,
        "Manual transport selected"
    );
    let p = profile(
        runtime,
        original["server_id"]
            .as_str()
            .context("Missing active profile")?,
    )?;
    let secret = runtime.paths.secret_store().get(&p.identity_reference)?;
    let client = ManagementClient::new(&p, &secret)?;
    let mut status = TransportQualityStatus {
        sample: runtime
            .platform
            .measure(&json!({"mode":"active"}), generation)?,
        selection: QualitySelection::Observing,
        candidates_checked: 1,
        ..Default::default()
    };
    if status.sample.is_none() {
        status.selection = QualitySelection::IcmpUnavailable;
        return Ok(serde_json::to_value(status)?);
    }
    if !client.configuration().await?.isolated_measurement_enabled {
        return Ok(serde_json::to_value(status)?);
    }
    status.isolated_measurement_supported = true;
    // Existing identity generation supplies a random ephemeral WireGuard key;
    // nothing from this identity or the samples is written to persistent storage.
    let probe = LocalIdentity::generate("Ephemeral path measurement")?;
    let lease = client
        .measurement_lease(probe.public.wireguard_public_key.clone())
        .await?;
    let outcome=async {
        let IpAddr::V4(address)=p.client_tunnel_address else {anyhow::bail!("Invalid measurement address")};
        ensure!(lease.public_key==probe.public.wireguard_public_key && lease.client_address==Ipv4Addr::new(10,77,1,address.octets()[3]) && lease.expires_at_unix>now()+10 && lease.expires_at_unix<=now()+125,"Invalid measurement lease");
        let preferences=runtime.platform.connection_preferences(&p.id.to_string())?.map(serde_json::from_value).transpose()?
            .unwrap_or(preferences(runtime).get(p.id).map_err(anyhow::Error::msg)?);
        let active:TransportKind=serde_json::from_value(original["transport"].clone())?;
        let plan=TransportEngine.automatic_plan(&p,preferences.network_profile,None)?;
        let private=zeroize::Zeroizing::new(hex::encode(STANDARD.decode(&probe.secret.wireguard_private_key)?));
        let public=hex::encode(STANDARD.decode(&p.server_wireguard_public_key)?);
        let unchanged=||->Result<()> {
            let current=runtime.platform.quality_state(generation)?;
            ensure!(current["endpoint"]==original["endpoint"] && current["transport"]==original["transport"] && now()+8<lease.expires_at_unix,"Measurement superseded");Ok(())
        };
        let mut winner=None;
        for selection in plan.iter().filter(|s|s.kind!=active && u64::from(s.mtu)>=original["mtu"].as_u64().unwrap_or(u64::MAX)) {
            unchanged()?;
            let transport=match carrier(runtime,selection,&probe.secret.wireguard_private_key,Some(SocketAddr::from(([127,0,0,1],51826))),4).await {Ok(value)=>value,Err(_)=>continue};
            status.candidates_checked+=1;
            let config=json!({"source":lease.client_address,"destination":p.server_tunnel_address,"transport":selection.kind,
                "wireguard":format!("private_key={}\nreplace_peers=true\npublic_key={}\nendpoint={}\nallowed_ip={}/32\npersistent_keepalive_interval=25\n",*private,public,transport.endpoint,p.server_tunnel_address)});
            let mut measured=None;
            for comparison in 0..2 {
                unchanged()?;
                let baseline=runtime.platform.measure(&json!({"mode":"active"}),generation)?;
                let candidate=runtime.platform.measure(&config,generation)?;
                if let (Some(base),Some(sample))=(baseline,candidate) && sample.improves(base) {
                    if comparison==1 {measured=Some(sample)}
                } else {break}
            }
            transport.shutdown().await;
            if let Some(sample)=measured && winner.is_none_or(|best:TransportQualitySample|sample.improves(best)) {winner=Some(sample)}
        }
        if let Some(winner)=winner {
            unchanged()?;
            let selection=plan.iter().find(|s|s.kind==winner.transport).context("Missing candidate")?;
            let mut next=carrier(runtime,selection,&secret.wireguard_private_key,Some(SocketAddr::from(([127,0,0,1],51825))),4).await?;
            unchanged()?;
            let candidate=next.endpoint.to_string();
            runtime.platform.handoff(&json!({"previous":original["endpoint"],"endpoint":candidate,"maximum_mtu":selection.mtu}),generation)?;
            let confirmed=runtime.platform.measure(&json!({"mode":"active"}),generation).ok().flatten()
                .filter(|sample|sample.stable());
            if let Some(mut sample)=confirmed {
                // No JNI calls while holding the relay lock: Controller.stopEngine
                // takes the locks in the opposite order. The native generation
                // prevents a late optimizer from replacing a newer session's task.
                let mut relay=runtime.relay.lock().map_err(|_|anyhow::anyhow!("Transport unavailable"))?;
                ensure!(runtime.generation.load(Ordering::SeqCst)==generation,"Connection changed");
                if let Some(previous)=relay.take() {previous.abort();}
                *relay=next.task.take();
                sample.transport=winner.transport;status.sample=Some(sample);
                status.selection=QualitySelection::Selected;status.last_switch_reason=Some(TransportSwitchReason::QualityImprovement);
                let mut result=serde_json::to_value(&status)?;result["selected_transport"]=serde_json::to_value(winner.transport)?;return Ok(result)
            }
            runtime.platform.handoff(&json!({"previous":candidate,"endpoint":original["endpoint"],"maximum_mtu":original["mtu"]}),generation)?;
            status.last_switch_reason=Some(TransportSwitchReason::Rollback);
        }
        Ok(serde_json::to_value(&status)?)
    }.await;
    let _ = runtime
        .platform
        .quality_result(outcome.as_ref().ok(), generation);
    // The server also expires this lease after two minutes if connectivity or
    // the process is lost before this best-effort cleanup can reach it.
    let _ = client.remove_measurement_lease(lease.public_key).await;
    outcome
}
