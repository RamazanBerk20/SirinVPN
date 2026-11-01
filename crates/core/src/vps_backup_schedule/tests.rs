use super::*;
use crate::{LocalIdentity, read_encrypted_server_backup, write_encrypted_server_backup};
use serde_json::json;
use sirinvpn_protocol::{
    DEFAULT_MANAGEMENT_PORT, INTERFACE_NAME, SERVER_TUNNEL_ADDRESS, TUNNEL_CIDR,
};

const NOW: i64 = 1_793_491_200; // 2026-11-01T00:00:00Z

#[test]
fn file_names_sort_by_utc_time_and_only_match_one_server() {
    let id = ServerId::new();
    assert_eq!(utc_stamp(0), "19700101T000000Z");
    assert_eq!(utc_stamp(951_782_400), "20000229T000000Z");
    assert_eq!(utc_stamp(NOW + 43_199), "20261101T115959Z");
    assert_eq!(
        vps_backup_file_name(id, NOW),
        format!("sirinvpn-vps-{id}-20261101T000000Z.sirinvpn-server-backup")
    );
    let other = ServerId::new();
    let names = [
        vps_backup_file_name(id, NOW),
        vps_backup_file_name(id, NOW - DAY),
        vps_backup_file_name(id, NOW - 2 * DAY),
        vps_backup_file_name(other, NOW - 3 * DAY),
        format!("sirinvpn-vps-{id}-latest.sirinvpn-server-backup"),
        format!("sirinvpn-vps-{id}-20261101T000000Z.sirinvpn-server-backup.part"),
        "notes.txt".to_owned(),
    ];
    assert_eq!(
        expired_vps_backups(id, names.iter().map(String::as_str), 1),
        [names[1].as_str(), names[2].as_str()]
    );
    assert!(expired_vps_backups(id, names.iter().map(String::as_str), 3).is_empty());
}

#[test]
fn rotation_keeps_exactly_the_newest_n_of_this_server() {
    let folder = tempfile::tempdir().unwrap();
    let id = ServerId::new();
    let other = ServerId::new();
    for day in 0..7 {
        fs::write(
            folder
                .path()
                .join(vps_backup_file_name(id, NOW - day * DAY)),
            b"x",
        )
        .unwrap();
    }
    let foreign = vps_backup_file_name(other, NOW - 30 * DAY);
    fs::write(folder.path().join(&foreign), b"x").unwrap();
    fs::write(folder.path().join("notes.txt"), b"x").unwrap();
    // A matching directory or link is never followed or deleted.
    fs::create_dir(folder.path().join(vps_backup_file_name(id, NOW - 40 * DAY))).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        folder.path().join("notes.txt"),
        folder.path().join(vps_backup_file_name(id, NOW - 50 * DAY)),
    )
    .unwrap();

    assert_eq!(rotate_vps_backup_folder(folder.path(), id, 3).unwrap(), 4);
    let mut remaining: Vec<String> = fs::read_dir(folder.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| {
            name.starts_with(&format!("sirinvpn-vps-{id}-"))
                && fs::symlink_metadata(folder.path().join(name))
                    .unwrap()
                    .is_file()
        })
        .collect();
    remaining.sort();
    assert_eq!(
        remaining,
        (0..3)
            .rev()
            .map(|day| vps_backup_file_name(id, NOW - day * DAY))
            .collect::<Vec<_>>()
    );
    assert!(folder.path().join(foreign).exists());
    assert!(folder.path().join("notes.txt").exists());
    assert_eq!(rotate_vps_backup_folder(folder.path(), id, 3).unwrap(), 0);
}

#[test]
fn schedule_is_due_weekly_retries_failures_hourly_and_turns_stale() {
    let directory = tempfile::tempdir().unwrap();
    let store = VpsBackupScheduleStore::new(directory.path().join("vps-backup-schedules.json"));
    let id = ServerId::new();
    for (keep, interval) in [(0, 7), (31, 7), (4, 0), (4, 31)] {
        assert!(matches!(
            store.set(id, "/backups".into(), keep, interval, NOW),
            Err(VpsBackupScheduleError::InvalidSettings)
        ));
    }
    assert!(store.set(id, " ".into(), 4, 7, NOW).is_err());
    // Without a schedule nothing is recorded.
    store.record_success(id, NOW).unwrap();
    assert!(store.load().unwrap().is_empty());

    let schedule = store.set(id, "/backups".into(), 4, 7, NOW).unwrap();
    assert!(schedule.due(NOW) && !schedule.stale(NOW));
    assert!(schedule.stale(NOW + 8 * DAY + 1));

    store
        .record_failure(id, NOW, &"SSH failed. ".repeat(100))
        .unwrap();
    let failed = store.get(id).unwrap().unwrap();
    let failure = failed.last_failure.clone().unwrap();
    assert_eq!((failure.at, failure.message.len() <= 512), (NOW, true));
    assert!(!failed.due(NOW + VPS_BACKUP_RETRY_SECONDS - 1));
    assert!(failed.due(NOW + VPS_BACKUP_RETRY_SECONDS));

    store.record_success(id, NOW + DAY).unwrap();
    let succeeded = store.get(id).unwrap().unwrap();
    assert_eq!(succeeded.last_success, Some(NOW + DAY));
    assert_eq!(succeeded.last_failure, None);
    assert!(!succeeded.due(NOW + 8 * DAY - 1));
    assert!(succeeded.due(NOW + 8 * DAY));
    assert!(!succeeded.stale(NOW + 9 * DAY));
    assert!(succeeded.stale(NOW + 9 * DAY + 1));

    // Changing the folder keeps the status; forgetting removes it.
    let moved = store
        .set(id, "/elsewhere".into(), 2, 1, NOW + 2 * DAY)
        .unwrap();
    assert_eq!(
        (moved.enabled_at, moved.last_success),
        (NOW, Some(NOW + DAY))
    );
    let status = serde_json::to_value(moved.status(NOW + 2 * DAY)).unwrap();
    assert_eq!(status["folder"], "/elsewhere");
    assert_eq!(
        (status["due"].clone(), status["stale"].clone()),
        (json!(true), json!(false))
    );
    store.forget(id).unwrap();
    assert!(store.get(id).unwrap().is_none());

    fs::write(
        directory.path().join("vps-backup-schedules.json"),
        b"{\"schema_version\":2,\"schedules\":[]}",
    )
    .unwrap();
    assert!(matches!(
        store.load(),
        Err(VpsBackupScheduleError::InvalidData)
    ));
}

#[test]
fn a_scheduled_backup_restores_after_rotation() {
    let folder = tempfile::tempdir().unwrap();
    let password = "correct horse battery staple";
    let server = LocalIdentity::generate("Scheduled server").unwrap();
    let owner = LocalIdentity::generate("Scheduled owner").unwrap();
    let id = ServerId::new();
    let configuration = json!({
        "schema_version": 1,
        "server_name": "Scheduled VPS",
        "interface_name": INTERFACE_NAME,
        "tunnel_cidr": TUNNEL_CIDR,
        "server_tunnel_address": SERVER_TUNNEL_ADDRESS,
        "wireguard_port": 51_820,
        "management_port": DEFAULT_MANAGEMENT_PORT,
        "wireguard_public_key": server.public.wireguard_public_key,
        "owner_certificate_pem": owner.public.management_certificate_pem,
    });
    let snapshot = |generation: u64| {
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "server_id": id,
            "configuration_json": serde_json::to_string(&configuration).unwrap(),
            "wireguard_private_key": server.secret.wireguard_private_key,
            "transport_private_key": null,
            "management_certificate_pem": server.public.management_certificate_pem,
            "management_private_key_pem": server.secret.management_private_key_pem,
            "authorization_json": serde_json::to_string(&json!({
                "schema_version": 1,
                "server_id": id,
                "members": generation,
            })).unwrap(),
            "authorization_required": true,
        }))
        .unwrap()
    };
    for day in 0..3_u64 {
        let path = folder
            .path()
            .join(vps_backup_file_name(id, NOW + day as i64 * DAY));
        write_encrypted_server_backup(&path, &snapshot(day), password).unwrap();
        rotate_vps_backup_folder(folder.path(), id, 2).unwrap();
    }
    let mut names: Vec<_> = fs::read_dir(folder.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2);
    let restored = read_encrypted_server_backup(names.last().unwrap(), password).unwrap();
    assert_eq!(restored.snapshot(), snapshot(2));
    assert_eq!(restored.metadata().server_id, id);
    assert_eq!(restored.metadata().server_name, "Scheduled VPS");
    assert!(read_encrypted_server_backup(names.last().unwrap(), "wrong password long").is_err());
}
