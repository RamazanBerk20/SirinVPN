//! Read-only, current host counters. No samples, timestamps, or device activity are stored.
use super::*;

async fn bounded_output(program: &str, arguments: &[&str]) -> Option<String> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env("LC_ALL", "C")
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(1), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

pub(super) async fn root_disk_usage() -> Option<(u64, u64)> {
    let output = bounded_output("stat", &["--file-system", "--format=%b %f %S", "--", "/"]).await?;
    parse_disk_usage(&output)
}

fn parse_disk_usage(output: &str) -> Option<(u64, u64)> {
    let mut fields = output.split_whitespace();
    let total = fields.next()?.parse::<u64>().ok()?;
    let free = fields.next()?.parse::<u64>().ok()?;
    let block_size = fields.next()?.parse::<u64>().ok()?;
    if fields.next().is_some() || total == 0 || block_size == 0 {
        return None;
    }
    let used = total.checked_sub(free)?.checked_mul(block_size)?;
    Some((used, total.checked_mul(block_size)?))
}

pub(super) fn packet_counter(interface: &str, counter: &str) -> Option<u64> {
    fs::read_to_string(
        Path::new("/sys/class/net")
            .join(interface)
            .join("statistics")
            .join(counter),
    )
    .ok()?
    .trim()
    .parse()
    .ok()
}

pub(super) async fn recent_peer_activity(interface: &str) -> Option<HashMap<String, bool>> {
    // Request only public peer keys and handshake times; never use `wg ... dump`,
    // which also returns private keys and endpoint addresses.
    let output = bounded_output("wg", &["show", interface, "latest-handshakes"]).await?;
    parse_peer_activity(&output, unix_time())
}

fn parse_peer_activity(output: &str, now: u64) -> Option<HashMap<String, bool>> {
    let mut activity = HashMap::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let key = fields.next()?;
        validate_wireguard_public_key(key).ok()?;
        let timestamp = fields.next()?.parse::<u64>().ok()?;
        if fields.next().is_some() || activity.contains_key(key) {
            return None;
        }
        // Clock corrections must not make an old or future timestamp look active.
        if let Some(age) = now.checked_sub(timestamp) {
            activity.insert(key.to_owned(), timestamp != 0 && age <= 180);
        }
    }
    Some(activity)
}

pub(super) fn count_recent_authorized(
    activity: &HashMap<String, bool>,
    keys: &[String],
) -> Option<u32> {
    // Omit incomplete readings and exclude invitation/bootstrap/removed peers.
    keys.iter().try_fold(0_u32, |total, key| {
        total.checked_add(u32::from(*activity.get(key)?))
    })
}

#[cfg(test)]
#[path = "service_metrics_kernel.rs"]
mod kernel_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_counters_preserve_free_space_and_reject_invalid_or_overflowed_values() {
        assert_eq!(parse_disk_usage("100 25 4096\n"), Some((307_200, 409_600)));
        assert_eq!(parse_disk_usage("100 100 4096"), Some((0, 409_600)));
        for output in [
            "",
            "0 0 4096",
            "100 101 4096",
            "100 20 0",
            "100 20 -1",
            "18446744073709551615 0 4096",
            "100 20 4096 extra",
        ] {
            assert_eq!(parse_disk_usage(output), None, "{output}");
        }
    }

    #[test]
    fn activity_uses_only_recent_handshakes_and_handles_missing_or_future_data() {
        let key = STANDARD.encode([1_u8; 32]);
        for (timestamp, expected) in [
            (0, Some(false)),
            (819, Some(false)),
            (820, Some(true)),
            (1_000, Some(true)),
            (1_001, None),
        ] {
            let output = format!("{key}\t{timestamp}\n");
            assert_eq!(
                parse_peer_activity(&output, 1_000)
                    .unwrap()
                    .get(&key)
                    .copied(),
                expected
            );
        }
        assert!(parse_peer_activity("", 1_000).unwrap().is_empty());
        assert!(parse_peer_activity(&format!("{key} invalid"), 1_000).is_none());
        assert!(parse_peer_activity(&format!("{key} 900 extra"), 1_000).is_none());
        assert!(parse_peer_activity(&format!("{key} 900\n{key} 950"), 1_000).is_none());
        assert!(parse_peer_activity("invalid-key 900", 1_000).is_none());
    }

    #[tokio::test]
    async fn current_host_storage_is_read_without_a_vpn_or_authorization_store() {
        let (used, total) = root_disk_usage()
            .await
            .expect("coreutils stat reads the root filesystem");
        assert!(total > 0 && used <= total);
        assert_eq!(
            packet_counter("sirinvpn-missing-interface", "rx_packets"),
            None
        );
        assert!(
            bounded_output("sirinvpn-nonexistent-tool", &[])
                .await
                .is_none()
        );
    }
}
