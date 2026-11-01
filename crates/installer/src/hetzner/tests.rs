use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

const TOKEN: &str = "test-token-0123456789abcdefABCDEF";

#[derive(Default)]
struct State {
    /// Method, path with query, Authorization header, JSON body.
    calls: Vec<(String, String, String, Value)>,
    statuses: Vec<&'static str>,
    create_error: Option<(u16, Value)>,
    key_error: Option<(u16, Value)>,
    create_delay: Option<Duration>,
    created: bool,
}

struct Mock {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl Mock {
    fn start(state: State) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(state));
        let shared = state.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = shared.clone();
                thread::spawn(move || serve(stream, &state));
            }
        });
        Self { address, state }
    }

    fn client(&self, wait: Wait) -> HetznerClient {
        let http = Client::builder()
            .timeout(Duration::from_millis(800))
            .build()
            .unwrap();
        let base = Url::parse(&format!("http://{}/v1/", self.address)).unwrap();
        HetznerClient::with(http, base, &format!("  {TOKEN}\n"), wait).unwrap()
    }

    fn calls(&self, method: &str) -> Vec<(String, Value)> {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.0 == method)
            .map(|call| (call.1.clone(), call.3.clone()))
            .collect()
    }
}

fn quick() -> Wait {
    Wait {
        running: Duration::from_millis(300),
        ssh: Duration::from_millis(300),
        poll: Duration::from_millis(10),
    }
}

fn serve(stream: TcpStream, state: &Mutex<State>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let (mut length, mut authorization) = (0, String::new());
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header.trim().is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().unwrap(),
            "authorization" => authorization = value.trim().to_owned(),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let (status, response) = respond(state, &method, &path, &authorization, body);
    let reason = if status < 400 { "OK" } else { "Error" };
    let text = if status == 204 {
        String::new()
    } else {
        response.to_string()
    };
    let _ = write!(
        &stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
}

fn respond(
    state: &Mutex<State>,
    method: &str,
    path: &str,
    authorization: &str,
    body: Value,
) -> (u16, Value) {
    let mut state_guard = state.lock().unwrap();
    state_guard.calls.push((
        method.to_owned(),
        path.to_owned(),
        authorization.to_owned(),
        body,
    ));
    if authorization != format!("Bearer {TOKEN}") {
        return (
            401,
            json!({"error": {"code": "unauthorized", "message": "unable to authenticate"}}),
        );
    }
    let route = path.split('?').next().unwrap();
    let last_page = json!({"pagination": {"next_page": null}});
    match (method, route) {
        ("GET", "/v1/locations") => (
            200,
            json!({"locations": [
            {"name": "fsn1", "description": "Falkenstein DC Park 1", "city": "Falkenstein", "country": "DE"},
            {"name": "ash", "description": "Ashburn, VA", "city": "Ashburn", "country": "US"},
            {"name": "hel1", "description": "Helsinki DC Park 1", "city": "Helsinki", "country": "FI"},
        ], "meta": last_page}),
        ),
        ("GET", "/v1/server_types") if path.contains("page=1") => {
            let mut deprecated =
                server_type("cx22", "x86", &[("fsn1", "3.0000000000000000", true)]);
            deprecated["deprecation"] = json!({"announced": "2025-10-01T00:00:00Z", "unavailable_after": "2026-01-01T00:00:00Z"});
            (
                200,
                json!({"server_types": [
                server_type("cx23", "x86", &[("fsn1", "4.5101000000000000", true), ("ash", "5.9500000000000000", true)]),
                server_type("cpx22", "x86", &[("fsn1", "8.3300000000000000", true)]),
                deprecated,
            ], "meta": {"pagination": {"next_page": 2}}}),
            )
        }
        ("GET", "/v1/server_types") => (
            200,
            json!({"server_types": [
            server_type("cax11", "arm", &[("fsn1", "4.1000000000000000", true)]),
            server_type("ccx13", "x86", &[("fsn1", "1.0000000000000000", false), ("hel1", "1.0000000000000000", false)]),
        ], "meta": last_page}),
        ),
        ("GET", "/v1/pricing") => (
            200,
            json!({"pricing": {"currency": "EUR", "primary_ips": [
                {"type": "ipv6", "prices": [{"location": "fsn1", "price_monthly": {"net": "0", "gross": "0"}}]},
                {"type": "ipv4", "prices": [
                    {"location": "fsn1", "price_monthly": {"net": "0.5000", "gross": "0.5950000000000000"}},
                    {"location": "ash", "price_monthly": {"net": "0.5000", "gross": "0.5000"}},
                ]},
            ]}}),
        ),
        ("GET", "/v1/images") => (
            200,
            json!({"images": [{"id": if path.contains("arm") { 8 } else { 7 }}], "meta": last_page}),
        ),
        ("POST", "/v1/ssh_keys") => state_guard
            .key_error
            .clone()
            .unwrap_or((201, json!({"ssh_key": {"id": 11}}))),
        ("GET", "/v1/ssh_keys") => (200, json!({"ssh_keys": [{"id": 11}], "meta": last_page})),
        ("DELETE", "/v1/ssh_keys/11") => (204, Value::Null),
        ("POST", "/v1/servers") => {
            if let Some(error) = state_guard.create_error.clone() {
                return error;
            }
            state_guard.created = true;
            if let Some(delay) = state_guard.create_delay {
                drop(state_guard);
                thread::sleep(delay);
            }
            (201, json!({"server": server(42, "initializing")}))
        }
        ("GET", "/v1/servers") => {
            let found = if state_guard.created {
                vec![json!({"id": 42})]
            } else {
                Vec::new()
            };
            (200, json!({"servers": found, "meta": last_page}))
        }
        ("GET", "/v1/servers/42") => {
            let status = if state_guard.statuses.len() > 1 {
                state_guard.statuses.remove(0)
            } else {
                state_guard.statuses.first().copied().unwrap_or("running")
            };
            (200, json!({"server": server(42, status)}))
        }
        ("DELETE", "/v1/servers/42") if state_guard.created => {
            state_guard.created = false;
            (200, json!({"action": {"id": 1, "status": "running"}}))
        }
        _ => (
            404,
            json!({"error": {"code": "not_found", "message": "not found"}}),
        ),
    }
}

fn server_type(name: &str, architecture: &str, prices: &[(&str, &str, bool)]) -> Value {
    json!({
        "id": 1, "name": name, "description": name.to_uppercase(), "cores": 2, "memory": 4.0, "disk": 40,
        "deprecated": false, "deprecation": null, "storage_type": "local", "cpu_type": "shared",
        "architecture": architecture,
        "prices": prices.iter().map(|(location, gross, _)| json!({
            "location": location,
            "price_hourly": {"net": "0.0060", "gross": "0.0071"},
            "price_monthly": {"net": "3.7900", "gross": gross},
        })).collect::<Vec<_>>(),
        "locations": prices.iter().map(|(location, _, available)| json!({
            "id": 1, "name": location, "deprecation": null, "recommended": true, "available": available,
        })).collect::<Vec<_>>(),
    })
}

fn server(id: u64, status: &str) -> Value {
    json!({"id": id, "name": "sirinvpn-test", "status": status, "public_net": {
        "ipv4": {"id": 5, "ip": "203.0.113.7"},
        "ipv6": {"id": 6, "ip": "2001:db8:1:2::/64"},
    }})
}

fn plan(price: &str) -> HetznerServerRequest {
    HetznerServerRequest {
        location: "fsn1".to_owned(),
        server_type: "cx23".to_owned(),
        accepted_monthly_price: price.to_owned(),
    }
}

#[tokio::test]
async fn catalog_lists_available_types_with_the_ipv4_address_in_the_price() {
    let mock = Mock::start(State::default());
    let catalog = mock.client(quick()).catalog(false).await.unwrap();
    assert_eq!(catalog.currency, "EUR");
    assert_eq!(catalog.image, "debian-13");
    let names = |catalog: &HetznerCatalog| {
        catalog
            .server_types
            .iter()
            .map(|kind| kind.name.clone())
            .collect::<Vec<_>>()
    };
    // Deprecated, unavailable and (without an aarch64 payload) Arm types are left out.
    assert_eq!(names(&catalog), ["cx23", "cpx22"]);
    assert_eq!(
        catalog
            .locations
            .iter()
            .map(|l| l.name.as_str())
            .collect::<Vec<_>>(),
        ["fsn1", "ash"]
    );
    assert_eq!(
        catalog.price("fsn1", "cx23"),
        Some(&HetznerPrice {
            location: "fsn1".to_owned(),
            server_monthly: "4.51".to_owned(),
            ipv4_monthly: Some("0.60".to_owned()),
            total_monthly: "5.11".to_owned(),
        })
    );
    assert_eq!(catalog.price("ash", "cx23").unwrap().total_monthly, "6.45");
    assert_eq!(catalog.cheapest_x86("fsn1").unwrap().name, "cx23");

    let with_arm = mock.client(quick()).catalog(true).await.unwrap();
    assert_eq!(names(&with_arm), ["cx23", "cpx22", "cax11"]);
    assert_eq!(with_arm.cheapest_x86("fsn1").unwrap().name, "cx23");
}

#[tokio::test]
async fn creation_pre_seeds_keys_and_continues_once_the_pinned_key_answers() {
    let mock = Mock::start(State {
        statuses: vec!["initializing", "starting", "running"],
        ..State::default()
    });
    let client = mock.client(quick());
    let prepared = PreparedServer::generate();
    let server = client
        .create_server(&prepared, &plan("5.11"), false)
        .await
        .unwrap();
    assert_eq!(server.id, 42);
    assert_eq!(server.host_key_sha256, prepared.host_key_sha256());

    let posts = mock.calls("POST");
    assert_eq!(posts[0].0, "/v1/ssh_keys");
    assert_eq!(posts[0].1["name"], prepared.name);
    let login = posts[0].1["public_key"].as_str().unwrap();
    assert!(login.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"));
    let create = &posts[1].1;
    assert_eq!(posts[1].0, "/v1/servers");
    assert_eq!(create["image"], "7");
    assert_eq!(create["server_type"], "cx23");
    assert_eq!(create["location"], "fsn1");
    assert_eq!(create["ssh_keys"], json!([11]));
    assert_eq!(create["labels"], json!({"managed-by": "sirinvpn"}));
    assert_eq!(create["user_data"], prepared.user_data());
    assert!(create["user_data"].as_str().unwrap().contains(login));
    // The per-server project key is removed again right after creation.
    assert_eq!(mock.calls("DELETE")[0].0, "/v1/ssh_keys/11");
    assert!(
        mock.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .all(|call| call.2 == format!("Bearer {TOKEN}"))
    );

    let attempts = Arc::new(Mutex::new(0));
    let replaced = Arc::new(AtomicBool::new(false));
    let (seen, done) = (attempts.clone(), replaced.clone());
    let expected = server.host_key_sha256.clone();
    let ready = client
        .wait_with(
            &server,
            &AtomicBool::new(false),
            move |ipv4| {
                assert_eq!(ipv4, Ipv4Addr::new(203, 0, 113, 7));
                let mut attempts = seen.lock().unwrap();
                *attempts += 1;
                match *attempts {
                    1 => None,
                    2 => Some("SHA256:cloud-init-has-not-run-yet".to_owned()),
                    // sshd still restarting after the replacement
                    3 | 4 => Some(expected.clone()),
                    _ if done.load(Ordering::SeqCst) => Some("SHA256:replaced".to_owned()),
                    _ => None,
                }
            },
            move |ipv4| {
                assert_eq!(ipv4, Ipv4Addr::new(203, 0, 113, 7));
                replaced.store(true, Ordering::SeqCst);
                Ok("SHA256:replaced".to_owned())
            },
        )
        .await
        .unwrap();
    assert_eq!(*attempts.lock().unwrap(), 5);
    assert_eq!(
        ready,
        HetznerReady {
            ipv4: Ipv4Addr::new(203, 0, 113, 7),
            ipv6: Some("2001:db8:1:2::1".parse().unwrap()),
            host_key_sha256: "SHA256:replaced".to_owned(),
        }
    );
}

#[tokio::test]
async fn an_api_error_creates_nothing_and_removes_the_uploaded_key() {
    let mock = Mock::start(State {
        create_error: Some((
            403,
            json!({"error": {"code": "resource_limit_exceeded", "message": "server limit reached"}}),
        )),
        ..State::default()
    });
    let error = mock
        .client(quick())
        .create_server(&PreparedServer::generate(), &plan("5.11"), false)
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        HetznerError::Api { status: 403, code, message }
            if code == "resource_limit_exceeded" && message == "server limit reached"
    ));
    assert_eq!(mock.calls("DELETE")[0].0, "/v1/ssh_keys/11");

    // A server error is no refusal: the server may exist, so its name is looked up.
    let failed = Mock::start(State {
        create_error: Some((503, Value::Null)),
        ..State::default()
    });
    let prepared = PreparedServer::generate();
    assert!(matches!(
        failed.client(quick()).create_server(&prepared, &plan("5.11"), false).await,
        Err(HetznerError::Uncertain(name)) if name == prepared.name
    ));
    assert!(
        failed
            .calls("GET")
            .iter()
            .any(|call| call.0.starts_with("/v1/servers?name="))
    );
    assert_eq!(failed.calls("DELETE")[0].0, "/v1/ssh_keys/11");

    // An unanswered key upload may have stored the key; it is found and removed.
    for (status, removed) in [(502, true), (422, false)] {
        let mock = Mock::start(State {
            key_error: Some((status, Value::Null)),
            ..State::default()
        });
        assert!(matches!(
            mock.client(quick()).create_server(&PreparedServer::generate(), &plan("5.11"), false).await,
            Err(HetznerError::Api { status: code, .. }) if code == status
        ));
        assert_eq!(
            mock.calls("DELETE")
                .iter()
                .any(|call| call.0 == "/v1/ssh_keys/11"),
            removed
        );
        assert_eq!(mock.calls("POST").len(), 1, "no server is created");
    }

    let rejected = Mock::start(State::default());
    let http = Client::new();
    let base = Url::parse(&format!("http://{}/v1/", rejected.address)).unwrap();
    let wrong = HetznerClient::with(http, base, "another-token-0123456789", quick()).unwrap();
    assert!(matches!(
        wrong.catalog(false).await,
        Err(HetznerError::Api { status: 401, .. })
    ));
}

#[tokio::test]
async fn a_changed_price_or_unavailable_choice_stops_before_anything_is_created() {
    let mock = Mock::start(State::default());
    let client = mock.client(quick());
    let prepared = PreparedServer::generate();
    assert!(matches!(
        client.create_server(&prepared, &plan("4.99"), false).await,
        Err(HetznerError::PriceChanged(price)) if price == "5.11 EUR"
    ));
    let arm = HetznerServerRequest {
        server_type: "cax11".to_owned(),
        ..plan("4.70")
    };
    assert!(matches!(
        client.create_server(&prepared, &arm, false).await,
        Err(HetznerError::InvalidChoice(_))
    ));
    assert!(mock.calls("POST").is_empty());
}

#[tokio::test]
async fn an_unanswered_create_request_finds_the_server_by_its_name() {
    let mock = Mock::start(State {
        create_delay: Some(Duration::from_secs(2)),
        ..State::default()
    });
    let server = mock
        .client(quick())
        .create_server(&PreparedServer::generate(), &plan("5.11"), false)
        .await
        .unwrap();
    assert_eq!(server.id, 42);
    assert!(
        mock.calls("GET")
            .iter()
            .any(|call| call.0.starts_with("/v1/servers?name=sirinvpn-"))
    );
}

#[tokio::test]
async fn waiting_times_out_and_never_trusts_another_host_key() {
    let mock = Mock::start(State {
        statuses: vec!["initializing"],
        ..State::default()
    });
    let client = mock.client(quick());
    let server = HetznerServer {
        id: 42,
        name: "sirinvpn-test".to_owned(),
        host_key_sha256: "SHA256:pinned".to_owned(),
    };
    let never = AtomicBool::new(false);
    let unused = |_| unreachable!("the pinned key never answered");
    assert!(matches!(
        client.wait_with(&server, &never, |_| None, unused).await,
        Err(HetznerError::Timeout("start"))
    ));
    mock.state.lock().unwrap().statuses = vec!["running"];
    assert!(matches!(
        client.wait_with(&server, &never, |_| None, unused).await,
        Err(HetznerError::Timeout("accept SSH connections"))
    ));
    assert!(matches!(
        client
            .wait_with(&server, &never, |_| Some("SHA256:other".to_owned()), unused)
            .await,
        Err(HetznerError::HostKeyMismatch)
    ));

    // After the replacement only the new key is trusted.
    let pinned = |_| Some("SHA256:pinned".to_owned());
    assert!(matches!(
        client
            .wait_with(&server, &never, pinned, |_| Err(
                HetznerError::HostKeyReplacement("failed".to_owned())
            ))
            .await,
        Err(HetznerError::HostKeyReplacement(_))
    ));
    assert!(matches!(
        client
            .wait_with(&server, &never, pinned, |_| Ok("SHA256:new".to_owned()))
            .await,
        Err(HetznerError::Timeout("accept SSH connections"))
    ));
    let probes = Arc::new(Mutex::new(0));
    let third = move |_| {
        let mut probes = probes.lock().unwrap();
        *probes += 1;
        Some(
            if *probes == 1 {
                "SHA256:pinned"
            } else {
                "SHA256:other"
            }
            .to_owned(),
        )
    };
    assert!(matches!(
        client
            .wait_with(&server, &never, third, |_| Ok("SHA256:new".to_owned()))
            .await,
        Err(HetznerError::HostKeyMismatch)
    ));
}

#[tokio::test]
async fn cancelling_stops_waiting_and_the_server_is_deleted_only_when_asked() {
    let mock = Mock::start(State {
        statuses: vec!["initializing"],
        ..State::default()
    });
    let client = mock.client(Wait {
        running: Duration::from_secs(30),
        ..quick()
    });
    let prepared = PreparedServer::generate();
    let server = client
        .create_server(&prepared, &plan("5.11"), false)
        .await
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        flag.store(true, Ordering::SeqCst);
    });
    assert!(matches!(
        client
            .wait_with(&server, &cancel, |_| None, |_| unreachable!())
            .await,
        Err(HetznerError::Cancelled)
    ));
    assert!(
        !mock
            .calls("DELETE")
            .iter()
            .any(|call| call.0 == "/v1/servers/42")
    );

    client.delete_server(server.id).await.unwrap();
    assert!(
        mock.calls("DELETE")
            .iter()
            .any(|call| call.0 == "/v1/servers/42")
    );
    // Already gone counts as deleted.
    client.delete_server(server.id).await.unwrap();
}

#[test]
fn tokens_are_validated_and_never_printed() {
    let base = Url::parse("http://127.0.0.1/v1/").unwrap();
    for token in [
        "",
        "short",
        "contains whitespace 0123456789",
        "tab\tseparated-0123456789",
    ] {
        assert!(matches!(
            HetznerClient::with(Client::new(), base.clone(), token, quick()),
            Err(HetznerError::InvalidToken)
        ));
    }
    let client = HetznerClient::with(Client::new(), base, TOKEN, quick()).unwrap();
    assert!(client.authorization.is_sensitive());
    assert!(!format!("{client:?}").contains(TOKEN));
    assert!(HetznerClient::new(TOKEN).unwrap().base.as_str() == "https://api.hetzner.cloud/v1/");
}

#[test]
fn prices_use_exact_decimal_arithmetic() {
    assert_eq!(money("4.5101000000000000"), Some(45_101));
    assert_eq!(money("12"), Some(120_000));
    assert_eq!(money("0.595"), Some(5_950));
    for invalid in ["", ".5", "1.2.3", "-1", "1e3", "abc", "1.5x"] {
        assert_eq!(money(invalid), None, "{invalid}");
    }
    assert_eq!(cents(45_101), "4.51");
    assert_eq!(cents(5_950), "0.60");
    assert_eq!(cents(51_051), "5.11");
    assert_eq!(cents(0), "0.00");
}

#[test]
fn the_server_takes_the_first_address_of_its_ipv6_network() {
    assert_eq!(
        first_address("2a01:4f8:c17:abcd::/64"),
        Some("2a01:4f8:c17:abcd::1".parse().unwrap())
    );
    assert_eq!(first_address("not an address"), None);
}

#[test]
fn keys_use_the_openssh_format_and_the_installer_fingerprint() {
    let prepared = PreparedServer::generate();
    let login = openssh_public_key(&prepared.login, "login");
    let pem = prepared.login_private_key();
    let body = STANDARD
        .decode(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();
    assert!(body.starts_with(b"openssh-key-v1\0\0\0\0\x04none\0\0\0\x04none\0\0\0\0\0\0\0\x01"));
    let public = public_key_blob(&prepared.login);
    assert_eq!(&body[39..43], &(public.len() as u32).to_be_bytes());
    assert_eq!(&body[43..43 + public.len()], public.as_slice());
    let private = &body[47 + public.len()..];
    assert_eq!(private.len() % 8, 0);
    assert_eq!(private[..4], private[4..8]);
    assert!(pem.lines().all(|line| line.len() <= 70));

    let user_data = prepared.user_data();
    assert!(user_data.starts_with("#cloud-config\n"));
    assert!(user_data.len() < 32 * 1024);
    assert!(user_data.contains("ssh_pwauth: false\n"));
    assert!(user_data.contains("  ed25519_private: |\n    -----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert!(user_data.contains(&format!(
        "  ed25519_public: {}\n",
        openssh_public_key(&prepared.host, &format!("{}-host", prepared.name))
    )));
    assert!(
        !user_data.contains(pem.as_str()),
        "the login private key stays local"
    );

    let target = ssh_target(
        Ipv4Addr::new(203, 0, 113, 7),
        prepared.login_private_key(),
        prepared.host_key_sha256(),
    );
    assert_eq!(
        (target.host.as_str(), target.port, target.username.as_str()),
        ("203.0.113.7", 22, "root")
    );
    assert_eq!(
        target.expected_host_key_sha256,
        Some(prepared.host_key_sha256())
    );
    assert!(matches!(
        target.authentication,
        SshAuthentication::PrivateKeyMemory {
            passphrase: None,
            ..
        }
    ));

    // Cross-check with OpenSSH where it is installed (CI runners have it).
    let directory = tempfile::tempdir().unwrap();
    let path = save_login_key(directory.path(), &prepared).unwrap();
    assert_eq!(path, directory.path().join("ssh-keys").join(&prepared.name));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    assert_eq!(
        load_login_key(directory.path(), &prepared.name).unwrap(),
        prepared.login_private_key()
    );
    assert!(load_login_key(directory.path(), "../host").is_err());
    assert!(forget_login_key(directory.path(), "../host").is_err());
    let copy = directory.path().join("login-copy");
    std::fs::copy(&path, &copy).unwrap();
    forget_login_key(directory.path(), &prepared.name).unwrap();
    assert!(!path.exists());
    forget_login_key(directory.path(), &prepared.name).unwrap();
    let path = copy;
    let host_path = directory.path().join("host");
    sirinvpn_platform::files::atomic_write(
        &host_path,
        openssh_private_key(&prepared.host, "host").as_bytes(),
        false,
    )
    .unwrap();
    let keygen = |arguments: &[&str]| {
        std::process::Command::new("ssh-keygen")
            .args(arguments)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8(output.stdout).unwrap())
    };
    let Some(derived) = keygen(&["-y", "-f", path.to_str().unwrap()]) else {
        eprintln!("ssh-keygen is unavailable; skipped the OpenSSH cross-check");
        return;
    };
    assert_eq!(
        derived.split_whitespace().take(2).collect::<Vec<_>>(),
        login.split_whitespace().take(2).collect::<Vec<_>>()
    );
    let listed = keygen(&["-l", "-E", "sha256", "-f", host_path.to_str().unwrap()]).unwrap();
    assert_eq!(
        listed.split_whitespace().nth(1),
        Some(prepared.host_key_sha256().as_str())
    );
}
