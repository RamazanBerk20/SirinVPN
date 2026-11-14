use super::*;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use sirinvpn_release::{
    SchemaRange, StateCompatibility, build_manifest, build_trust_policy, encode_manifest,
    encode_trust_policy, generate_signing_keypair, sign_manifest, sign_release_notes,
    sign_trust_policy,
};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::{MetadataExt, symlink},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const TEST_TARGET: &str = "x86_64-unknown-linux-gnu";
const TEST_ARTIFACT_NAME: &str = "SirinVPN_test_amd64.deb";
const TEST_SUMMARY: &str = "Reconnects faster after sleep.";

struct SignedFixture {
    root_public_key: String,
    policy: Vec<u8>,
    trust_signature: Vec<u8>,
    manifest: Vec<u8>,
    release_signature: Vec<u8>,
    notes: Vec<u8>,
    artifact: Vec<u8>,
}

impl SignedFixture {
    fn new(channel: ReleaseChannel) -> Self {
        let artifact = b"authenticated Debian package fixture".to_vec();
        let directory = tempfile::tempdir().unwrap();
        let artifact_path = directory.path().join(TEST_ARTIFACT_NAME);
        fs::write(&artifact_path, &artifact).unwrap();
        let declaration =
            ReleaseArtifact::from_path(ArtifactKind::LinuxDeb, TEST_TARGET, &artifact_path)
                .unwrap();
        let manifest = build_manifest(
            "0.2.0",
            2,
            channel,
            true,
            vec![declaration],
            vec![StateCompatibility {
                state: "linux_release_trust".to_owned(),
                reads: SchemaRange {
                    minimum: 1,
                    maximum: 1,
                },
                writes: SchemaRange {
                    minimum: 1,
                    maximum: 1,
                },
            }],
        )
        .unwrap();
        let manifest = encode_manifest(&manifest).unwrap();
        let (release_private_key, release_public_key) = generate_signing_keypair().unwrap();
        let release_signature = sign_manifest(&manifest, &release_private_key).unwrap();
        let notes = sign_release_notes(&manifest, TEST_SUMMARY, &release_private_key).unwrap();
        let (root_private_key, root_public_key) = generate_signing_keypair().unwrap();
        let policy = build_trust_policy(3, vec![release_public_key], Vec::new()).unwrap();
        let policy = encode_trust_policy(&policy).unwrap();
        let trust_signature = sign_trust_policy(&policy, &root_private_key).unwrap();
        Self {
            root_public_key,
            policy,
            trust_signature,
            manifest,
            release_signature,
            notes,
            artifact,
        }
    }

    fn routes(&self) -> HashMap<String, TestResponse> {
        HashMap::from([
            (
                stable_path(TRUST_POLICY_FILE_NAME),
                TestResponse::ok(self.policy.clone()),
            ),
            (
                stable_path(TRUST_SIGNATURE_FILE_NAME),
                TestResponse::ok(self.trust_signature.clone()),
            ),
            (
                stable_path(RELEASE_MANIFEST_FILE_NAME),
                TestResponse::ok(self.manifest.clone()),
            ),
            (
                stable_path(RELEASE_SIGNATURE_FILE_NAME),
                TestResponse::ok(self.release_signature.clone()),
            ),
            (
                stable_path(RELEASE_NOTES_FILE_NAME),
                TestResponse::ok(self.notes.clone()),
            ),
            (
                stable_path(TEST_ARTIFACT_NAME),
                TestResponse::ok(self.artifact.clone()),
            ),
        ])
    }
}

#[derive(Clone)]
struct TestResponse {
    status: &'static str,
    body: Vec<u8>,
    declared_length: Option<u64>,
    extra_headers: Vec<(&'static str, String)>,
}

impl TestResponse {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: "200 OK",
            body,
            declared_length: None,
            extra_headers: Vec::new(),
        }
    }
}

struct TestHttpsServer {
    port: u16,
    certificate: reqwest::Certificate,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl TestHttpsServer {
    fn start(routes: HashMap<String, TestResponse>, expected_requests: usize) -> Self {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let certificate = reqwest::Certificate::from_der(cert.der().as_ref()).unwrap();
        let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let configuration = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private_key.into())
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        // Redirect targets may name this server's port as "{PORT}".
        let routes: HashMap<_, _> = routes
            .into_iter()
            .map(|(path, mut response)| {
                for (_, value) in &mut response.extra_headers {
                    *value = value.replace("{PORT}", &port.to_string());
                }
                (path, response)
            })
            .collect();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            for _ in 0..expected_requests {
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "HTTPS fixture timed out");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("HTTPS fixture accept failed: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = ServerConnection::new(Arc::new(configuration.clone())).unwrap();
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0, "HTTPS request ended before its headers");
                    request.extend_from_slice(&buffer[..read]);
                    assert!(
                        request.len() <= 16 * 1024,
                        "HTTPS request headers too large"
                    );
                }
                let request = String::from_utf8(request).unwrap();
                let request_line = request.lines().next().unwrap();
                let mut fields = request_line.split_whitespace();
                assert_eq!(fields.next(), Some("GET"));
                let path = fields.next().unwrap().to_owned();
                recorded.lock().unwrap().push(request.clone());
                let response = routes.get(&path).cloned().unwrap_or(TestResponse {
                    status: "404 Not Found",
                    body: Vec::new(),
                    declared_length: None,
                    extra_headers: Vec::new(),
                });
                let length = response
                    .declared_length
                    .unwrap_or(response.body.len() as u64);
                let mut headers = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status, length
                );
                for (name, value) in response.extra_headers {
                    headers.push_str(name);
                    headers.push_str(": ");
                    headers.push_str(&value);
                    headers.push_str("\r\n");
                }
                headers.push_str("\r\n");
                let _ = stream.write_all(headers.as_bytes());
                let _ = stream.write_all(&response.body);
                let _ = stream.flush();
            }
        });
        Self {
            port,
            certificate,
            requests,
            worker: Some(worker),
        }
    }

    fn source(&self) -> String {
        format!("{}://127.0.0.1:{}/stable/", "https", self.port)
    }

    /// The client production picks for this server's typed source.
    fn client(&self) -> Client {
        client_builder(&validate_source_url(&self.source()).unwrap())
            .add_root_certificate(self.certificate.clone())
            .build()
            .unwrap()
    }

    fn finish(mut self) -> Vec<String> {
        self.worker.take().unwrap().join().unwrap();
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for TestHttpsServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn stable_path(file_name: &str) -> String {
    format!("/stable/{file_name}")
}

fn request(source: String, destination: PathBuf) -> ReleaseFetchRequest {
    ReleaseFetchRequest {
        source,
        expected_channel: ReleaseChannel::Stable,
        artifact_kind: ArtifactKind::LinuxDeb,
        artifact_target: TEST_TARGET.to_owned(),
        destination,
        release_notes: true,
    }
}

fn assert_no_staging_directory(parent: &Path) {
    assert!(fs::read_dir(parent).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".sirinvpn-release-fetch.")
    }));
}

#[tokio::test]
async fn verified_https_bundle_is_published_atomically_and_privately() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let server = TestHttpsServer::start(fixture.routes(), 6);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let fetched = fetch_release_with_client_and_root(
        request(server.source(), destination.clone()),
        &server.client(),
        &fixture.root_public_key,
    )
    .await
    .unwrap();

    assert_eq!(fetched.release_version, "0.2.0");
    assert_eq!(fetched.release_sequence, 2);
    assert_eq!(fetched.trust_policy_sequence, 3);
    assert!(fetched.security_update);
    assert_eq!(fetched.release_notes.as_deref(), Some(TEST_SUMMARY));
    assert_eq!(
        fs::read(destination.join(RELEASE_NOTES_FILE_NAME)).unwrap(),
        fixture.notes
    );
    assert_eq!(fetched.bundle_directory, destination);
    assert_eq!(
        fs::read(
            destination
                .join(ARTIFACT_DIRECTORY_NAME)
                .join(TEST_ARTIFACT_NAME)
        )
        .unwrap(),
        fixture.artifact
    );
    assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(destination.join(RELEASE_MANIFEST_FILE_NAME))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(destination.join(ARTIFACT_DIRECTORY_NAME))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(
            destination
                .join(ARTIFACT_DIRECTORY_NAME)
                .join(TEST_ARTIFACT_NAME)
        )
        .unwrap()
        .mode()
            & 0o777,
        0o600
    );
    assert_no_staging_directory(parent.path());

    let requests = server.finish();
    let paths = requests
        .iter()
        .map(|request| request.lines().next().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            format!("GET {} HTTP/1.1", stable_path(TRUST_POLICY_FILE_NAME)),
            format!("GET {} HTTP/1.1", stable_path(TRUST_SIGNATURE_FILE_NAME)),
            format!("GET {} HTTP/1.1", stable_path(RELEASE_MANIFEST_FILE_NAME)),
            format!("GET {} HTTP/1.1", stable_path(RELEASE_SIGNATURE_FILE_NAME)),
            format!("GET {} HTTP/1.1", stable_path(RELEASE_NOTES_FILE_NAME)),
            format!("GET {} HTTP/1.1", stable_path(TEST_ARTIFACT_NAME)),
        ]
    );
    for request in requests {
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("accept-encoding: identity\r\n"));
        assert!(lower.contains("user-agent: sirinvpn-release-fetch/1\r\n"));
        assert!(!lower.contains("referer:"));
    }
}

#[tokio::test]
async fn artifact_tampering_fails_and_leaves_no_destination() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let mut routes = fixture.routes();
    let mut tampered = fixture.artifact.clone();
    tampered[0] ^= 1;
    routes.insert(stable_path(TEST_ARTIFACT_NAME), TestResponse::ok(tampered));
    let server = TestHttpsServer::start(routes, 6);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let result = fetch_release_with_client_and_root(
        request(server.source(), destination.clone()),
        &server.client(),
        &fixture.root_public_key,
    )
    .await;
    assert!(matches!(
        result,
        Err(FetchError::Release(ReleaseError::ArtifactDigestMismatch(_)))
    ));
    assert!(!destination.exists());
    assert_no_staging_directory(parent.path());
    assert_eq!(server.finish().len(), 6);
}

#[tokio::test]
async fn missing_or_unverified_notes_are_dropped_without_failing_the_fetch() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let replayed = SignedFixture::new(ReleaseChannel::Stable).notes;
    let mut tampered = fixture.notes.clone();
    let position = tampered
        .windows(b"faster".len())
        .position(|window| window == b"faster")
        .unwrap();
    tampered[position] = b'F';
    for notes in [None, Some(tampered), Some(replayed)] {
        let mut routes = fixture.routes();
        match notes {
            Some(notes) => routes.insert(
                stable_path(RELEASE_NOTES_FILE_NAME),
                TestResponse::ok(notes),
            ),
            None => routes.remove(&stable_path(RELEASE_NOTES_FILE_NAME)),
        };
        let server = TestHttpsServer::start(routes, 6);
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("candidate");
        let fetched = fetch_release_with_client_and_root(
            request(server.source(), destination.clone()),
            &server.client(),
            &fixture.root_public_key,
        )
        .await
        .unwrap();
        assert_eq!(fetched.release_notes, None);
        assert!(!destination.join(RELEASE_NOTES_FILE_NAME).exists());
        assert_eq!(server.finish().len(), 6);
    }
}

#[tokio::test]
async fn a_bundle_with_tampered_notes_on_disk_opens_without_them() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let server = TestHttpsServer::start(fixture.routes(), 6);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    fetch_release_with_client_and_root(
        request(server.source(), destination.clone()),
        &server.client(),
        &fixture.root_public_key,
    )
    .await
    .unwrap();
    server.finish();
    let open = || {
        VerifiedReleaseBundle::open_with_root(
            &destination,
            ArtifactKind::LinuxDeb,
            TEST_TARGET,
            &fixture.root_public_key,
        )
        .unwrap()
    };
    assert_eq!(open().release_notes.unwrap().1, TEST_SUMMARY);
    // The staging area is writable by the downloader: edited notes are dropped, the release isn't.
    let path = destination.join(RELEASE_NOTES_FILE_NAME);
    let edited = String::from_utf8(fs::read(&path).unwrap())
        .unwrap()
        .replace("faster", "Faster");
    fs::write(&path, edited).unwrap();
    assert!(open().release_notes.is_none());
}

#[tokio::test]
async fn a_caller_that_does_not_ask_for_notes_never_meets_them() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let server = TestHttpsServer::start(fixture.routes(), 5);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let mut without_notes = request(server.source(), destination.clone());
    without_notes.release_notes = false;
    let fetched = fetch_release_with_client_and_root(
        without_notes,
        &server.client(),
        &fixture.root_public_key,
    )
    .await
    .unwrap();
    assert_eq!(fetched.release_notes, None);
    assert!(!destination.join(RELEASE_NOTES_FILE_NAME).exists());
    // The same five requests as before notes existed, and no field an older parser rejects.
    let requests = server.finish();
    assert_eq!(requests.len(), 5);
    assert!(
        !requests
            .iter()
            .any(|path| path.contains(RELEASE_NOTES_FILE_NAME))
    );
    assert!(
        !serde_json::to_string(&fetched)
            .unwrap()
            .contains("release_notes")
    );
}

#[tokio::test]
async fn unauthorized_manifest_is_rejected_before_artifact_request() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let mut routes = fixture.routes();
    let mut signature = fixture.release_signature.clone();
    let tampered_byte = signature.len() - 2;
    signature[tampered_byte] ^= 1;
    routes.insert(
        stable_path(RELEASE_SIGNATURE_FILE_NAME),
        TestResponse::ok(signature),
    );
    let server = TestHttpsServer::start(routes, 4);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let result = fetch_release_with_client_and_root(
        request(server.source(), destination.clone()),
        &server.client(),
        &fixture.root_public_key,
    )
    .await;
    assert!(matches!(result, Err(FetchError::Release(_))));
    assert!(!destination.exists());
    assert_no_staging_directory(parent.path());
    assert_eq!(server.finish().len(), 4);
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let mut routes = fixture.routes();
    routes.insert(
        stable_path(TRUST_POLICY_FILE_NAME),
        TestResponse {
            status: "302 Found",
            body: Vec::new(),
            declared_length: None,
            // Even a GitHub host is not followed for a typed source.
            extra_headers: vec![(
                "Location",
                format!("{}://github.com/RamazanBerk20/SirinVPN/", "https"),
            )],
        },
    );
    let server = TestHttpsServer::start(routes, 1);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let result = fetch_release_with_client_and_root(
        request(server.source(), destination.clone()),
        &server.client(),
        &fixture.root_public_key,
    )
    .await;
    assert!(matches!(
        result,
        Err(FetchError::HttpStatus { status: 302, .. })
    ));
    assert!(!destination.exists());
    assert_no_staging_directory(parent.path());
    assert_eq!(server.finish().len(), 1);
}

#[tokio::test]
async fn oversized_metadata_is_rejected_from_headers() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let mut routes = fixture.routes();
    routes.insert(
        stable_path(TRUST_POLICY_FILE_NAME),
        TestResponse {
            status: "200 OK",
            body: Vec::new(),
            declared_length: Some(MAX_TRUST_POLICY_BYTES + 1),
            extra_headers: Vec::new(),
        },
    );
    let server = TestHttpsServer::start(routes, 1);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let result = fetch_release_with_client_and_root(
        request(server.source(), destination.clone()),
        &server.client(),
        &fixture.root_public_key,
    )
    .await;
    assert!(matches!(result, Err(FetchError::ResponseTooLarge { .. })));
    assert!(!destination.exists());
    assert_no_staging_directory(parent.path());
    assert_eq!(server.finish().len(), 1);
}

#[tokio::test]
async fn channel_mismatch_is_rejected_before_artifact_request() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let server = TestHttpsServer::start(fixture.routes(), 4);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let mut request = request(server.source(), destination.clone());
    request.expected_channel = ReleaseChannel::Preview;
    let result =
        fetch_release_with_client_and_root(request, &server.client(), &fixture.root_public_key)
            .await;
    assert!(matches!(result, Err(FetchError::ChannelMismatch { .. })));
    assert!(!destination.exists());
    assert_no_staging_directory(parent.path());
    assert_eq!(server.finish().len(), 4);
}

#[test]
fn source_policy_rejects_downgrade_credentials_and_tracking_data() {
    let https = |suffix: &str| format!("{}://updates.invalid/{suffix}", "https");
    let http = format!("{}://updates.invalid/stable/", "http");
    assert!(matches!(
        validate_source_url(&http),
        Err(FetchError::SourceMustUseHttps)
    ));
    assert!(matches!(
        validate_source_url(&format!("{}://user@updates.invalid/stable/", "https")),
        Err(FetchError::SourceContainsPrivateData)
    ));
    assert!(matches!(
        validate_source_url(&https("stable/?device=1")),
        Err(FetchError::SourceContainsPrivateData)
    ));
    assert!(matches!(
        validate_source_url(&https("stable/#fragment")),
        Err(FetchError::SourceContainsPrivateData)
    ));
    assert!(matches!(
        validate_source_url(&https("stable")),
        Err(FetchError::SourceIsNotDirectory)
    ));
    assert!(validate_source_url(&https("stable/")).is_ok());
}

#[test]
fn destination_policy_is_absolute_normalized_real_and_no_clobber() {
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    assert_eq!(validate_destination(&destination).unwrap(), destination);
    fs::create_dir(&destination).unwrap();
    assert!(matches!(
        validate_destination(&destination),
        Err(FetchError::DestinationExists)
    ));
    assert!(matches!(
        validate_destination(Path::new("relative")),
        Err(FetchError::InvalidDestination)
    ));

    let real_parent = parent.path().join("real");
    let linked_parent = parent.path().join("linked");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(matches!(
        validate_destination(&linked_parent.join("candidate")),
        Err(FetchError::InvalidDestination)
    ));
}

// Linux (any libc) and Android share this commit path, so the host run covers Android's.
#[test]
fn staging_commit_is_no_replace_on_every_linux_and_android_libc() {
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let staging = TempBuilder::new().tempdir_in(parent.path()).unwrap();
    fs::write(staging.path().join("marker"), b"first").unwrap();
    commit_staging(staging, &destination).unwrap();
    assert_eq!(fs::read(destination.join("marker")).unwrap(), b"first");

    let second = TempBuilder::new().tempdir_in(parent.path()).unwrap();
    fs::write(second.path().join("marker"), b"second").unwrap();
    assert!(matches!(
        commit_staging(second, &destination),
        Err(FetchError::DestinationExists)
    ));
    assert_eq!(fs::read(destination.join("marker")).unwrap(), b"first");
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
}

// The built-in GitHub source, against a local server standing in for both GitHub hosts.
const RELEASES_PATH: &str = "/repos/owner/project/releases?per_page=10";
const LATEST_PATH: &str = "/repos/owner/project/releases/latest";
const LATEST: &str =
    r#"{"tag_name": "v0.2.0", "draft": false, "prerelease": false, "body": "Notes."}"#;
const RELEASE_LIST: &str = r#"[
    {"tag_name": "v9.0.0", "draft": true, "prerelease": false},
    {"tag_name": "v0.3.0-rc.1", "draft": false, "prerelease": true, "assets": [{"name": "ignored"}]},
    {"tag_name": "v0.2.0", "draft": false, "prerelease": false, "body": "Notes GitHub shows."}
]"#;

fn github_endpoints(port: u16) -> GitHubEndpoints {
    let leak = |value: String| -> &'static str { Box::leak(value.into_boxed_str()) };
    GitHubEndpoints {
        releases: leak(format!("https://127.0.0.1:{port}{RELEASES_PATH}")),
        latest: leak(format!("https://127.0.0.1:{port}{LATEST_PATH}")),
        downloads: leak(format!("https://127.0.0.1:{port}/download/")),
        redirect_hosts: &["127.0.0.1"],
    }
}

fn github_client(server: &TestHttpsServer) -> Client {
    github_client_builder(&["127.0.0.1"], Some(server.port))
        .add_root_certificate(server.certificate.clone())
        .build()
        .unwrap()
}

fn redirect(location: String) -> TestResponse {
    TestResponse {
        status: "302 Found",
        body: Vec::new(),
        declared_length: None,
        extra_headers: vec![("Location", location)],
    }
}

fn status(status: &'static str) -> TestResponse {
    TestResponse {
        status,
        body: Vec::new(),
        declared_length: None,
        extra_headers: Vec::new(),
    }
}

fn github_request(channel: ReleaseChannel, destination: PathBuf) -> ReleaseFetchRequest {
    let mut request = request(GITHUB_SOURCE.to_owned(), destination);
    request.expected_channel = channel;
    request
}

/// The six release files under `/download/{tag}/`, each redirecting to `/storage/{tag}/`.
fn redirected_release(fixture: &SignedFixture, tag: &str) -> HashMap<String, TestResponse> {
    let mut routes = HashMap::from([(LATEST_PATH.to_owned(), TestResponse::ok(LATEST.into()))]);
    for (path, response) in fixture.routes() {
        let name = path.trim_start_matches("/stable/");
        routes.insert(
            format!("/download/{tag}/{name}"),
            redirect(format!("/storage/{tag}/{name}")),
        );
        routes.insert(format!("/storage/{tag}/{name}"), response);
    }
    routes
}

#[tokio::test]
async fn github_source_fetches_the_stable_release_through_allowlisted_redirects() {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let server = TestHttpsServer::start(redirected_release(&fixture, "v0.2.0"), 13);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let fetched = fetch_release_via(
        github_request(ReleaseChannel::Stable, destination.clone()),
        &github_client(&server),
        &fixture.root_public_key,
        &github_endpoints(server.port),
    )
    .await
    .unwrap();
    assert_eq!(fetched.release_version, "0.2.0");
    assert_eq!(
        fs::read(
            destination
                .join(ARTIFACT_DIRECTORY_NAME)
                .join(TEST_ARTIFACT_NAME)
        )
        .unwrap(),
        fixture.artifact
    );
    let requests = server.finish();
    assert!(requests[0].starts_with(&format!("GET {LATEST_PATH} HTTP/1.1")));
    assert!(requests[1].starts_with(&format!("GET /download/v0.2.0/{TRUST_POLICY_FILE_NAME} ")));
    assert!(requests[2].starts_with(&format!("GET /storage/v0.2.0/{TRUST_POLICY_FILE_NAME} ")));
    for request in requests {
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("user-agent: sirinvpn-release-fetch/1\r\n"));
        assert!(!lower.contains("referer:") && !lower.contains("authorization:"));
    }
}

#[tokio::test]
async fn github_source_picks_the_newest_pre_release_for_the_preview_channel() {
    let fixture = SignedFixture::new(ReleaseChannel::Preview);
    let mut routes = HashMap::from([(
        RELEASES_PATH.to_owned(),
        TestResponse::ok(RELEASE_LIST.into()),
    )]);
    for (path, response) in fixture.routes() {
        routes.insert(path.replace("/stable/", "/download/v0.3.0-rc.1/"), response);
    }
    let server = TestHttpsServer::start(routes, 7);
    let parent = tempfile::tempdir().unwrap();
    let fetched = fetch_release_via(
        github_request(ReleaseChannel::Preview, parent.path().join("candidate")),
        &github_client(&server),
        &fixture.root_public_key,
        &github_endpoints(server.port),
    )
    .await
    .unwrap();
    assert_eq!(fetched.channel, ReleaseChannel::Preview);
    assert!(server.finish()[1].starts_with("GET /download/v0.3.0-rc.1/"));
}

async fn github_failure(routes: HashMap<String, TestResponse>, requests: usize) -> FetchError {
    let fixture = SignedFixture::new(ReleaseChannel::Stable);
    let server = TestHttpsServer::start(routes, requests);
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("candidate");
    let error = fetch_release_via(
        github_request(ReleaseChannel::Stable, destination.clone()),
        &github_client(&server),
        &fixture.root_public_key,
        &github_endpoints(server.port),
    )
    .await
    .unwrap_err();
    assert!(!destination.exists());
    assert_no_staging_directory(parent.path());
    assert_eq!(server.finish().len(), requests);
    error
}

fn list_and_first_file(first: TestResponse) -> HashMap<String, TestResponse> {
    HashMap::from([
        (LATEST_PATH.to_owned(), TestResponse::ok(LATEST.into())),
        (format!("/download/v0.2.0/{TRUST_POLICY_FILE_NAME}"), first),
    ])
}

fn is_refused_redirect(error: &FetchError) -> bool {
    matches!(error, FetchError::Request { source, .. } if source.is_redirect())
}

#[tokio::test]
async fn github_redirects_to_other_hosts_plain_http_or_too_many_hops_are_refused() {
    let elsewhere = github_failure(
        list_and_first_file(redirect(
            "https://localhost:{PORT}/storage/policy".to_owned(),
        )),
        2,
    )
    .await;
    assert!(is_refused_redirect(&elsewhere), "{elsewhere:?}");

    for (label, location) in [
        ("port", "https://127.0.0.1:1/storage/policy"),
        (
            "credentials",
            "https://user:secret@127.0.0.1:{PORT}/storage/policy",
        ),
    ] {
        let error = github_failure(list_and_first_file(redirect(location.to_owned())), 2).await;
        assert!(is_refused_redirect(&error), "{label}: {error:?}");
    }

    let downgrade = github_failure(
        list_and_first_file(redirect(
            "http://127.0.0.1:{PORT}/storage/policy".to_owned(),
        )),
        2,
    )
    .await;
    assert!(is_refused_redirect(&downgrade), "{downgrade:?}");

    let mut hops = list_and_first_file(redirect("/hop/1".to_owned()));
    for hop in 1..=3 {
        hops.insert(format!("/hop/{hop}"), redirect(format!("/hop/{}", hop + 1)));
    }
    hops.insert(
        "/hop/4".to_owned(),
        TestResponse::ok(b"never reached".to_vec()),
    );
    let looping = github_failure(hops, 5).await;
    assert!(is_refused_redirect(&looping), "{looping:?}");
}

#[tokio::test]
async fn github_rate_limits_and_bad_release_lists_fail_with_their_own_errors() {
    let limited = |answer: &'static str, header: Option<(&'static str, String)>| TestResponse {
        extra_headers: header.into_iter().collect(),
        ..status(answer)
    };
    for (answer, header, code) in [
        ("429 Too Many Requests", None, 429),
        (
            "403 Forbidden",
            Some(("x-ratelimit-remaining", "0".to_owned())),
            403,
        ),
        ("403 Forbidden", Some(("Retry-After", "60".to_owned())), 403),
    ] {
        let routes = HashMap::from([(LATEST_PATH.to_owned(), limited(answer, header))]);
        let error = github_failure(routes, 1).await;
        assert!(matches!(error, FetchError::GitHubRateLimited(c) if c == code));
        assert_eq!(error.failure(), FetchFailure::RateLimited);
    }
    // Any other 403 (a blocked network, a captive portal) is not called a rate limit.
    let error = github_failure(
        HashMap::from([(LATEST_PATH.to_owned(), status("403 Forbidden"))]),
        1,
    )
    .await;
    assert!(
        matches!(error, FetchError::HttpStatus { status: 403, .. }),
        "{error:?}"
    );
    for body in [
        r#"{"tag_name": "../../evil", "prerelease": false}"#,
        r#"{"message": "No tag"}"#,
        r#"[{"tag_name": "v1.0.0", "prerelease": false}]"#,
    ] {
        let error = github_failure(
            HashMap::from([(LATEST_PATH.to_owned(), TestResponse::ok(body.into()))]),
            1,
        )
        .await;
        assert!(
            matches!(error, FetchError::GitHubResponseInvalid),
            "{error:?}"
        );
    }
    // No full release yet (404), or a "latest" that claims to be a pre-release: nothing to offer.
    let marked_preview = r#"{"tag_name": "v1.0.0-rc.1", "prerelease": true}"#;
    for answer in [
        status("404 Not Found"),
        TestResponse::ok(marked_preview.into()),
    ] {
        let error = github_failure(HashMap::from([(LATEST_PATH.to_owned(), answer)]), 1).await;
        assert!(matches!(
            error,
            FetchError::GitHubReleaseUnavailable(ReleaseChannel::Stable)
        ));
        assert_eq!(error.failure(), FetchFailure::NoRelease);
    }
}

#[tokio::test]
async fn github_preview_with_only_full_releases_listed_finds_nothing() {
    let fixture = SignedFixture::new(ReleaseChannel::Preview);
    let only_stable = r#"[{"tag_name": "v1.1.0", "prerelease": false}, {"tag_name": "v1.0.0", "prerelease": false}]"#;
    let server = TestHttpsServer::start(
        HashMap::from([(
            RELEASES_PATH.to_owned(),
            TestResponse::ok(only_stable.into()),
        )]),
        1,
    );
    let parent = tempfile::tempdir().unwrap();
    let error = fetch_release_via(
        github_request(ReleaseChannel::Preview, parent.path().join("candidate")),
        &github_client(&server),
        &fixture.root_public_key,
        &github_endpoints(server.port),
    )
    .await
    .unwrap_err();
    assert_eq!(error.failure(), FetchFailure::NoRelease);
    assert_eq!(server.finish().len(), 1);
}

#[tokio::test]
async fn an_unreachable_github_reads_as_offline() {
    let port = {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let parent = tempfile::tempdir().unwrap();
    let error = fetch_release_via(
        github_request(ReleaseChannel::Stable, parent.path().join("candidate")),
        &github_client_builder(&["127.0.0.1"], Some(port))
            .build()
            .unwrap(),
        &SignedFixture::new(ReleaseChannel::Stable).root_public_key,
        &github_endpoints(port),
    )
    .await
    .unwrap_err();
    assert_eq!(error.failure(), FetchFailure::Offline, "{error:?}");
}

#[test]
fn only_the_exact_built_in_name_selects_github() {
    assert_eq!(
        validate_source_url(GITHUB_SOURCE).unwrap(),
        ReleaseSource::GitHub
    );
    for near in ["GitHub", "github/", " github", "https://github.com/"] {
        assert!(!matches!(
            validate_source_url(near),
            Ok(ReleaseSource::GitHub)
        ));
    }
}
