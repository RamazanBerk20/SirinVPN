use super::*;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use sirinvpn_release::{
    SchemaRange, StateCompatibility, build_manifest, build_trust_policy, encode_manifest,
    encode_trust_policy, generate_signing_keypair, sign_manifest, sign_trust_policy,
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

struct SignedFixture {
    root_public_key: String,
    policy: Vec<u8>,
    trust_signature: Vec<u8>,
    manifest: Vec<u8>,
    release_signature: Vec<u8>,
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

    fn client(&self) -> Client {
        secure_client_builder()
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
    let server = TestHttpsServer::start(fixture.routes(), 5);
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
    let server = TestHttpsServer::start(routes, 5);
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
    assert_eq!(server.finish().len(), 5);
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
            extra_headers: vec![("Location", stable_path(TRUST_POLICY_FILE_NAME))],
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
