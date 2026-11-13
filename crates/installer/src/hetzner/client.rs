use super::*;

#[derive(Clone, Copy)]
pub(super) struct Wait {
    pub(super) running: Duration,
    pub(super) ssh: Duration,
    pub(super) poll: Duration,
}

pub struct HetznerClient {
    http: Client,
    pub(super) base: Url,
    pub(super) authorization: HeaderValue,
    wait: Wait,
}

impl std::fmt::Debug for HetznerClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HetznerClient([REDACTED])")
    }
}

impl HetznerClient {
    pub fn new(token: &str) -> Result<Self, HetznerError> {
        #[allow(unused_mut)]
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("SirinVPN");
        // rustls-native-certs does not read Android's trust store.
        #[cfg(target_os = "android")]
        for directory in [
            "/apex/com.android.conscrypt/cacerts",
            "/system/etc/security/cacerts",
        ] {
            let roots = std::fs::read_dir(directory)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|entry| std::fs::read(entry.path()).ok())
                .filter_map(|pem| reqwest::Certificate::from_pem(&pem).ok())
                .collect::<Vec<_>>();
            if !roots.is_empty() {
                for root in roots {
                    builder = builder.add_root_certificate(root);
                }
                break;
            }
        }
        let http = builder
            .build()
            .map_err(|error| HetznerError::Request(error.to_string()))?;
        Self::with(
            http,
            Url::parse(API).expect("valid API URL"),
            token,
            Wait {
                running: Duration::from_secs(5 * 60),
                ssh: Duration::from_secs(5 * 60),
                poll: Duration::from_secs(3),
            },
        )
    }

    pub(super) fn with(
        http: Client,
        base: Url,
        token: &str,
        wait: Wait,
    ) -> Result<Self, HetznerError> {
        let token = token.trim();
        if !(16..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HetznerError::InvalidToken);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| HetznerError::InvalidToken)?;
        authorization.set_sensitive(true);
        Ok(Self {
            http,
            base,
            authorization,
            wait,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, HetznerError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| HetznerError::InvalidResponse)?;
        let mut request = self
            .http
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| HetznerError::Request(error.without_url().to_string()))?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| HetznerError::Request(error.without_url().to_string()))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(HetznerError::InvalidResponse);
            }
        }
        if !status.is_success() {
            let error: Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let text = |key: &str, fallback: &str| {
                error["error"][key]
                    .as_str()
                    .unwrap_or(fallback)
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(300)
                    .collect::<String>()
            };
            return Err(HetznerError::Api {
                status: status.as_u16(),
                code: text("code", "http_error"),
                message: text("message", status.canonical_reason().unwrap_or("error")),
            });
        }
        if status == StatusCode::NO_CONTENT {
            bytes = b"null".to_vec();
        }
        serde_json::from_slice(&bytes).map_err(|_| HetznerError::InvalidResponse)
    }

    /// Every page of a list endpoint.
    async fn list<T: DeserializeOwned>(
        &self,
        path: &str,
        field: &str,
    ) -> Result<Vec<T>, HetznerError> {
        let mut items = Vec::new();
        for page in 1..=20 {
            let separator = if path.contains('?') { '&' } else { '?' };
            let mut response: Value = self
                .call(
                    Method::GET,
                    &format!("{path}{separator}per_page=50&page={page}"),
                    None,
                )
                .await?;
            let batch: Vec<T> = serde_json::from_value(response[field].take())
                .map_err(|_| HetznerError::InvalidResponse)?;
            items.extend(batch);
            if response["meta"]["pagination"]["next_page"]
                .as_u64()
                .is_none()
            {
                return Ok(items);
            }
        }
        Err(HetznerError::InvalidResponse)
    }

    /// Locations and server types with monthly prices. Arm types are listed only
    /// when the caller has an aarch64 server payload.
    pub async fn catalog(&self, allow_arm: bool) -> Result<HetznerCatalog, HetznerError> {
        let locations: Vec<HetznerLocation> = self.list("locations", "locations").await?;
        let types: Vec<ApiServerType> = self.list("server_types", "server_types").await?;
        let pricing: ApiPricing = self.call(Method::GET, "pricing", None).await?;
        let ipv4 = pricing
            .pricing
            .primary_ips
            .into_iter()
            .find(|price| price.kind == "ipv4")
            .map(|price| price.prices)
            .unwrap_or_default();
        let server_types = types
            .into_iter()
            .filter(|kind| {
                !kind.deprecated.unwrap_or(false)
                    && kind.deprecation.is_none()
                    && (kind.architecture == "x86" || allow_arm && kind.architecture == "arm")
            })
            .filter_map(|kind| {
                let prices = kind
                    .prices
                    .iter()
                    .filter(|price| {
                        kind.locations.is_empty()
                            || kind.locations.iter().any(|location| {
                                location.name == price.location
                                    && location.available.unwrap_or(true)
                                    && location.deprecation.is_none()
                            })
                    })
                    .filter_map(|price| {
                        let server = money(&price.price_monthly.gross)?;
                        let address = ipv4
                            .iter()
                            .find(|address| address.location == price.location)
                            .and_then(|address| money(&address.price_monthly.gross));
                        Some(HetznerPrice {
                            location: price.location.clone(),
                            server_monthly: cents(server),
                            ipv4_monthly: address.map(cents),
                            total_monthly: cents(server.checked_add(address.unwrap_or(0))?),
                        })
                    })
                    .collect::<Vec<_>>();
                (!prices.is_empty()).then_some(HetznerServerType {
                    name: kind.name,
                    description: kind.description,
                    architecture: kind.architecture,
                    cores: kind.cores,
                    memory_gb: kind.memory,
                    disk_gb: kind.disk,
                    prices,
                })
            })
            .collect::<Vec<_>>();
        Ok(HetznerCatalog {
            currency: pricing.pricing.currency,
            image: IMAGE.to_owned(),
            locations: locations
                .into_iter()
                .filter(|location| {
                    server_types.iter().any(|kind| {
                        kind.prices
                            .iter()
                            .any(|price| price.location == location.name)
                    })
                })
                .collect(),
            server_types,
        })
    }

    /// Creates the server with the prepared keys. Returns once Hetzner accepted
    /// it; call [`Self::wait_until_ready`] next.
    pub async fn create_server(
        &self,
        prepared: &PreparedServer,
        request: &HetznerServerRequest,
        allow_arm: bool,
    ) -> Result<HetznerServer, HetznerError> {
        let catalog = self.catalog(allow_arm).await?;
        let architecture = catalog
            .server_types
            .iter()
            .find(|kind| kind.name == request.server_type)
            .map(|kind| kind.architecture.clone())
            .ok_or_else(|| {
                HetznerError::InvalidChoice("this server type is not available".to_owned())
            })?;
        let price = catalog
            .price(&request.location, &request.server_type)
            .ok_or_else(|| {
                HetznerError::InvalidChoice(
                    "this server type is not available in the chosen location".to_owned(),
                )
            })?;
        if price.total_monthly != request.accepted_monthly_price {
            return Err(HetznerError::PriceChanged(format!(
                "{} {}",
                price.total_monthly, catalog.currency
            )));
        }
        let images: Vec<ApiId> = self
            .list(
                &format!("images?type=system&name={IMAGE}&architecture={architecture}"),
                "images",
            )
            .await?;
        let image = images.first().ok_or_else(|| {
            HetznerError::InvalidChoice(format!(
                "Hetzner Cloud offers no Debian 13 image for {architecture} servers"
            ))
        })?;

        let labels: Value = serde_json::from_str(LABELS).expect("valid labels");
        let key = match self
            .call::<ApiSshKey>(
                Method::POST,
                "ssh_keys",
                Some(json!({
                    "name": prepared.name,
                    "public_key": openssh_public_key(&prepared.login, &format!("{}-login", prepared.name)),
                    "labels": labels,
                })),
            )
            .await
        {
            Ok(key) => key.ssh_key.id,
            Err(error) => {
                if !refused(&error) && let Ok(Some(id)) = self.find("ssh_keys", &prepared.name).await {
                    self.forget_ssh_key(id).await;
                }
                return Err(error);
            }
        };
        let created = self
            .call::<ApiServerResponse>(
                Method::POST,
                "servers",
                Some(json!({
                    "name": prepared.name,
                    "server_type": request.server_type,
                    "location": request.location,
                    "image": image.id.to_string(),
                    "ssh_keys": [key],
                    "user_data": prepared.user_data(),
                    "labels": labels,
                    "start_after_create": true,
                    "public_net": {"enable_ipv4": true, "enable_ipv6": true},
                })),
            )
            .await;
        let server = match created {
            Ok(response) => Ok(response.server.id),
            Err(error) if refused(&error) => Err(error),
            // No answer, a server error or an unreadable answer: the server may
            // exist anyway. Look it up before reporting.
            Err(_) => match self.find("servers", &prepared.name).await {
                Ok(Some(id)) => Ok(id),
                _ => Err(HetznerError::Uncertain(prepared.name.clone())),
            },
        };
        // The login key reaches root through user_data too, so the per-server
        // project key is no longer needed once the server exists (or failed).
        self.forget_ssh_key(key).await;
        Ok(HetznerServer {
            id: server?,
            name: prepared.name.clone(),
            host_key_sha256: prepared.host_key_sha256(),
        })
    }

    /// Waits until the server runs and answers SSH with the pre-seeded host key,
    /// then replaces that key over the pinned session. Pin the returned key.
    pub async fn wait_until_ready(
        &self,
        server: &HetznerServer,
        login_private_key: Zeroizing<String>,
        cancel: &AtomicBool,
    ) -> Result<HetznerReady, HetznerError> {
        let pin = server.host_key_sha256.clone();
        self.wait_with(server, cancel, None, presented_host_key, move |ipv4| {
            replace_host_key(&ssh_target(ipv4, login_private_key, pin))
                .map_err(|error| HetznerError::HostKeyReplacement(error.to_string()))
        })
        .await
    }

    /// Continues a recorded creation from its phase and records each new one.
    /// A `Requested` record whose server Hetzner does not have is forgotten.
    pub async fn resume(
        &self,
        configuration_directory: &Path,
        provision: &mut HetznerProvision,
        login_private_key: Zeroizing<String>,
        cancel: &AtomicBool,
    ) -> Result<HetznerReady, HetznerError> {
        let record = |provision: &mut HetznerProvision, phase| {
            provision
                .advance(configuration_directory, phase)
                .map_err(|error| HetznerError::Request(format!("saving progress: {error}")))
        };
        if provision.phase == HetznerPhase::Requested {
            // A failed lookup keeps the record: the server may still exist.
            let Some(server_id) = self.find("servers", &provision.name).await? else {
                let _ = HetznerProvision::forget(configuration_directory, &provision.name);
                return Err(HetznerError::InvalidChoice(format!(
                    "Hetzner Cloud has no server named {}; nothing to resume",
                    provision.name
                )));
            };
            record(provision, HetznerPhase::Created { server_id })?;
        }
        if let HetznerPhase::Ready { ready, .. } = &provision.phase {
            return Ok(ready.clone());
        }
        let server = HetznerServer {
            id: provision.server_id().expect("created"),
            name: provision.name.clone(),
            host_key_sha256: provision.pre_seeded_host_key_sha256.clone(),
        };
        let pin = server.host_key_sha256.clone();
        let already = match &provision.phase {
            HetznerPhase::ReplacingHostKey {
                replacement_host_key_sha256,
                ..
            } => Some(replacement_host_key_sha256.clone()),
            _ => None,
        };
        // Written from the blocking SSH task before activation, so a crash
        // after this point still knows the key the server may present.
        let directory = configuration_directory.to_path_buf();
        let mut replacing = provision.clone();
        let server_id = server.id;
        let ready = self
            .wait_with(
                &server,
                cancel,
                already.as_deref(),
                presented_host_key,
                move |ipv4| {
                    replace_host_key_with(
                        &ssh_target(ipv4, login_private_key, pin),
                        |replacement| {
                            replacing
                                .advance(
                                    &directory,
                                    HetznerPhase::ReplacingHostKey {
                                        server_id,
                                        replacement_host_key_sha256: replacement.to_owned(),
                                    },
                                )
                                .map_err(|error| crate::phase_error("host key", error.into()))
                        },
                    )
                    .map_err(|error| HetznerError::HostKeyReplacement(error.to_string()))
                },
            )
            .await?;
        record(
            provision,
            HetznerPhase::Ready {
                server_id,
                ready: ready.clone(),
            },
        )?;
        Ok(ready)
    }

    pub(super) async fn wait_with(
        &self,
        server: &HetznerServer,
        cancel: &AtomicBool,
        already_replaced: Option<&str>,
        probe: impl Fn(Ipv4Addr) -> Option<String> + Clone + Send + 'static,
        replace: impl FnOnce(Ipv4Addr) -> Result<String, HetznerError> + Send + 'static,
    ) -> Result<HetznerReady, HetznerError> {
        let deadline = Instant::now() + self.wait.running;
        let (ipv4, ipv6) = loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(HetznerError::Cancelled);
            }
            let current: ApiServerResponse = self
                .call(Method::GET, &format!("servers/{}", server.id), None)
                .await?;
            let network = current.server.public_net;
            if current.server.status == "running"
                && let Some(ipv4) = network.ipv4.and_then(|address| address.ip.parse().ok())
            {
                break (
                    ipv4,
                    network.ipv6.and_then(|address| first_address(&address.ip)),
                );
            }
            if Instant::now() > deadline {
                return Err(HetznerError::Timeout("start"));
            }
            tokio::time::sleep(self.wait.poll).await;
        };
        // A resumed creation whose replacement key is already active is done.
        if let Some(replacement) = already_replaced {
            let probe = probe.clone();
            if tokio::task::spawn_blocking(move || probe(ipv4))
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some(replacement)
            {
                return Ok(HetznerReady {
                    ipv4,
                    ipv6,
                    host_key_sha256: replacement.to_owned(),
                });
            }
        }
        self.wait_for_key(ipv4, &server.host_key_sha256, None, cancel, &probe)
            .await?;
        let host_key_sha256 = tokio::task::spawn_blocking(move || replace(ipv4))
            .await
            .map_err(|error| HetznerError::HostKeyReplacement(error.to_string()))??;
        // sshd restarts on reload; until then it may still present the old key.
        self.wait_for_key(
            ipv4,
            &host_key_sha256,
            Some(&server.host_key_sha256),
            cancel,
            &probe,
        )
        .await?;
        Ok(HetznerReady {
            ipv4,
            ipv6,
            host_key_sha256,
        })
    }

    async fn wait_for_key(
        &self,
        ipv4: Ipv4Addr,
        expected: &str,
        previous: Option<&str>,
        cancel: &AtomicBool,
        probe: &(impl Fn(Ipv4Addr) -> Option<String> + Clone + Send + 'static),
    ) -> Result<(), HetznerError> {
        let deadline = Instant::now() + self.wait.ssh;
        let mut mismatch = false;
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(HetznerError::Cancelled);
            }
            let probe = probe.clone();
            match tokio::task::spawn_blocking(move || probe(ipv4)).await {
                Ok(Some(fingerprint)) if fingerprint == expected => return Ok(()),
                Ok(Some(fingerprint)) if Some(fingerprint.as_str()) == previous => {}
                // Keep waiting: cloud-init may not have written the key yet.
                Ok(Some(_)) => mismatch = true,
                _ => {}
            }
            if Instant::now() > deadline {
                return Err(if mismatch {
                    HetznerError::HostKeyMismatch
                } else {
                    HetznerError::Timeout("accept SSH connections")
                });
            }
            tokio::time::sleep(self.wait.poll).await;
        }
    }

    /// The ID of the named resource, if it exists.
    /// `Ok(None)` only when Hetzner answered that nothing has this name; a failed
    /// lookup is an error, never "not found".
    async fn find(&self, collection: &str, name: &str) -> Result<Option<u64>, HetznerError> {
        Ok(self
            .list::<ApiId>(&format!("{collection}?name={name}"), collection)
            .await?
            .first()
            .map(|item| item.id))
    }

    async fn forget_ssh_key(&self, id: u64) {
        let _ = self
            .call::<serde::de::IgnoredAny>(Method::DELETE, &format!("ssh_keys/{id}"), None)
            .await;
    }

    /// Deletes the server. A server that no longer exists counts as deleted.
    pub async fn delete_server(&self, id: u64) -> Result<(), HetznerError> {
        match self
            .call::<serde::de::IgnoredAny>(Method::DELETE, &format!("servers/{id}"), None)
            .await
        {
            Ok(_) | Err(HetznerError::Api { status: 404, .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
