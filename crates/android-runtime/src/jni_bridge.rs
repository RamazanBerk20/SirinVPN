use anyhow::{Context, Result, bail};
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JByteArray, JObject, JString, JValue},
    sys::{jboolean, jlong, jstring},
};
use sirinvpn_core::{ClientPaths, SecretIdentity, SecretStore, SecretStoreError};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

pub struct Platform {
    vm: JavaVM,
    object: GlobalRef,
}
pub struct Runtime {
    pub paths: ClientPaths,
    pub platform: Arc<Platform>,
    pub executor: tokio::runtime::Runtime,
    pub relay: Mutex<Option<tokio::task::JoinHandle<Result<(), sirinvpn_transport::RelayError>>>>,
    pub measurement: tokio::sync::Mutex<()>,
    pub generation: std::sync::atomic::AtomicI64,
}
static RUNTIME: OnceLock<Runtime> = OnceLock::new();
pub fn runtime() -> Result<&'static Runtime> {
    RUNTIME.get().context("Android service not initialized")
}

impl Platform {
    pub fn quality_result(
        &self,
        result: Option<&serde_json::Value>,
        generation: i64,
    ) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let result = if let Some(result) = result {
            JObject::from(env.new_string(result.to_string())?)
        } else {
            JObject::null()
        };
        env.call_method(
            &self.object,
            "qualityResult",
            "(Ljava/lang/String;J)V",
            &[JValue::Object(&result), JValue::Long(generation)],
        )?;
        Ok(())
    }
    pub fn quality_state(&self, generation: i64) -> Result<serde_json::Value> {
        let mut env = self.vm.attach_current_thread()?;
        let value = env
            .call_method(
                &self.object,
                "qualityState",
                "(J)Ljava/lang/String;",
                &[JValue::Long(generation)],
            )?
            .l()?;
        if value.is_null() {
            bail!("Connection changed")
        }
        let value: String = env.get_string(&JString::from(value))?.into();
        Ok(serde_json::from_str(&value)?)
    }
    pub fn handoff(&self, config: &serde_json::Value, generation: i64) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let value = env.new_string(config.to_string())?;
        if !env
            .call_method(
                &self.object,
                "handoff",
                "(Ljava/lang/String;J)Z",
                &[JValue::Object(&value), JValue::Long(generation)],
            )?
            .z()?
        {
            bail!("Connection changed")
        }
        Ok(())
    }
    pub fn measure(
        &self,
        config: &serde_json::Value,
        generation: i64,
    ) -> Result<Option<sirinvpn_protocol::TransportQualitySample>> {
        let mut env = self.vm.attach_current_thread()?;
        let serialized = Zeroizing::new(config.to_string());
        let value = env.new_string(&*serialized)?;
        let result = env
            .call_method(
                &self.object,
                "measure",
                "(Ljava/lang/String;J)Ljava/lang/String;",
                &[JValue::Object(&value), JValue::Long(generation)],
            )?
            .l()?;
        if result.is_null() {
            return Ok(None);
        }
        let result: String = env.get_string(&JString::from(result))?.into();
        let sample: sirinvpn_protocol::TransportQualitySample = serde_json::from_str(&result)?;
        Ok(sample.valid().then_some(sample))
    }
    pub fn connection_preferences(&self, id: &str) -> Result<Option<serde_json::Value>> {
        let mut env = self.vm.attach_current_thread()?;
        let id = env.new_string(id)?;
        let value = env
            .call_method(
                &self.object,
                "connectionPreferences",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&id)],
            )?
            .l()?;
        if value.is_null() {
            return Ok(None);
        }
        let value: String = env.get_string(&JString::from(value))?.into();
        Ok(Some(serde_json::from_str(&value)?))
    }
    pub fn prepare_connection(
        &self,
        id: &str,
        preferences: &sirinvpn_tunnel_model::ConnectionPreferences,
        generation: i64,
    ) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let value = env
            .new_string(serde_json::json!({"serverId":id,"preferences":preferences}).to_string())?;
        env.call_method(
            &self.object,
            "prepareConnection",
            "(Ljava/lang/String;J)V",
            &[JValue::Object(&value), JValue::Long(generation)],
        )?;
        Ok(())
    }
    pub fn wifi(&self) -> Result<serde_json::Value> {
        let mut env = self.vm.attach_current_thread()?;
        let value = env
            .call_method(&self.object, "wifi", "()Ljava/lang/String;", &[])?
            .l()?;
        let text: String = env.get_string(&JString::from(value))?.into();
        Ok(serde_json::from_str(&text)?)
    }
    pub fn installed_apk(&self) -> Result<std::path::PathBuf> {
        let mut env = self.vm.attach_current_thread()?;
        let value = env
            .call_method(&self.object, "installedApk", "()Ljava/lang/String;", &[])?
            .l()?;
        let value: String = env.get_string(&JString::from(value))?.into();
        Ok(value.into())
    }
    pub fn install_apk(&self, path: &std::path::Path) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let path = env.new_string(path.to_str().context("Invalid package path")?)?;
        env.call_method(
            &self.object,
            "installApk",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&path)],
        )?;
        Ok(())
    }
    pub fn abandon_apk(&self) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        env.call_method(&self.object, "abandonApk", "()V", &[])?;
        Ok(())
    }
    pub fn has_handshake(&self) -> Result<bool> {
        let mut env = self.vm.attach_current_thread()?;
        Ok(env
            .call_method(&self.object, "hasHandshake", "()Z", &[])?
            .z()?)
    }
    pub fn blob(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut env = self.vm.attach_current_thread()?;
        let name = env.new_string(name)?;
        let array = env
            .call_method(
                &self.object,
                "secretGet",
                "(Ljava/lang/String;)[B",
                &[JValue::Object(&name)],
            )?
            .l()?;
        if array.is_null() {
            return Ok(None);
        }
        let array = JByteArray::from(array);
        let bytes = Zeroizing::new(env.convert_byte_array(&array)?);
        env.set_byte_array_region(&array, 0, &vec![0; bytes.len()])?;
        Ok(Some(bytes))
    }
    pub fn put_blob(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let name = env.new_string(name)?;
        let array = env.byte_array_from_slice(bytes)?;
        let result = env.call_method(
            &self.object,
            "secretPut",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&name), JValue::Object(&array)],
        );
        if result.is_err() {
            let _ = env.exception_clear();
        }
        env.set_byte_array_region(&array, 0, &vec![0; bytes.len()])?;
        result?;
        Ok(())
    }
    pub fn delete_blob(&self, name: &str) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let name = env.new_string(name)?;
        env.call_method(
            &self.object,
            "secretDelete",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&name)],
        )?;
        Ok(())
    }
    pub fn document(&self, uri: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut env = self.vm.attach_current_thread()?;
        let uri = env.new_string(uri)?;
        let array = env
            .call_method(
                &self.object,
                "readDocument",
                "(Ljava/lang/String;)[B",
                &[JValue::Object(&uri)],
            )?
            .l()?;
        let array = JByteArray::from(array);
        let bytes = Zeroizing::new(env.convert_byte_array(&array)?);
        env.set_byte_array_region(&array, 0, &vec![0; bytes.len()])?;
        Ok(bytes)
    }
    pub fn write_document(&self, uri: &str, bytes: &[u8]) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let uri = env.new_string(uri)?;
        let array = env.byte_array_from_slice(bytes)?;
        env.call_method(
            &self.object,
            "writeDocument",
            "(Ljava/lang/String;[B)V",
            &[JValue::Object(&uri), JValue::Object(&array)],
        )?;
        Ok(())
    }
    fn check_state(&self, method: &str, id: &str) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        let id = env.new_string(id)?;
        if !env
            .call_method(
                &self.object,
                method,
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&id)],
            )?
            .z()?
        {
            bail!("The active tunnel does not permit this operation")
        }
        Ok(())
    }
    pub fn require_active(&self, id: &str) -> Result<()> {
        self.check_state("isActive", id)
    }
    pub fn require_inactive(&self, id: &str) -> Result<()> {
        self.check_state("isInactive", id)
    }
    pub fn require_idle(&self) -> Result<()> {
        self.check_state("isInactive", "")
    }
    pub fn current(&self, generation: i64) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        if !env
            .call_method(
                &self.object,
                "isCurrent",
                "(J)Z",
                &[JValue::Long(generation)],
            )?
            .z()?
        {
            bail!("Connection cancelled")
        }
        Ok(())
    }
    pub fn protect(&self, fd: i32) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        if !env
            .call_method(&self.object, "protectSocket", "(I)Z", &[JValue::Int(fd)])?
            .z()?
        {
            bail!("Transport socket protection failed")
        }
        Ok(())
    }
    pub fn resolve(&self, host: &str) -> Result<String> {
        let mut env = self.vm.attach_current_thread()?;
        let name = env.new_string(host)?;
        let value = env
            .call_method(
                &self.object,
                "resolve",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        Ok(env.get_string(&JString::from(value))?.into())
    }
    pub fn activate(&self, config: &serde_json::Value, generation: i64) -> Result<()> {
        self.current(generation)?;
        let mut env = self.vm.attach_current_thread()?;
        let serialized = Zeroizing::new(serde_json::to_string(config)?);
        let data = env.new_string(&*serialized)?;
        if !env
            .call_method(
                &self.object,
                "activate",
                "(Ljava/lang/String;J)Z",
                &[JValue::Object(&data), JValue::Long(generation)],
            )?
            .z()?
        {
            bail!("Android could not establish the tunnel")
        }
        Ok(())
    }
    pub fn deactivate(&self, generation: i64) -> Result<()> {
        let mut env = self.vm.attach_current_thread()?;
        env.call_method(
            &self.object,
            "deactivate",
            "(J)V",
            &[JValue::Long(generation)],
        )?;
        Ok(())
    }
    fn store_error(&self) -> SecretStoreError {
        if let Ok(env) = self.vm.attach_current_thread() {
            let _ = env.exception_clear();
        }
        SecretStoreError::Unavailable(
            "Android Keystore is unavailable; unlock the device and retry".into(),
        )
    }
}

struct AndroidSecrets(Arc<Platform>);
impl SecretStore for AndroidSecrets {
    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        let result = (|| -> Result<Option<SecretIdentity>> {
            let mut env = self.0.vm.attach_current_thread()?;
            let name = env.new_string(reference)?;
            let array = env
                .call_method(
                    &self.0.object,
                    "secretGet",
                    "(Ljava/lang/String;)[B",
                    &[JValue::Object(&name)],
                )?
                .l()?;
            if array.is_null() {
                return Ok(None);
            }
            let array = JByteArray::from(array);
            let bytes = Zeroizing::new(env.convert_byte_array(&array)?);
            env.set_byte_array_region(&array, 0, &vec![0; bytes.len()])?;
            Ok(Some(serde_json::from_slice(&bytes)?))
        })()
        .map_err(|_| self.0.store_error())?;
        result.ok_or(SecretStoreError::NotFound)
    }
    fn put(&self, reference: &str, identity: &SecretIdentity) -> Result<(), SecretStoreError> {
        (|| -> Result<()> {
            let mut env = self.0.vm.attach_current_thread()?;
            let name = env.new_string(reference)?;
            let bytes = Zeroizing::new(serde_json::to_vec(identity)?);
            let array = env.byte_array_from_slice(&bytes)?;
            let result = env.call_method(
                &self.0.object,
                "secretPut",
                "(Ljava/lang/String;[B)V",
                &[JValue::Object(&name), JValue::Object(&array)],
            );
            if result.is_err() {
                let _ = env.exception_clear();
            }
            env.set_byte_array_region(&array, 0, &vec![0; bytes.len()])?;
            result?;
            Ok(())
        })()
        .map_err(|_| self.0.store_error())
    }
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        (|| -> Result<()> {
            let mut env = self.0.vm.attach_current_thread()?;
            let name = env.new_string(reference)?;
            env.call_method(
                &self.0.object,
                "secretDelete",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&name)],
            )?;
            Ok(())
        })()
        .map_err(|_| self.0.store_error())
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_sirinvpn_client_Native_initialize(
    mut env: JNIEnv,
    _: JObject,
    directory: JString,
    platform: JObject,
) -> jboolean {
    if RUNTIME.get().is_some() {
        return 1;
    }
    let result = (|| -> Result<()> {
        let directory: String = env.get_string(&directory)?.into();
        let platform = Arc::new(Platform {
            vm: env.get_java_vm()?,
            object: env.new_global_ref(platform)?,
        });
        sirinvpn_core::install_android_secret_store(Box::new(AndroidSecrets(platform.clone())))?;
        let paths = ClientPaths::under(directory.into());
        sirinvpn_platform::files::create_private_directory(&paths.configuration_directory)?;
        let executor = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        RUNTIME
            .set(Runtime {
                paths,
                platform,
                executor,
                relay: Mutex::new(None),
                measurement: tokio::sync::Mutex::new(()),
                generation: std::sync::atomic::AtomicI64::new(0),
            })
            .map_err(|_| anyhow::anyhow!("Already initialized"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = env.exception_clear();
    }
    result.is_ok().into()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_sirinvpn_client_Native_call(
    mut env: JNIEnv,
    _: JObject,
    command: JString,
    arguments: JString,
    generation: jlong,
) -> jstring {
    let result = (|| -> Result<serde_json::Value> {
        let runtime = runtime()?;
        let command: String = env.get_string(&command)?.into();
        let arguments = Zeroizing::new(String::from(env.get_string(&arguments)?));
        if arguments.len() > 131072 {
            bail!("Request too large")
        }
        runtime.executor.block_on(crate::commands::dispatch(
            runtime,
            &command,
            serde_json::from_str(&arguments)?,
            generation,
        ))
    })();
    let response = match result {
        Ok(value) => serde_json::json!({"ok": value}),
        Err(error) => {
            let _ = env.exception_clear();
            let message = if let Some(error) =
                error.downcast_ref::<crate::tunnel::ConnectionFailure>()
            {
                error.0.to_owned()
            } else if let Some(error) = error.downcast_ref::<sirinvpn_core::ManagementError>() {
                match error {
                    sirinvpn_core::ManagementError::RequestRejected { code, .. } => format!(
                        "The VPS rejected the management request ({code:?}). Refresh its current permissions and configuration."
                    ),
                    _ => error.to_string(),
                }
            } else if let Some(error) = error.downcast_ref::<sirinvpn_core::BackupError>() {
                use sirinvpn_core::BackupError::*;
                match error {
                    Io(_)|ProfileStore(_)|SecretStore(_)=>"The encrypted document or protected storage could not be accessed. Select the file again and unlock the device.".to_owned(),
                    _=>error.to_string(),
                }
            } else if let Some(error) = error.downcast_ref::<sirinvpn_core::KeyRotationError>() {
                use sirinvpn_core::KeyRotationError::*;
                match error {
                    InvalidState=>"The key rotation checkpoint is invalid. Preserve the profile and recover from its encrypted backup.".to_owned(),
                    UnsupportedServer=>"Repair or update the VPS before rotating device keys.".to_owned(),
                    Management(_)=>"The private management endpoint could not complete key rotation. Restore connectivity and resume the operation.".to_owned(),
                    Tunnel(_)=>"The replacement tunnel could not be authenticated. Resume key rotation to finish safely.".to_owned(),
                    RecoveryRequired(_)=>"Key rotation is pending. Restore connectivity and resume it before changing or removing this profile.".to_owned(),
                    Secret(_)=>"Unlock the device to access the saved key rotation identities.".to_owned(),
                    _=>"The key rotation checkpoint could not be saved. Preserve the profile and retry.".to_owned(),
                }
            } else if let Some(error) = error.downcast_ref::<sirinvpn_installer::InstallerError>() {
                use sirinvpn_installer::InstallerError::*;
                match error {
                    HostKeyUnknown{..}=>"Review and explicitly trust the SSH fingerprint before continuing.".to_owned(),
                    HostKeyMismatch=>"The SSH host key changed. Stop and verify the new fingerprint independently.".to_owned(),
                    AuthenticationFailed=>"SSH rejected the login. Check the username, password or imported key.".to_owned(),
                    ExistingInstallation|RestoreTargetOccupied=>"The VPS already contains an installation. Review its ownership before explicitly choosing replacement.".to_owned(),
                    UninstallTargetMismatch|RepairTargetMismatch|ServerBackupTargetMismatch|ServerReleaseTargetMismatch|RestoreBackupMismatch=>"The VPS or backup identity does not match this Owner profile. The identity check prevented the operation.".to_owned(),
                    Incompatible(_)=>"The VPS software, configuration or network is incompatible with this operation. Review the network inspection and server requirements.".to_owned(),
                    PhaseFailed{phase,..}=>format!("The VPS operation failed during {phase}. Review the current server state before retrying the same operation."),
                    _=>"The server operation could not finish. Check its inputs and the encrypted file, if applicable.".to_owned(),
                }
            } else {
                "The operation did not complete. Check permissions, credentials and network access. Review the current state before retrying: a server change may already have completed.".to_owned()
            };
            serde_json::json!({"error":message})
        }
    };
    env.new_string(response.to_string())
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_sirinvpn_client_Native_stopTransport(_: JNIEnv, _: JObject) {
    if let Ok(runtime) = runtime() {
        crate::tunnel::stop_relay(runtime);
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_sirinvpn_client_Native_generation(
    _: JNIEnv,
    _: JObject,
    generation: jlong,
) {
    if let Ok(runtime) = runtime() {
        runtime
            .generation
            .store(generation, std::sync::atomic::Ordering::SeqCst);
    }
}
