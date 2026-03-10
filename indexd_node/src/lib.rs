#[macro_use]
extern crate napi_derive;

use std::collections::HashMap;
use std::io::Cursor;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll};
use std::time::SystemTime;

use indexd::Url;
use indexd::app_client::{RegisterAppRequest, RegisterAppResponse};
use napi::bindgen_prelude::*;
use sia::rhp::SECTOR_SIZE;
use sia::seed::Seed;
use sia::signing::{PrivateKey, PublicKey, Signature};
use sia::types::Hash256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::{self, Runtime};
use tokio::sync::{mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create global runtime")
});

fn spawn<F, T>(future: F) -> AbortOnDropHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    AbortOnDropHandle::new(RUNTIME.spawn(future))
}

fn tls_config() -> rustls::ClientConfig {
    use rustls_platform_verifier::ConfigVerifierExt;
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    rustls::ClientConfig::with_platform_verifier().expect("failed to create tls config")
}

fn system_time_to_epoch_ms(t: SystemTime) -> f64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}

fn epoch_ms_to_system_time(ms: f64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms as u64)
}

// -- NativeAppKey --

#[napi]
pub struct NativeAppKey {
    key: PrivateKey,
}

#[napi]
impl NativeAppKey {
    #[napi(constructor)]
    pub fn new(key: Buffer) -> Result<Self> {
        let bytes = key.as_ref();
        match bytes.len() {
            64 => {
                let mut keypair = [0u8; 64];
                keypair.copy_from_slice(bytes);
                Ok(NativeAppKey {
                    key: PrivateKey::from(keypair),
                })
            }
            32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(bytes);
                Ok(NativeAppKey {
                    key: PrivateKey::from_seed(&seed),
                })
            }
            _ => Err(Error::from_reason(
                "app key must be 64 bytes (keypair) or 32 bytes (seed)",
            )),
        }
    }

    #[napi]
    pub fn export(&self) -> Buffer {
        Buffer::from(self.key.as_ref().to_vec())
    }

    #[napi(js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.key.public_key().to_string()
    }

    #[napi]
    pub fn sign(&self, message: Buffer) -> Buffer {
        let sig = self.key.sign(message.as_ref());
        Buffer::from(sig.as_ref().to_vec())
    }

    #[napi(js_name = "verifySignature")]
    pub fn verify_signature(&self, message: Buffer, signature: Buffer) -> Result<bool> {
        let sig_bytes = signature.as_ref();
        if sig_bytes.len() != 64 {
            return Err(Error::from_reason("signatures must be 64 bytes"));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(sig_bytes);
        Ok(self
            .key
            .public_key()
            .verify(message.as_ref(), &Signature::from(sig)))
    }
}

// -- NativePinnedObject --

#[napi]
pub struct NativePinnedObject {
    inner: Arc<Mutex<indexd::Object>>,
}

#[napi]
impl NativePinnedObject {
    #[napi(factory)]
    pub fn open(app_key: &NativeAppKey, sealed_json: String) -> Result<Self> {
        let sealed: SealedObjectJson =
            serde_json::from_str(&sealed_json).map_err(|e| Error::from_reason(e.to_string()))?;
        let indexd_sealed = sealed
            .to_indexd()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let obj = indexd_sealed
            .open(&app_key.key)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(NativePinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    #[napi]
    pub fn seal(&self, app_key: &NativeAppKey) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        let sealed = inner.seal(&app_key.key);
        let json = SealedObjectJson::from_indexd(sealed);
        serde_json::to_string(&json).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn id(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.id().to_string()
    }

    #[napi]
    pub fn size(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        inner.size() as f64
    }

    #[napi(js_name = "slabCount")]
    pub fn slab_count(&self) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.slabs().len() as u32
    }

    #[napi]
    pub fn slabs(&self) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        let slabs: Vec<SlabJson> = inner
            .slabs()
            .iter()
            .cloned()
            .map(SlabJson::from_indexd)
            .collect();
        serde_json::to_string(&slabs).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn metadata(&self) -> Buffer {
        let inner = self.inner.lock().unwrap();
        Buffer::from(inner.metadata.clone())
    }

    #[napi(js_name = "updateMetadata")]
    pub fn update_metadata(&mut self, metadata: Buffer) {
        let mut inner = self.inner.lock().unwrap();
        inner.metadata = metadata.to_vec();
    }

    #[napi(js_name = "createdAt")]
    pub fn created_at(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        system_time_to_epoch_ms((*inner.created_at()).into())
    }

    #[napi(js_name = "updatedAt")]
    pub fn updated_at(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        system_time_to_epoch_ms((*inner.updated_at()).into())
    }

    #[napi(js_name = "slabLengths")]
    pub fn slab_lengths(&self) -> Vec<u32> {
        let inner = self.inner.lock().unwrap();
        inner.slabs().iter().map(|s| s.length).collect()
    }
}

impl NativePinnedObject {
    fn object(&self) -> indexd::Object {
        self.inner.lock().unwrap().clone()
    }

    fn from_object(obj: indexd::Object) -> Self {
        NativePinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        }
    }
}

// -- NativeObjectEvent --

#[napi]
pub struct NativeObjectEvent {
    event_id: String,
    event_deleted: bool,
    event_updated_at: f64,
    event_object: Option<Arc<Mutex<indexd::Object>>>,
}

#[napi]
impl NativeObjectEvent {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.event_id.clone()
    }

    #[napi(getter)]
    pub fn deleted(&self) -> bool {
        self.event_deleted
    }

    #[napi(getter, js_name = "updatedAt")]
    pub fn updated_at(&self) -> f64 {
        self.event_updated_at
    }

    #[napi(getter)]
    pub fn object(&self) -> Option<NativePinnedObject> {
        self.event_object.as_ref().map(|obj| NativePinnedObject {
            inner: obj.clone(),
        })
    }
}

// -- JSON serialization helpers --

#[derive(serde::Serialize, serde::Deserialize)]
struct SectorJson {
    root: String,
    #[serde(rename = "hostKey")]
    host_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SlabJson {
    #[serde(rename = "encryptionKey")]
    encryption_key: String,
    #[serde(rename = "minShards")]
    min_shards: u8,
    sectors: Vec<SectorJson>,
    offset: u32,
    length: u32,
}

impl SlabJson {
    fn from_indexd(s: indexd::Slab) -> Self {
        use base64::Engine;
        SlabJson {
            encryption_key: base64::engine::general_purpose::STANDARD
                .encode(s.encryption_key.as_ref()),
            min_shards: s.min_shards,
            sectors: s
                .sectors
                .into_iter()
                .map(|sec| SectorJson {
                    root: sec.root.to_string(),
                    host_key: sec.host_key.to_string(),
                })
                .collect(),
            offset: s.offset,
            length: s.length,
        }
    }

    fn to_indexd(&self) -> std::result::Result<indexd::Slab, String> {
        use base64::Engine;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.encryption_key)
            .map_err(|e| e.to_string())?;
        Ok(indexd::Slab {
            encryption_key: sia::encryption::EncryptionKey::try_from(key_bytes.as_slice())?,
            min_shards: self.min_shards,
            sectors: self
                .sectors
                .iter()
                .map(|sec| {
                    Ok(indexd::Sector {
                        root: Hash256::from_str(&sec.root).map_err(|e| e.to_string())?,
                        host_key: PublicKey::from_str(&sec.host_key).map_err(|e| e.to_string())?,
                    })
                })
                .collect::<std::result::Result<Vec<_>, String>>()?,
            offset: self.offset,
            length: self.length,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedObjectJson {
    id: String,
    #[serde(rename = "encryptedDataKey")]
    encrypted_data_key: String,
    #[serde(rename = "encryptedMetadataKey")]
    encrypted_metadata_key: String,
    slabs: Vec<SlabJson>,
    #[serde(rename = "encryptedMetadata")]
    encrypted_metadata: String,
    #[serde(rename = "dataSignature")]
    data_signature: String,
    #[serde(rename = "metadataSignature")]
    metadata_signature: String,
    #[serde(rename = "createdAt")]
    created_at: f64,
    #[serde(rename = "updatedAt")]
    updated_at: f64,
}

impl SealedObjectJson {
    fn from_indexd(s: indexd::SealedObject) -> Self {
        use base64::Engine;
        let engine = &base64::engine::general_purpose::STANDARD;
        SealedObjectJson {
            id: s.id().to_string(),
            encrypted_data_key: engine.encode(&s.encrypted_data_key),
            encrypted_metadata_key: engine.encode(&s.encrypted_metadata_key),
            slabs: s.slabs.into_iter().map(SlabJson::from_indexd).collect(),
            encrypted_metadata: engine.encode(&s.encrypted_metadata),
            data_signature: engine.encode(s.data_signature.as_ref()),
            metadata_signature: engine.encode(s.metadata_signature.as_ref()),
            created_at: system_time_to_epoch_ms(s.created_at.into()),
            updated_at: system_time_to_epoch_ms(s.updated_at.into()),
        }
    }

    fn to_indexd(&self) -> std::result::Result<indexd::SealedObject, String> {
        use base64::Engine;
        let engine = &base64::engine::general_purpose::STANDARD;
        let data_sig_bytes = engine
            .decode(&self.data_signature)
            .map_err(|e| e.to_string())?;
        let meta_sig_bytes = engine
            .decode(&self.metadata_signature)
            .map_err(|e| e.to_string())?;
        Ok(indexd::SealedObject {
            encrypted_data_key: engine
                .decode(&self.encrypted_data_key)
                .map_err(|e| e.to_string())?,
            encrypted_metadata_key: engine
                .decode(&self.encrypted_metadata_key)
                .map_err(|e| e.to_string())?,
            slabs: self
                .slabs
                .iter()
                .map(|s| s.to_indexd())
                .collect::<std::result::Result<Vec<_>, _>>()?,
            encrypted_metadata: engine
                .decode(&self.encrypted_metadata)
                .map_err(|e| e.to_string())?,
            data_signature: Signature::try_from(data_sig_bytes.as_ref())
                .map_err(|e| e.to_string())?,
            metadata_signature: Signature::try_from(meta_sig_bytes.as_ref())
                .map_err(|e| e.to_string())?,
            created_at: epoch_ms_to_system_time(self.created_at).into(),
            updated_at: epoch_ms_to_system_time(self.updated_at).into(),
        })
    }
}

// -- NativeUploadOptions / NativeDownloadOptions --

#[napi(object)]
pub struct NativeUploadOptions {
    pub data_shards: Option<u32>,
    pub parity_shards: Option<u32>,
    pub max_inflight: Option<u32>,
}

#[napi(object)]
pub struct NativeDownloadOptions {
    pub max_inflight: Option<u32>,
}

// -- NativePackedUpload --

enum PackedUploadAction {
    Add(Vec<u8>, oneshot::Sender<std::result::Result<u64, String>>),
    Finalize(oneshot::Sender<std::result::Result<Vec<indexd::Object>, String>>),
}

#[napi]
pub struct NativePackedUpload {
    upload_task: Mutex<Option<AbortOnDropHandle<()>>>,
    tx: mpsc::Sender<PackedUploadAction>,
    slab_size: u64,
    length: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

#[napi]
impl NativePackedUpload {
    #[napi]
    pub fn remaining(&self) -> BigInt {
        let length = self.length.load(Ordering::Acquire);
        let r = if length == 0 {
            self.slab_size
        } else {
            (self.slab_size - (length % self.slab_size)) % self.slab_size
        };
        BigInt::from(r)
    }

    #[napi]
    pub fn length(&self) -> BigInt {
        BigInt::from(self.length.load(Ordering::Acquire))
    }

    #[napi]
    pub fn slabs(&self) -> BigInt {
        let len = self.length.load(Ordering::Acquire);
        BigInt::from(len.div_ceil(self.slab_size))
    }

    #[napi]
    pub async fn add(&self, data: Buffer) -> Result<BigInt> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::from_reason("packed upload is closed"));
        }
        let tx = self.tx.clone();
        let bytes = data.to_vec();
        let (add_tx, add_rx) = oneshot::channel();
        tx.send(PackedUploadAction::Add(bytes, add_tx))
            .await
            .map_err(|_| Error::from_reason("packed upload channel closed"))?;
        let written = add_rx
            .await
            .map_err(|_| Error::from_reason("packed upload result channel closed"))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(BigInt::from(written))
    }

    #[napi]
    pub async fn finalize(&self) -> Result<Vec<NativePinnedObject>> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(Error::from_reason("packed upload is closed"));
        }
        let tx = self.tx.clone();
        let (finalize_tx, finalize_rx) = oneshot::channel();
        tx.send(PackedUploadAction::Finalize(finalize_tx))
            .await
            .map_err(|_| Error::from_reason("packed upload channel closed"))?;
        let objects = finalize_rx
            .await
            .map_err(|_| Error::from_reason("packed upload result channel closed"))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(objects
            .into_iter()
            .map(NativePinnedObject::from_object)
            .collect())
    }

    #[napi]
    pub async fn cancel(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(Error::from_reason("packed upload is closed"));
        }
        if let Some(task) = self.upload_task.lock().unwrap().take() {
            task.abort();
        }
        Ok(())
    }
}

// -- Builder state machine --

enum BuilderState {
    Disconnected(indexd::Builder<indexd::DisconnectedState>),
    RequestingApproval(indexd::Builder<indexd::RequestingApprovalState>),
    Approved(indexd::Builder<indexd::ApprovedState>),
    Finalized,
}

#[napi]
pub struct NativeBuilder {
    state: Arc<Mutex<Option<BuilderState>>>,
}

#[napi]
impl NativeBuilder {
    #[napi(constructor)]
    pub fn new(indexer_url: String) -> Result<Self> {
        let builder =
            indexd::Builder::new(indexer_url).map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(NativeBuilder {
            state: Arc::new(Mutex::new(Some(BuilderState::Disconnected(builder)))),
        })
    }

    #[napi(js_name = "requestConnection")]
    pub async fn request_connection(&self, app_meta_json: String) -> Result<()> {
        #[derive(serde::Deserialize)]
        struct AppMetaInput {
            #[serde(rename = "appID")]
            id: String,
            name: String,
            description: String,
            #[serde(rename = "serviceURL")]
            service_url: String,
            #[serde(rename = "logoURL")]
            logo_url: Option<String>,
            #[serde(rename = "callbackURL")]
            callback_url: Option<String>,
        }
        let meta: AppMetaInput =
            serde_json::from_str(&app_meta_json).map_err(|e| Error::from_reason(e.to_string()))?;

        let app_id =
            Hash256::from_str(&meta.id).map_err(|e| Error::from_reason(e.to_string()))?;

        let state_arc = self.state.clone();
        let state = {
            state_arc
                .lock()
                .map_err(|_| Error::from_reason("mutex poisoned"))?
                .take()
        };
        match state {
            Some(BuilderState::Disconnected(builder)) => {
                let builder = spawn(async move {
                    builder
                        .request_connection(&RegisterAppRequest {
                            app_id,
                            name: meta.name,
                            description: meta.description,
                            service_url: Url::parse(&meta.service_url)
                                .map_err(|e| format!("invalid service url: {e}"))?,
                            logo_url: meta
                                .logo_url
                                .map(|s| {
                                    Url::parse(&s).map_err(|e| format!("invalid logo url: {e}"))
                                })
                                .transpose()?,
                            callback_url: meta
                                .callback_url
                                .map(|s| {
                                    Url::parse(&s)
                                        .map_err(|e| format!("invalid callback url: {e}"))
                                })
                                .transpose()?,
                        })
                        .await
                        .map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?
                .map_err(|e| Error::from_reason(e))?;
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? =
                    Some(BuilderState::RequestingApproval(builder));
                Ok(())
            }
            other => {
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? = other;
                Err(Error::from_reason("invalid state for requestConnection"))
            }
        }
    }

    #[napi(js_name = "responseUrl")]
    pub fn response_url(&self) -> Result<String> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::from_reason("mutex poisoned"))?;
        match state.as_ref() {
            Some(BuilderState::RequestingApproval(builder)) => {
                Ok(builder.response_url().to_owned())
            }
            _ => Err(Error::from_reason("invalid state for responseUrl")),
        }
    }

    #[napi(js_name = "setConnectionResponse")]
    pub fn set_connection_response(
        &self,
        app_id_hex: String,
        response_json: String,
    ) -> Result<()> {
        let app_id =
            Hash256::from_str(&app_id_hex).map_err(|e| Error::from_reason(e.to_string()))?;
        let response: RegisterAppResponse = serde_json::from_str(&response_json)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::from_reason("mutex poisoned"))?;
        let current = state.take();
        match current {
            Some(BuilderState::Disconnected(builder)) => {
                let builder = builder
                    .with_connection_response(app_id, response)
                    .map_err(|e| Error::from_reason(e.to_string()))?;
                *state = Some(BuilderState::RequestingApproval(builder));
                Ok(())
            }
            other => {
                *state = other;
                Err(Error::from_reason(
                    "invalid state for setConnectionResponse: expected Disconnected",
                ))
            }
        }
    }

    #[napi(js_name = "waitForApproval")]
    pub async fn wait_for_approval(&self) -> Result<()> {
        let state_arc = self.state.clone();
        let state = {
            state_arc
                .lock()
                .map_err(|_| Error::from_reason("mutex poisoned"))?
                .take()
        };
        match state {
            Some(BuilderState::RequestingApproval(builder)) => {
                let builder = spawn(async move {
                    builder
                        .wait_for_approval()
                        .await
                        .map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?
                .map_err(|e| Error::from_reason(e))?;
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? =
                    Some(BuilderState::Approved(builder));
                Ok(())
            }
            other => {
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? = other;
                Err(Error::from_reason("invalid state for waitForApproval"))
            }
        }
    }

    #[napi]
    pub async fn connected(&self, app_key: &NativeAppKey) -> Result<Option<NativeSDK>> {
        let state_arc = self.state.clone();
        let state = {
            state_arc
                .lock()
                .map_err(|_| Error::from_reason("mutex poisoned"))?
                .take()
        };
        match state {
            Some(BuilderState::Disconnected(builder)) => {
                let rustls_config = tls_config();
                let key = app_key.key.clone();
                let (result, builder) = spawn(async move {
                    let result = builder
                        .connected(&key, rustls_config)
                        .await
                        .map_err(|e| e.to_string());
                    (result, builder)
                })
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?;
                let result = result.map_err(|e| Error::from_reason(e))?;

                match result {
                    Some(sdk) => {
                        *state_arc
                            .lock()
                            .map_err(|_| Error::from_reason("mutex poisoned"))? =
                            Some(BuilderState::Finalized);
                        Ok(Some(NativeSDK { inner: sdk }))
                    }
                    None => {
                        *state_arc
                            .lock()
                            .map_err(|_| Error::from_reason("mutex poisoned"))? =
                            Some(BuilderState::Disconnected(builder));
                        Ok(None)
                    }
                }
            }
            other => {
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? = other;
                Err(Error::from_reason("invalid state for connected"))
            }
        }
    }

    #[napi]
    pub async fn register(&self, mnemonic: String) -> Result<NativeSDK> {
        let state_arc = self.state.clone();
        let state = {
            state_arc
                .lock()
                .map_err(|_| Error::from_reason("mutex poisoned"))?
                .take()
        };
        match state {
            Some(BuilderState::Approved(builder)) => {
                let rustls_config = tls_config();
                let sdk = spawn(async move {
                    builder
                        .register(&mnemonic, rustls_config)
                        .await
                        .map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?
                .map_err(|e| Error::from_reason(e))?;
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? =
                    Some(BuilderState::Finalized);
                Ok(NativeSDK { inner: sdk })
            }
            other => {
                *state_arc
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? = other;
                Err(Error::from_reason("invalid state for register"))
            }
        }
    }
}

// -- UploadTask (async task for upload with progress callback) --

pub struct UploadTask {
    sdk: indexd::SDK,
    data: Vec<u8>,
    data_shards: u8,
    parity_shards: u8,
    max_inflight: usize,
    tsfn: napi::threadsafe_function::ThreadsafeFunction<
        (u64, u64),
        napi::threadsafe_function::ErrorStrategy::Fatal,
    >,
}

impl Task for UploadTask {
    type Output = indexd::Object;
    type JsValue = NativePinnedObject;

    fn compute(&mut self) -> Result<Self::Output> {
        let sdk = self.sdk.clone();
        let reader = Cursor::new(std::mem::take(&mut self.data));
        let data_shards = self.data_shards;
        let parity_shards = self.parity_shards;
        let max_inflight = self.max_inflight;

        let total_shards = data_shards as u64 + parity_shards as u64;
        let slab_encoded_size = total_shards * SECTOR_SIZE as u64;
        let tsfn = self.tsfn.clone();

        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<()>();
        RUNTIME.spawn(async move {
            let mut sectors: u64 = 0;
            while progress_rx.recv().await.is_some() {
                sectors += 1;
                let size = sectors * SECTOR_SIZE as u64;
                let slabs_size = sectors.div_ceil(total_shards) * slab_encoded_size;
                tsfn.call(
                    (size, slabs_size),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
            }
        });

        RUNTIME
            .block_on(async move {
                sdk.upload(
                    reader,
                    indexd::UploadOptions {
                        max_inflight,
                        data_shards,
                        parity_shards,
                        shard_uploaded: Some(progress_tx),
                    },
                )
                .await
                .map_err(|e| Error::from_reason(e.to_string()))
            })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(NativePinnedObject::from_object(output))
    }
}

// -- DownloadTask --

pub struct DownloadTask {
    sdk: indexd::SDK,
    obj: indexd::Object,
    max_inflight: usize,
    offset: u64,
    length: Option<u64>,
    progress_tsfn: Option<
        napi::threadsafe_function::ThreadsafeFunction<
            (u32, u32),
            napi::threadsafe_function::ErrorStrategy::Fatal,
        >,
    >,
    sector_tsfn: Option<
        napi::threadsafe_function::ThreadsafeFunction<
            String,
            napi::threadsafe_function::ErrorStrategy::Fatal,
        >,
    >,
}

impl Task for DownloadTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        let sdk = self.sdk.clone();
        let obj = self.obj.clone();
        let max_inflight = self.max_inflight;
        let offset = self.offset;
        let length = self.length;
        let total_slabs = obj.slabs().len() as u32;

        let slab_downloaded = if let Some(tsfn) = self.progress_tsfn.take() {
            let (tx, mut rx) = mpsc::unbounded_channel();
            RUNTIME.spawn(async move {
                let mut count: u32 = 0;
                while rx.recv().await.is_some() {
                    count += 1;
                    tsfn.call(
                        (count, total_slabs),
                        napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                    );
                }
            });
            Some(tx)
        } else {
            None
        };

        let sector_downloaded = if let Some(tsfn) = self.sector_tsfn.take() {
            let (tx, mut rx) = mpsc::unbounded_channel::<PublicKey>();
            RUNTIME.spawn(async move {
                while let Some(host_key) = rx.recv().await {
                    tsfn.call(
                        host_key.to_string(),
                        napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                    );
                }
            });
            Some(tx)
        } else {
            None
        };

        RUNTIME.block_on(async move {
            let mut buf = Vec::new();
            sdk.download(
                &mut buf,
                &obj,
                indexd::DownloadOptions {
                    offset,
                    length,
                    max_inflight,
                    slab_downloaded,
                    sector_downloaded,
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok(buf)
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(Buffer::from(output))
    }
}

// -- DownloadStreamingTask --

pub struct DownloadStreamingTask {
    sdk: indexd::SDK,
    obj: indexd::Object,
    max_inflight: usize,
    chunk_tsfn: napi::threadsafe_function::ThreadsafeFunction<
        Vec<u8>,
        napi::threadsafe_function::ErrorStrategy::Fatal,
    >,
    progress_tsfn: napi::threadsafe_function::ThreadsafeFunction<
        (u32, u32),
        napi::threadsafe_function::ErrorStrategy::Fatal,
    >,
}

/// Custom AsyncWrite that calls a threadsafe function with each chunk
struct ChunkWriter {
    tsfn: napi::threadsafe_function::ThreadsafeFunction<
        Vec<u8>,
        napi::threadsafe_function::ErrorStrategy::Fatal,
    >,
}

impl AsyncWrite for ChunkWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.tsfn.call(
            buf.to_vec(),
            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
        );
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Task for DownloadStreamingTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        let sdk = self.sdk.clone();
        let obj = self.obj.clone();
        let max_inflight = self.max_inflight;
        let total_slabs = obj.slabs().len() as u32;
        let progress_tsfn = self.progress_tsfn.clone();

        let (slab_tx, mut slab_rx) = mpsc::unbounded_channel();
        RUNTIME.spawn(async move {
            let mut count: u32 = 0;
            while slab_rx.recv().await.is_some() {
                count += 1;
                progress_tsfn.call(
                    (count, total_slabs),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
            }
        });

        let mut writer = ChunkWriter {
            tsfn: self.chunk_tsfn.clone(),
        };

        RUNTIME.block_on(async move {
            sdk.download(
                &mut writer,
                &obj,
                indexd::DownloadOptions {
                    offset: 0,
                    length: None,
                    max_inflight,
                    slab_downloaded: Some(slab_tx),
                    sector_downloaded: None,
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
        })
    }

    fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
        Ok(())
    }
}

// -- UploadSlabTask --

pub struct UploadSlabTask {
    sdk: indexd::SDK,
    data: Vec<u8>,
    data_key_bytes: Vec<u8>,
    stream_offset: u64,
    data_shards: u8,
    parity_shards: u8,
    max_inflight: usize,
    tsfn: napi::threadsafe_function::ThreadsafeFunction<
        (u64, u64),
        napi::threadsafe_function::ErrorStrategy::Fatal,
    >,
}

impl Task for UploadSlabTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let sdk = self.sdk.clone();
        let data = std::mem::take(&mut self.data);
        let key_bytes = std::mem::take(&mut self.data_key_bytes);
        let encryption_key = sia::encryption::EncryptionKey::try_from(key_bytes.as_slice())
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let offset = self.stream_offset;
        let data_shards = self.data_shards;
        let parity_shards = self.parity_shards;
        let max_inflight = self.max_inflight;
        let total_shards = data_shards as u64 + parity_shards as u64;
        let tsfn = self.tsfn.clone();

        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<()>();
        RUNTIME.spawn(async move {
            let mut count: u64 = 0;
            while progress_rx.recv().await.is_some() {
                count += 1;
                tsfn.call(
                    (count, total_shards),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
            }
        });

        let slab = RUNTIME.block_on(async move {
            sdk.upload_slab_raw(
                &data,
                &encryption_key,
                offset,
                indexd::UploadOptions {
                    max_inflight,
                    data_shards,
                    parity_shards,
                    shard_uploaded: Some(progress_tx),
                },
            )
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
        })?;

        let slab_json = SlabJson::from_indexd(slab);
        serde_json::to_string(&slab_json).map_err(|e| Error::from_reason(e.to_string()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

// -- ChannelReader (AsyncRead adapter for streaming uploads) --

struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        ChannelReader {
            rx,
            buffer: Vec::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Return buffered data from previous chunk
        if this.pos < this.buffer.len() {
            let n = std::cmp::min(buf.remaining(), this.buffer.len() - this.pos);
            buf.put_slice(&this.buffer[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }

        // Receive next chunk
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.buffer = data;
                    this.pos = n;
                } else {
                    this.buffer.clear();
                    this.pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

// -- NativeStreamingUpload --

#[napi]
pub struct NativeStreamingUpload {
    tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    result: Mutex<Option<oneshot::Receiver<std::result::Result<indexd::Object, String>>>>,
    #[allow(dead_code)]
    upload_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

#[napi]
impl NativeStreamingUpload {
    #[napi(js_name = "pushChunk")]
    pub async fn push_chunk(&self, data: Option<Buffer>) -> Result<()> {
        match data {
            Some(buf) => {
                let tx = {
                    let guard = self.tx.lock().unwrap();
                    guard
                        .as_ref()
                        .ok_or_else(|| Error::from_reason("upload already closed"))?
                        .clone()
                };
                let bytes = buf.to_vec();
                spawn(async move {
                    tx.send(bytes)
                        .await
                        .map_err(|_| "upload channel closed".to_string())
                })
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?
                .map_err(|e| Error::from_reason(e))?;
            }
            None => {
                // Drop sender to signal EOF
                self.tx.lock().unwrap().take();
            }
        }
        Ok(())
    }

    #[napi]
    pub async fn promise(&self) -> Result<NativePinnedObject> {
        let rx = self
            .result
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Error::from_reason("promise already consumed"))?;
        let obj = spawn(async move { rx.await.map_err(|_| "upload task dropped".to_string()) })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .map_err(|e| Error::from_reason(e))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(NativePinnedObject::from_object(obj))
    }
}

// -- Chunked upload session storage --

static CHUNK_BUFFERS: LazyLock<Mutex<HashMap<u64, (Vec<u8>, usize)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

// -- NativeSDK --

#[napi]
pub struct NativeSDK {
    inner: indexd::SDK,
}

#[napi]
impl NativeSDK {
    #[napi(js_name = "appKey")]
    pub fn app_key(&self) -> NativeAppKey {
        let pk = self.inner.app_key().clone();
        NativeAppKey { key: pk }
    }

    #[napi(js_name = "objectEvents")]
    pub async fn object_events(
        &self,
        cursor_json: Option<String>,
        limit: u32,
    ) -> Result<Vec<NativeObjectEvent>> {
        let cursor = match cursor_json {
            Some(json) => {
                #[derive(serde::Deserialize)]
                struct CursorInput {
                    id: String,
                    after: f64,
                }
                let c: CursorInput = serde_json::from_str(&json)
                    .map_err(|e| Error::from_reason(e.to_string()))?;
                Some(indexd::app_client::ObjectsCursor {
                    id: Hash256::from_str(&c.id).map_err(|e| Error::from_reason(e.to_string()))?,
                    after: epoch_ms_to_system_time(c.after).into(),
                })
            }
            None => None,
        };
        let sdk = self.inner.clone();
        let events = spawn(async move {
            sdk.object_events(cursor, Some(limit as usize))
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?
        .map_err(|e| Error::from_reason(e))?;

        Ok(events
            .into_iter()
            .map(|e| NativeObjectEvent {
                event_id: e.id.to_string(),
                event_deleted: e.deleted,
                event_updated_at: system_time_to_epoch_ms(e.updated_at.into()),
                event_object: e.object.map(|o| Arc::new(Mutex::new(o))),
            })
            .collect())
    }

    #[napi]
    pub async fn object(&self, key: String) -> Result<NativePinnedObject> {
        let key = Hash256::from_str(&key).map_err(|e| Error::from_reason(e.to_string()))?;
        let sdk = self.inner.clone();
        let obj = spawn(async move { sdk.object(&key).await.map_err(|e| e.to_string()) })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(NativePinnedObject::from_object(obj))
    }

    #[napi(
        js_name = "upload",
        ts_args_type = "data: Buffer, options: NativeUploadOptions, onProgress: (current: number, total: number) => void",
        ts_return_type = "Promise<NativePinnedObject>"
    )]
    pub fn upload(&self, data: Buffer, options: NativeUploadOptions, on_progress: JsFunction) -> Result<AsyncTask<UploadTask>> {
        let data_shards = options.data_shards.unwrap_or(10) as u8;
        let parity_shards = options.parity_shards.unwrap_or(20) as u8;
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let tsfn: napi::threadsafe_function::ThreadsafeFunction<
            (u64, u64),
            napi::threadsafe_function::ErrorStrategy::Fatal,
        > = on_progress.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(u64, u64)>| {
                let current = ctx.env.create_double(ctx.value.0 as f64)?;
                let total = ctx.env.create_double(ctx.value.1 as f64)?;
                Ok(vec![current, total])
            },
        )?;

        Ok(AsyncTask::new(UploadTask {
            sdk: self.inner.clone(),
            data: data.to_vec(),
            data_shards,
            parity_shards,
            max_inflight,
            tsfn,
        }))
    }

    #[napi(js_name = "uploadPacked")]
    pub fn upload_packed(&self, options: NativeUploadOptions) -> NativePackedUpload {
        let data_shards = options.data_shards.unwrap_or(10) as u8;
        let parity_shards = options.parity_shards.unwrap_or(20) as u8;
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let sdk = self.inner.clone();
        let (action_tx, mut action_rx) = mpsc::channel::<PackedUploadAction>(10);
        let slab_size = data_shards as u64 * SECTOR_SIZE as u64;
        let length = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicBool::new(false));

        let task_length = length.clone();
        let upload_task = spawn(async move {
            let mut packed_upload = sdk.upload_packed(indexd::UploadOptions {
                max_inflight,
                data_shards,
                parity_shards,
                shard_uploaded: None,
            });

            while let Some(action) = action_rx.recv().await {
                match action {
                    PackedUploadAction::Add(data, add_tx) => {
                        let reader = Cursor::new(data);
                        let res = packed_upload.add(reader).await.map_err(|e| e.to_string());
                        if let Ok(size) = &res {
                            task_length.fetch_add(*size, Ordering::AcqRel);
                        }
                        let _ = add_tx.send(res);
                    }
                    PackedUploadAction::Finalize(finalize_tx) => {
                        let result = packed_upload.finalize().await.map_err(|e| e.to_string());
                        let _ = finalize_tx.send(result);
                        return;
                    }
                }
            }
        });

        NativePackedUpload {
            upload_task: Mutex::new(Some(upload_task)),
            tx: action_tx,
            slab_size,
            length,
            closed,
        }
    }

    #[napi(
        js_name = "uploadSlab",
        ts_args_type = "data: Buffer, dataKey: Buffer, offset: number, options: NativeUploadOptions, onProgress: (current: number, total: number) => void",
        ts_return_type = "Promise<string>"
    )]
    pub fn upload_slab(
        &self,
        data: Buffer,
        data_key: Buffer,
        offset: u32,
        options: NativeUploadOptions,
        on_progress: JsFunction,
    ) -> Result<AsyncTask<UploadSlabTask>> {
        let data_shards = options.data_shards.unwrap_or(10) as u8;
        let parity_shards = options.parity_shards.unwrap_or(20) as u8;
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let tsfn: napi::threadsafe_function::ThreadsafeFunction<
            (u64, u64),
            napi::threadsafe_function::ErrorStrategy::Fatal,
        > = on_progress.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(u64, u64)>| {
                let current = ctx.env.create_double(ctx.value.0 as f64)?;
                let total = ctx.env.create_double(ctx.value.1 as f64)?;
                Ok(vec![current, total])
            },
        )?;

        Ok(AsyncTask::new(UploadSlabTask {
            sdk: self.inner.clone(),
            data: data.to_vec(),
            data_key_bytes: data_key.to_vec(),
            stream_offset: offset as u64,
            data_shards,
            parity_shards,
            max_inflight,
            tsfn,
        }))
    }

    #[napi(
        js_name = "download",
        ts_args_type = "object: NativePinnedObject, options: NativeDownloadOptions, onProgress: (current: number, total: number) => void, onSector: (hostKey: string) => void",
        ts_return_type = "Promise<Buffer>"
    )]
    pub fn download(
        &self,
        object: &NativePinnedObject,
        options: NativeDownloadOptions,
        on_progress: JsFunction,
        on_sector: JsFunction,
    ) -> Result<AsyncTask<DownloadTask>> {
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let progress_tsfn = on_progress.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(u32, u32)>| {
                let current = ctx.env.create_double(ctx.value.0 as f64)?;
                let total = ctx.env.create_double(ctx.value.1 as f64)?;
                Ok(vec![current, total])
            },
        )?;

        let sector_tsfn = on_sector.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<String>| {
                let key = ctx.env.create_string(&ctx.value)?;
                Ok(vec![key])
            },
        )?;

        Ok(AsyncTask::new(DownloadTask {
            sdk: self.inner.clone(),
            obj: object.object(),
            max_inflight,
            offset: 0,
            length: None,
            progress_tsfn: Some(progress_tsfn),
            sector_tsfn: Some(sector_tsfn),
        }))
    }

    #[napi(
        js_name = "downloadRange",
        ts_args_type = "object: NativePinnedObject, offset: number, length: number, options: NativeDownloadOptions, onSector: (hostKey: string) => void",
        ts_return_type = "Promise<Buffer>"
    )]
    pub fn download_range(
        &self,
        object: &NativePinnedObject,
        offset: f64,
        length: f64,
        options: NativeDownloadOptions,
        on_sector: JsFunction,
    ) -> Result<AsyncTask<DownloadTask>> {
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let sector_tsfn = on_sector.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<String>| {
                let key = ctx.env.create_string(&ctx.value)?;
                Ok(vec![key])
            },
        )?;

        Ok(AsyncTask::new(DownloadTask {
            sdk: self.inner.clone(),
            obj: object.object(),
            max_inflight,
            offset: offset as u64,
            length: Some(length as u64),
            progress_tsfn: None,
            sector_tsfn: Some(sector_tsfn),
        }))
    }

    #[napi(
        js_name = "downloadStreaming",
        ts_args_type = "object: NativePinnedObject, options: NativeDownloadOptions, onChunk: (data: Buffer) => void, onProgress: (current: number, total: number) => void",
        ts_return_type = "Promise<void>"
    )]
    pub fn download_streaming(
        &self,
        object: &NativePinnedObject,
        options: NativeDownloadOptions,
        on_chunk: JsFunction,
        on_progress: JsFunction,
    ) -> Result<AsyncTask<DownloadStreamingTask>> {
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let chunk_tsfn = on_chunk.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<Vec<u8>>| {
                let buf = ctx.env.create_buffer_with_data(ctx.value)?;
                Ok(vec![buf.into_raw()])
            },
        )?;

        let progress_tsfn = on_progress.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(u32, u32)>| {
                let current = ctx.env.create_double(ctx.value.0 as f64)?;
                let total = ctx.env.create_double(ctx.value.1 as f64)?;
                Ok(vec![current, total])
            },
        )?;

        Ok(AsyncTask::new(DownloadStreamingTask {
            sdk: self.inner.clone(),
            obj: object.object(),
            max_inflight,
            chunk_tsfn,
            progress_tsfn,
        }))
    }

    #[napi(
        js_name = "downloadSlabByIndex",
        ts_args_type = "object: NativePinnedObject, index: number, options: NativeDownloadOptions, onSector: (hostKey: string) => void",
        ts_return_type = "Promise<Buffer>"
    )]
    pub fn download_slab_by_index(
        &self,
        object: &NativePinnedObject,
        index: u32,
        options: NativeDownloadOptions,
        on_sector: JsFunction,
    ) -> Result<AsyncTask<DownloadTask>> {
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;
        let obj = object.object();
        let slabs = obj.slabs();
        let slab = slabs
            .get(index as usize)
            .ok_or_else(|| Error::from_reason(format!("slab index {} out of range", index)))?;
        let slab_offset = slab.offset as u64;
        let slab_length = slab.length as u64;

        let sector_tsfn = on_sector.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<String>| {
                let key = ctx.env.create_string(&ctx.value)?;
                Ok(vec![key])
            },
        )?;

        Ok(AsyncTask::new(DownloadTask {
            sdk: self.inner.clone(),
            obj,
            max_inflight,
            offset: slab_offset,
            length: Some(slab_length),
            progress_tsfn: None,
            sector_tsfn: Some(sector_tsfn),
        }))
    }

    #[napi(js_name = "generateDataKey")]
    pub fn generate_data_key(&self) -> Buffer {
        let key: [u8; 32] = rand::random();
        Buffer::from(key.to_vec())
    }

    #[napi(js_name = "assembleObject")]
    pub fn assemble_object(
        &self,
        data_key: Buffer,
        slabs_json: String,
    ) -> Result<NativePinnedObject> {
        let key_bytes = data_key.as_ref();
        let encryption_key = sia::encryption::EncryptionKey::try_from(key_bytes)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let slabs: Vec<SlabJson> =
            serde_json::from_str(&slabs_json).map_err(|e| Error::from_reason(e.to_string()))?;
        let indexd_slabs: Vec<indexd::Slab> = slabs
            .iter()
            .map(|s| s.to_indexd())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::from_reason(e))?;

        let obj = indexd::Object::new(encryption_key, indexd_slabs, Vec::new());
        Ok(NativePinnedObject::from_object(obj))
    }

    #[napi(js_name = "pinObject")]
    pub async fn pin_object(&self, object: &NativePinnedObject) -> Result<()> {
        let obj = object.object();
        let sdk = self.inner.clone();
        spawn(async move { sdk.pin_object(&obj).await.map_err(|e| e.to_string()) })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(())
    }

    #[napi(js_name = "updateObjectMetadata")]
    pub async fn update_object_metadata(&self, object: &NativePinnedObject) -> Result<()> {
        let obj = object.object();
        let sdk = self.inner.clone();
        spawn(async move {
            sdk.update_object_metadata(&obj)
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?
        .map_err(|e| Error::from_reason(e))?;
        Ok(())
    }

    #[napi(js_name = "deleteObject")]
    pub async fn delete_object(&self, key: String) -> Result<()> {
        let key = Hash256::from_str(&key).map_err(|e| Error::from_reason(e.to_string()))?;
        let sdk = self.inner.clone();
        spawn(async move { sdk.delete_object(&key).await.map_err(|e| e.to_string()) })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(())
    }

    #[napi(js_name = "sharedObject")]
    pub async fn shared_object(&self, url: String) -> Result<NativePinnedObject> {
        let shared_url: Url = if url.starts_with("sia://") {
            format!("https://{}", &url[6..])
        } else {
            url
        }
        .parse()
        .map_err(|e| Error::from_reason(format!("{e}")))?;
        let sdk = self.inner.clone();
        let obj = spawn(async move {
            sdk.shared_object(shared_url)
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?
        .map_err(|e| Error::from_reason(e))?;
        Ok(NativePinnedObject::from_object(obj))
    }

    #[napi(js_name = "shareObject")]
    pub fn share_object(
        &self,
        object: &NativePinnedObject,
        valid_until_ms: f64,
    ) -> Result<String> {
        let obj = object.object();
        let duration = std::time::Duration::from_millis(valid_until_ms as u64);
        let valid_until = SystemTime::UNIX_EPOCH + duration;
        let url = self
            .inner
            .share_object(&obj, valid_until.into())
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let url_str = url.to_string();
        Ok(if let Some(rest) = url_str.strip_prefix("https://") {
            format!("sia://{rest}")
        } else {
            url_str
        })
    }

    #[napi]
    pub async fn hosts(&self) -> Result<String> {
        let sdk = self.inner.clone();
        let hosts = spawn(async move {
            sdk.hosts(Default::default())
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?
        .map_err(|e| Error::from_reason(e))?;
        serde_json::to_string(&hosts).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn account(&self) -> Result<String> {
        let sdk = self.inner.clone();
        let a = spawn(async move { sdk.account().await.map_err(|e| e.to_string()) })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .map_err(|e| Error::from_reason(e))?;
        let obj = serde_json::json!({
            "accountKey": a.account_key.to_string(),
            "connectKey": a.connect_key,
            "maxPinnedData": a.max_pinned_data,
            "pinnedData": a.pinned_data,
            "app": {
                "id": a.app.id.to_string(),
                "description": a.app.description,
                "serviceUrl": a.app.service_url,
                "logoUrl": a.app.logo_url,
            },
            "lastUsed": system_time_to_epoch_ms(a.last_used.into()),
        });
        serde_json::to_string(&obj).map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi(js_name = "pruneSlabs")]
    pub async fn prune_slabs(&self) -> Result<()> {
        let sdk = self.inner.clone();
        spawn(async move { sdk.prune_slabs().await.map_err(|e| e.to_string()) })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .map_err(|e| Error::from_reason(e))?;
        Ok(())
    }

    #[napi(js_name = "slabDataSize")]
    pub fn slab_data_size(&self) -> f64 {
        let defaults = indexd::UploadOptions::default();
        (defaults.data_shards as usize * SECTOR_SIZE) as f64
    }

    #[napi(js_name = "startChunkedUpload")]
    pub fn start_chunked_upload(&self, total_size: f64) -> f64 {
        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let size = total_size as usize;
        let buffer = vec![0u8; size];
        CHUNK_BUFFERS
            .lock()
            .unwrap()
            .insert(session_id, (buffer, 0));
        session_id as f64
    }

    #[napi(js_name = "uploadChunk")]
    pub fn upload_chunk(&self, session_id: f64, chunk: Buffer) -> Result<f64> {
        let mut buffers = CHUNK_BUFFERS.lock().unwrap();
        let (buffer, offset) = buffers
            .get_mut(&(session_id as u64))
            .ok_or_else(|| {
                Error::from_reason("Invalid session ID. Call startChunkedUpload first.")
            })?;

        let end = *offset + chunk.len();
        if end > buffer.len() {
            return Err(Error::from_reason("Chunk exceeds total size"));
        }

        buffer[*offset..end].copy_from_slice(chunk.as_ref());
        *offset = end;
        Ok(*offset as f64)
    }

    #[napi(
        js_name = "finalizeChunkedUpload",
        ts_args_type = "sessionId: number, options: NativeUploadOptions, onProgress: (current: number, total: number) => void",
        ts_return_type = "Promise<NativePinnedObject>"
    )]
    pub fn finalize_chunked_upload(
        &self,
        session_id: f64,
        options: NativeUploadOptions,
        on_progress: JsFunction,
    ) -> Result<AsyncTask<UploadTask>> {
        let (data, final_offset) = CHUNK_BUFFERS
            .lock()
            .unwrap()
            .remove(&(session_id as u64))
            .ok_or_else(|| {
                Error::from_reason("Invalid session ID or session already finalized")
            })?;

        if final_offset != data.len() {
            return Err(Error::from_reason(format!(
                "Incomplete upload: expected {} bytes, got {} bytes",
                data.len(),
                final_offset
            )));
        }

        let data_shards = options.data_shards.unwrap_or(10) as u8;
        let parity_shards = options.parity_shards.unwrap_or(20) as u8;
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let tsfn: napi::threadsafe_function::ThreadsafeFunction<
            (u64, u64),
            napi::threadsafe_function::ErrorStrategy::Fatal,
        > = on_progress.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(u64, u64)>| {
                let current = ctx.env.create_double(ctx.value.0 as f64)?;
                let total = ctx.env.create_double(ctx.value.1 as f64)?;
                Ok(vec![current, total])
            },
        )?;

        Ok(AsyncTask::new(UploadTask {
            sdk: self.inner.clone(),
            data,
            data_shards,
            parity_shards,
            max_inflight,
            tsfn,
        }))
    }

    #[napi(
        js_name = "streamingUpload",
        ts_args_type = "totalSize: number, options: NativeUploadOptions, onProgress: (current: number, total: number) => void",
        ts_return_type = "NativeStreamingUpload"
    )]
    pub fn streaming_upload(
        &self,
        _total_size: f64,
        options: NativeUploadOptions,
        on_progress: JsFunction,
    ) -> Result<NativeStreamingUpload> {
        let data_shards = options.data_shards.unwrap_or(10) as u8;
        let parity_shards = options.parity_shards.unwrap_or(20) as u8;
        let max_inflight = options.max_inflight.unwrap_or(10) as usize;

        let total_shards_per_slab = data_shards as u64 + parity_shards as u64;
        let slab_encoded_size = total_shards_per_slab * SECTOR_SIZE as u64;

        let tsfn: napi::threadsafe_function::ThreadsafeFunction<
            (u64, u64),
            napi::threadsafe_function::ErrorStrategy::Fatal,
        > = on_progress.create_threadsafe_function(
            0,
            |ctx: napi::threadsafe_function::ThreadSafeCallContext<(u64, u64)>| {
                let current = ctx.env.create_double(ctx.value.0 as f64)?;
                let total = ctx.env.create_double(ctx.value.1 as f64)?;
                Ok(vec![current, total])
            },
        )?;

        // Bounded channel for backpressure (~2 slabs worth)
        let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
        let (result_tx, result_rx) = oneshot::channel();

        let sdk = self.inner.clone();
        let upload_task = spawn(async move {
            let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<()>();

            tokio::spawn(async move {
                let mut sectors: u64 = 0;
                while progress_rx.recv().await.is_some() {
                    sectors += 1;
                    let size = sectors * SECTOR_SIZE as u64;
                    let slabs_size =
                        sectors.div_ceil(total_shards_per_slab) * slab_encoded_size;
                    tsfn.call(
                        (size, slabs_size),
                        napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                    );
                }
            });

            let reader = ChannelReader::new(rx);
            let result = sdk
                .upload(
                    reader,
                    indexd::UploadOptions {
                        max_inflight,
                        data_shards,
                        parity_shards,
                        shard_uploaded: Some(progress_tx),
                    },
                )
                .await
                .map_err(|e| e.to_string());
            let _ = result_tx.send(result);
        });

        Ok(NativeStreamingUpload {
            tx: Mutex::new(Some(tx)),
            result: Mutex::new(Some(result_rx)),
            upload_task: Mutex::new(Some(upload_task)),
        })
    }
}

// -- Free functions --

#[napi(js_name = "generateRecoveryPhrase")]
pub fn generate_recovery_phrase() -> String {
    let seed: [u8; 16] = rand::random();
    Seed::from_seed(seed).to_string()
}

#[napi(js_name = "validateRecoveryPhrase")]
pub fn validate_recovery_phrase(phrase: String) -> Result<()> {
    Seed::new(&phrase).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(())
}

#[napi(js_name = "setLogLevel")]
pub fn set_log_level(level: String) {
    let filter = match level.as_str() {
        "debug" => log::LevelFilter::Debug,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    log::set_max_level(filter);
}
