use std::collections::HashMap;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use indexd::app_client::{RegisterAppRequest, RegisterAppResponse};
use js_sys::Uint8Array;
use sia::rhp::SECTOR_SIZE;
use sia::seed::Seed;
use sia::signing::{PrivateKey, PublicKey, Signature};
use sia::types::Hash256;
use std::str::FromStr;
use std::time::SystemTime;
use chrono::{TimeZone, Utc};
use tokio::io::AsyncWrite;
use wasm_bindgen::prelude::*;

/// Monotonically increasing ID counter for upload sessions and streaming readers
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// Upload configuration exposed to JavaScript.
#[wasm_bindgen]
pub struct UploadOptions {
    #[wasm_bindgen(js_name = "dataShards")]
    pub data_shards: u8,
    #[wasm_bindgen(js_name = "parityShards")]
    pub parity_shards: u8,
    #[wasm_bindgen(js_name = "maxInflight")]
    pub max_inflight: usize,
}

#[wasm_bindgen]
impl UploadOptions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> UploadOptions {
        let defaults = indexd::UploadOptions::default();
        UploadOptions {
            data_shards: defaults.data_shards,
            parity_shards: defaults.parity_shards,
            max_inflight: defaults.max_inflight,
        }
    }

    #[wasm_bindgen(getter, js_name = "totalShardsPerSlab")]
    pub fn total_shards_per_slab(&self) -> u32 {
        self.data_shards as u32 + self.parity_shards as u32
    }

    /// Size in bytes of data per slab (data_shards * SECTOR_SIZE).
    #[wasm_bindgen(js_name = "slabDataSize")]
    pub fn slab_data_size(&self) -> f64 {
        (self.data_shards as usize * SECTOR_SIZE) as f64
    }

    #[wasm_bindgen(js_name = "clone")]
    pub fn js_clone(&self) -> UploadOptions {
        UploadOptions {
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            max_inflight: self.max_inflight,
        }
    }
}

impl UploadOptions {
    fn into_indexd(
        self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> indexd::UploadOptions {
        indexd::UploadOptions {
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            max_inflight: self.max_inflight,
            shard_uploaded: tx,
        }
    }
}

/// Download configuration exposed to JavaScript.
#[wasm_bindgen]
pub struct DownloadOptions {
    #[wasm_bindgen(js_name = "maxInflight")]
    pub max_inflight: usize,
}

#[wasm_bindgen]
impl DownloadOptions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> DownloadOptions {
        let defaults = indexd::DownloadOptions::default();
        DownloadOptions {
            max_inflight: defaults.max_inflight,
        }
    }

    #[wasm_bindgen(js_name = "clone")]
    pub fn js_clone(&self) -> DownloadOptions {
        DownloadOptions {
            max_inflight: self.max_inflight,
        }
    }
}

impl DownloadOptions {
    fn into_indexd(
        self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        sector_tx: Option<tokio::sync::mpsc::UnboundedSender<PublicKey>>,
    ) -> indexd::DownloadOptions {
        indexd::DownloadOptions {
            max_inflight: self.max_inflight,
            offset: 0,
            length: None,
            slab_downloaded: tx,
            sector_downloaded: sector_tx,
        }
    }

    fn into_indexd_ranged(
        self,
        offset: u64,
        length: u64,
        tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        sector_tx: Option<tokio::sync::mpsc::UnboundedSender<PublicKey>>,
    ) -> indexd::DownloadOptions {
        indexd::DownloadOptions {
            max_inflight: self.max_inflight,
            offset,
            length: Some(length),
            slab_downloaded: tx,
            sector_downloaded: sector_tx,
        }
    }
}

/// Global storage for chunked upload buffers
/// Key: session_id (usize), Value: (pre-allocated buffer, current offset)
static CHUNK_BUFFERS: OnceLock<Mutex<HashMap<usize, (Vec<u8>, usize)>>> = OnceLock::new();

fn get_chunk_buffers() -> &'static Mutex<HashMap<usize, (Vec<u8>, usize)>> {
    CHUNK_BUFFERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Global storage for streaming readers
/// Key: reader_id (usize), Value: Arc<Mutex<ReaderState>>
static STREAMING_READERS: OnceLock<
    Mutex<HashMap<usize, Arc<Mutex<indexd::js_chunked_reader::ReaderState>>>>,
> = OnceLock::new();

fn get_streaming_readers()
-> &'static Mutex<HashMap<usize, Arc<Mutex<indexd::js_chunked_reader::ReaderState>>>> {
    STREAMING_READERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install a panic hook and logging bridge so that Rust panics show a proper
/// stack trace and `log::debug!()` / `log::info!()` etc. appear in the browser
/// console.
#[wasm_bindgen(start)]
fn init_panic_hook() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Info).ok();
}

/// Sets the log level filter. Accepts "debug", "info", "warn", or "error".
/// Allows JavaScript to control the verbosity of Rust logs at runtime.
#[wasm_bindgen(js_name = "setLogLevel")]
pub fn set_log_level(level: &str) {
    let filter = match level {
        "debug" => log::LevelFilter::Debug,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    log::set_max_level(filter);
}

/// Converts a JsValue error context into a JsError.
fn to_js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

// ── StreamingUpload ─────────────────────────────────────────────────────

/// Handle for a streaming upload operation.
/// JavaScript should call `pushChunk(data)` for each chunk, then `pushChunk(null)` to signal EOF.
/// The `promise` resolves to a PinnedObject when the upload completes.
#[wasm_bindgen]
pub struct StreamingUpload {
    reader_id: usize,

    #[wasm_bindgen(skip)]
    pub promise: js_sys::Promise,
}

#[wasm_bindgen]
impl StreamingUpload {
    /// Pushes a chunk of data to the upload.
    /// Pass data as Uint8Array. Call with `null` or `undefined` to signal EOF.
    ///
    /// **Backpressure**: This method applies backpressure to prevent memory exhaustion.
    /// It returns a Promise that resolves when the chunk has been queued.
    /// If the queue is full, it waits until space becomes available.
    ///
    /// **IMPORTANT**: JavaScript MUST await this Promise before pushing the next chunk:
    /// ```javascript
    /// await upload.pushChunk(data);  // ← await here!
    /// ```
    #[wasm_bindgen(js_name = "pushChunk")]
    pub fn push_chunk(&self, chunk: Option<Vec<u8>>) -> js_sys::Promise {
        let reader_id = self.reader_id;

        wasm_bindgen_futures::future_to_promise(async move {
            let readers = get_streaming_readers().lock().map_err(to_js_err)?;
            let state = readers
                .get(&reader_id)
                .ok_or_else(|| JsError::new("Invalid reader ID or upload already finalized"))?
                .clone();
            drop(readers); // Release the global lock

            match chunk {
                Some(data) => {
                    // Wait for space if queue is full (backpressure)
                    loop {
                        {
                            let mut reader_state = state.lock().map_err(to_js_err)?;

                            // Maximum 3 chunks queued = ~384 MB overhead (3 × 128 MB)
                            if reader_state.chunks.len() < 3 {
                                // Space available, push the chunk
                                reader_state.chunks.push_back(data);

                                // Wake the reader if it's waiting
                                if let Some(waker) = reader_state.waker.take() {
                                    waker.wake();
                                }
                                break;
                            }
                            // Queue is full, release lock and wait
                        }

                        // Wait 50ms for space to become available
                        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
                            let global = js_sys::global();
                            let set_timeout: js_sys::Function =
                                js_sys::Reflect::get(&global, &"setTimeout".into())
                                    .unwrap()
                                    .into();
                            let _ = set_timeout.call2(
                                &wasm_bindgen::JsValue::NULL,
                                &resolve,
                                &wasm_bindgen::JsValue::from_f64(50.0),
                            );
                        });
                        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
                    }
                }
                None => {
                    // Signal EOF - no backpressure needed
                    let mut reader_state = state.lock().map_err(to_js_err)?;
                    reader_state.eof = true;

                    // Wake the reader if it's waiting
                    if let Some(waker) = reader_state.waker.take() {
                        waker.wake();
                    }
                }
            }

            Ok(JsValue::UNDEFINED)
        })
    }

    /// Returns the promise that resolves when the upload completes
    #[wasm_bindgen(getter)]
    pub fn promise(&self) -> js_sys::Promise {
        self.promise.clone()
    }
}

// ── AppKey ──────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct AppKey(PrivateKey);

#[wasm_bindgen]
impl AppKey {
    /// Imports an AppKey from a 64-byte ed25519 keypair or a 32-byte seed.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<AppKey, JsError> {
        match key.len() {
            64 => {
                let mut keypair = [0u8; 64];
                keypair.copy_from_slice(key);
                Ok(AppKey(PrivateKey::from(keypair)))
            }
            32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(key);
                Ok(AppKey(PrivateKey::from_seed(&seed)))
            }
            _ => Err(JsError::new(
                "app key must be 64 bytes (keypair) or 32 bytes (seed)",
            )),
        }
    }

    /// Exports the full 64-byte ed25519 keypair.
    pub fn export(&self) -> Uint8Array {
        Uint8Array::from(self.0.as_ref())
    }

    /// Returns the hex-encoded public key.
    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Signs a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Uint8Array {
        let sig = self.0.sign(message);
        Uint8Array::from(sig.as_ref() as &[u8])
    }

    /// Verifies a signature against a message.
    #[wasm_bindgen(js_name = "verifySignature")]
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        if signature.len() != 64 {
            return Err(JsError::new("signatures must be 64 bytes"));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        Ok(self
            .0
            .public_key()
            .verify(message, &Signature::from(sig_bytes)))
    }
}

// ── PinnedObject ────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct PinnedObject {
    inner: Arc<Mutex<indexd::Object>>,
}

#[wasm_bindgen]
impl PinnedObject {
    /// Opens a sealed object (JSON) using the provided app key.
    pub fn open(app_key: &AppKey, sealed_json: &str) -> Result<PinnedObject, JsError> {
        let sealed: indexd::SealedObject = serde_json::from_str(sealed_json).map_err(to_js_err)?;
        let obj = sealed.open(&app_key.0).map_err(to_js_err)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    /// Seals the object for offline storage, returning JSON.
    pub fn seal(&self, app_key: &AppKey) -> Result<String, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        let sealed = inner.seal(&app_key.0);
        serde_json::to_string(&sealed).map_err(to_js_err)
    }

    /// Returns the object's ID as a hex string.
    pub fn id(&self) -> Result<String, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(inner.id().to_string())
    }

    /// Returns the total size of the object in bytes.
    pub fn size(&self) -> Result<f64, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(inner.size() as f64)
    }

    /// Returns the metadata as a Uint8Array.
    pub fn metadata(&self) -> Result<Uint8Array, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(Uint8Array::from(inner.metadata.as_slice()))
    }

    /// Updates the metadata.
    #[wasm_bindgen(js_name = "updateMetadata")]
    pub fn update_metadata(&self, metadata: &[u8]) -> Result<(), JsError> {
        let mut inner = self.inner.lock().map_err(to_js_err)?;
        inner.metadata = metadata.to_vec();
        Ok(())
    }

    /// Returns the slab layout as a JSON array.
    ///
    /// Each element contains `offset`, `length`, `minShards`, and `hostKeys`
    /// (an array of host public-key strings identifying which hosts store
    /// each sector of the slab).
    pub fn slabs(&self) -> Result<JsValue, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        let slabs: Vec<serde_json::Value> = inner.slabs().iter().map(|s| {
            serde_json::json!({
                "offset": s.offset,
                "length": s.length,
                "minShards": s.min_shards,
                "hostKeys": s.sectors.iter().map(|sec| sec.host_key.to_string()).collect::<Vec<_>>(),
            })
        }).collect();
        serde_wasm_bindgen::to_value(&slabs).map_err(to_js_err)
    }

    /// Returns the number of slabs in the object.
    ///
    /// Useful for sizing a Web Worker pool (cap workers at slab count) and
    /// for tracking completion when downloading or uploading slabs in parallel.
    #[wasm_bindgen(js_name = "slabCount")]
    pub fn slab_count(&self) -> Result<u32, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        Ok(inner.slabs().len() as u32)
    }

    /// Returns the actual data length of each slab as a JS array of numbers.
    ///
    /// Useful for computing per-slab byte offsets and for accurate download
    /// progress reporting.
    #[wasm_bindgen(js_name = "slabLengths")]
    pub fn slab_lengths(&self) -> Result<js_sys::Array, JsError> {
        let inner = self.inner.lock().map_err(to_js_err)?;
        let arr = js_sys::Array::new();
        for slab in inner.slabs() {
            arr.push(&JsValue::from(slab.length as f64));
        }
        Ok(arr)
    }
}

// ── SDK ─────────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct SDK {
    inner: indexd::SDK,
}

#[wasm_bindgen]
impl SDK {
    /// Returns the app key used by this SDK instance.
    #[wasm_bindgen(js_name = "appKey")]
    pub fn app_key(&self) -> AppKey {
        AppKey(self.inner.app_key().clone())
    }

    /// Uploads a Uint8Array with per-shard progress reporting.
    ///
    /// The `on_progress` callback receives `(current_shards, total_shards)`.
    pub async fn upload(
        &self,
        data: &[u8],
        options: UploadOptions,
        on_progress: &js_sys::Function,
    ) -> Result<PinnedObject, JsError> {
        log::info!("upload: starting ({} bytes)", data.len());
        let slab_data_size = options.data_shards as usize * SECTOR_SIZE;
        let num_slabs = if data.is_empty() {
            0
        } else {
            data.len().div_ceil(slab_data_size)
        };
        let total_shards = (num_slabs as u32) * options.total_shards_per_slab();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd(Some(tx));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let cursor = Cursor::new(data.to_vec());
        let on_progress = on_progress.clone();
        let object: indexd::Object = local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_shards),
                        );
                    }
                });
                self.inner.upload(cursor, options).await
            })
            .await
            .map_err(to_js_err)?;
        log::info!("upload: complete");
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(object)),
        })
    }

    /// Downloads an object's data with per-slab progress reporting.
    ///
    /// The `on_progress` callback receives `(current_slabs, total_slabs)`.
    pub async fn download(
        &self,
        object: &PinnedObject,
        options: DownloadOptions,
        on_progress: &js_sys::Function,
    ) -> Result<Uint8Array, JsError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let size = obj.size() as usize;
        let total_slabs = obj.slabs().len() as u32;
        let mut buf = vec![0u8; size];

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd(Some(tx), None);

        let on_progress = on_progress.clone();
        local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_slabs),
                        );
                    }
                });
                self.inner
                    .download(&mut Cursor::new(&mut buf), &obj, options)
                    .await
            })
            .await
            .map_err(to_js_err)?;
        Ok(Uint8Array::from(buf.as_slice()))
    }

    /// Downloads a byte range from an object, returning the decrypted data as a Uint8Array.
    ///
    /// Only downloads the slabs that overlap the requested range, making this
    /// much more efficient than `download()` for small reads from large objects.
    ///
    /// The `on_sector` callback is called with the host public key string for
    /// each sector successfully downloaded.
    #[wasm_bindgen(js_name = "downloadRange")]
    pub async fn download_range(
        &self,
        object: &PinnedObject,
        offset: f64,
        length: f64,
        options: DownloadOptions,
        on_sector: &js_sys::Function,
    ) -> Result<Uint8Array, JsError> {
        let offset = offset as u64;
        let length = length as u64;
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let mut buf = vec![0u8; length as usize];

        let (sector_tx, mut sector_rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd_ranged(offset, length, None, Some(sector_tx));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let on_sector = on_sector.clone();
        local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    while let Some(host_key) = sector_rx.recv().await {
                        let _ = on_sector.call1(
                            &JsValue::NULL,
                            &JsValue::from_str(&host_key.to_string()),
                        );
                    }
                });
                self.inner
                    .download(&mut Cursor::new(&mut buf), &obj, options)
                    .await
            })
            .await
            .map_err(to_js_err)?;
        Ok(Uint8Array::from(buf.as_slice()))
    }

    /// Downloads an object with streaming chunks.
    /// Fires `on_chunk(bytes)` after each slab is decoded and `on_progress(current, total)` for progress.
    #[wasm_bindgen(js_name = "downloadStreaming")]
    pub async fn download_streaming(
        &self,
        object: &PinnedObject,
        options: DownloadOptions,
        on_chunk: &js_sys::Function,
        on_progress: &js_sys::Function,
    ) -> Result<(), JsError> {
        /// Custom AsyncWrite that calls JS callback with each chunk
        struct ChunkWriter {
            callback: js_sys::Function,
        }

        impl AsyncWrite for ChunkWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, std::io::Error>> {
                let array = Uint8Array::from(buf);
                let _ = self.callback.call1(&JsValue::NULL, &array);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Poll::Ready(Ok(()))
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let total_slabs = obj.slabs().len() as u32;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd(Some(tx), None);

        let mut writer = ChunkWriter {
            callback: on_chunk.clone(),
        };

        let on_progress = on_progress.clone();
        local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_slabs),
                        );
                    }
                });
                self.inner.download(&mut writer, &obj, options).await
            })
            .await
            .map_err(to_js_err)?;
        Ok(())
    }

    /// Downloads a single slab by index, returning its decrypted data as a Uint8Array.
    ///
    /// Used by slab download workers to enable parallel slab downloads across
    /// multiple Web Workers, each with their own SDK instance and thread.
    #[wasm_bindgen(js_name = "downloadSlabByIndex")]
    pub async fn download_slab_by_index(
        &self,
        object: &PinnedObject,
        slab_index: u32,
        options: DownloadOptions,
        on_sector: &js_sys::Function,
    ) -> Result<Uint8Array, JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let slabs = obj.slabs();
        let idx = slab_index as usize;
        if idx >= slabs.len() {
            return Err(JsError::new(&format!(
                "slab index {} out of range (object has {} slabs)",
                idx,
                slabs.len()
            )));
        }
        // Compute byte offset into the object for this slab
        let offset: u64 = slabs[..idx].iter().map(|s| s.length as u64).sum();
        let length = slabs[idx].length as u64;
        let mut buf = vec![0u8; length as usize];

        let (sector_tx, mut sector_rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd_ranged(offset, length, None, Some(sector_tx));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let on_sector = on_sector.clone();
        local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    while let Some(host_key) = sector_rx.recv().await {
                        let _ = on_sector.call1(
                            &JsValue::NULL,
                            &JsValue::from_str(&host_key.to_string()),
                        );
                    }
                });
                self.inner
                    .download(&mut Cursor::new(&mut buf), &obj, options)
                    .await
            })
            .await
            .map_err(to_js_err)?;
        Ok(Uint8Array::from(buf.as_slice()))
    }

    /// Returns the slab data size for default options (data_shards * SECTOR_SIZE).
    /// Prefer `UploadOptions.slabDataSize()` for custom shard counts.
    #[wasm_bindgen(js_name = "slabDataSize")]
    pub fn slab_data_size(&self) -> f64 {
        UploadOptions::new().slab_data_size()
    }

    /// Generates a random 32-byte encryption key for object-level encryption.
    /// Used by parallel upload workers that share a single data key.
    #[wasm_bindgen(js_name = "generateDataKey")]
    pub fn generate_data_key(&self) -> Uint8Array {
        let key: [u8; 32] = rand::random();
        Uint8Array::from(&key[..])
    }

    /// Uploads a single slab's worth of raw data with object-level encryption
    /// at the given stream offset. Returns the slab metadata as JSON.
    ///
    /// Used by parallel upload workers. Each worker calls this with a different
    /// chunk of the file and the correct stream offset. The shared data_key
    /// ensures all slabs can be decrypted together.
    ///
    /// The `on_progress` callback receives `(current_shards, total_shards)`.
    #[wasm_bindgen(js_name = "uploadSlab")]
    pub async fn upload_slab(
        &self,
        data: &[u8],
        data_key: &[u8],
        stream_offset: f64,
        options: UploadOptions,
        on_progress: &js_sys::Function,
    ) -> Result<String, JsError> {
        let key = sia::encryption::EncryptionKey::try_from(data_key)
            .map_err(|e| JsError::new(&format!("invalid data key: {e}")))?;

        let total_shards = options.total_shards_per_slab();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd(Some(tx));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();

        let on_progress = on_progress.clone();
        let slab = local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_shards),
                        );
                    }
                });
                self.inner
                    .upload_slab_raw(data, &key, stream_offset as u64, options)
                    .await
            })
            .await
            .map_err(to_js_err)?;

        serde_json::to_string(&slab).map_err(to_js_err)
    }

    /// Assembles a PinnedObject from a data key and an array of slab metadata JSONs.
    ///
    /// Used after parallel upload workers have uploaded all slabs independently.
    /// The main thread collects the slab JSONs and calls this to create the
    /// final object that can be pinned to the indexer.
    #[wasm_bindgen(js_name = "assembleObject")]
    pub fn assemble_object(
        &self,
        data_key: &[u8],
        slabs_json: &str,
    ) -> Result<PinnedObject, JsError> {
        let key = sia::encryption::EncryptionKey::try_from(data_key)
            .map_err(|e| JsError::new(&format!("invalid data key: {e}")))?;
        let slabs: Vec<indexd::Slab> = serde_json::from_str(slabs_json).map_err(to_js_err)?;
        let object = indexd::Object::new(key, slabs, Vec::new());
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(object)),
        })
    }

    /// Starts a new chunked upload session with the total file size.
    /// Returns a session ID (as a number) to track this upload.
    ///
    /// Note: Due to WASM 32-bit limitations, maximum file size is approximately 1.5 GB.
    #[wasm_bindgen(js_name = "startChunkedUpload")]
    pub fn start_chunked_upload(&self, total_size: f64) -> Result<f64, JsError> {
        let session_id = NEXT_ID.fetch_add(1, Ordering::Relaxed) as f64;
        let size = total_size as usize;

        // WASM has a 32-bit address space, so we can't allocate more than ~2GB
        // Set a conservative limit of 1.5GB to avoid capacity overflow
        const MAX_SIZE: usize = 1536 * 1024 * 1024; // 1.5 GB
        if size > MAX_SIZE {
            return Err(JsError::new(&format!(
                "File too large ({:.2} GB). Maximum upload size is 1.5 GB due to WASM memory limitations.",
                size as f64 / (1024.0 * 1024.0 * 1024.0)
            )));
        }

        let mut buffers = get_chunk_buffers().lock().map_err(to_js_err)?;

        let buffer = vec![0u8; size];

        buffers.insert(session_id as usize, (buffer, 0)); // (buffer, current_offset)

        log::info!(
            "startChunkedUpload: session {} initialized with {} bytes",
            session_id,
            size
        );
        Ok(session_id)
    }

    /// Adds a chunk to an existing upload session.
    /// Returns the current offset after adding this chunk.
    #[wasm_bindgen(js_name = "uploadChunk")]
    pub fn upload_chunk(&self, session_id: f64, chunk: &[u8]) -> Result<f64, JsError> {
        let mut buffers = get_chunk_buffers().lock().map_err(to_js_err)?;

        let (buffer, offset) = buffers
            .get_mut(&(session_id as usize))
            .ok_or_else(|| JsError::new("Invalid session ID. Call startChunkedUpload first."))?;

        // Copy chunk data to the pre-allocated buffer at the current offset
        let end = *offset + chunk.len();
        if end > buffer.len() {
            return Err(JsError::new("Chunk exceeds total size"));
        }

        buffer[*offset..end].copy_from_slice(chunk);
        *offset = end;

        log::debug!(
            "uploadChunk: wrote {} bytes at offset {}, total progress: {}/{}",
            chunk.len(),
            *offset - chunk.len(),
            *offset,
            buffer.len()
        );
        Ok(*offset as f64)
    }

    /// Finalizes a chunked upload and returns the PinnedObject.
    /// on_progress callback receives (current_shards, total_shards).
    #[wasm_bindgen(js_name = "finalizeChunkedUpload")]
    pub async fn finalize_chunked_upload(
        &self,
        session_id: f64,
        options: UploadOptions,
        on_progress: &js_sys::Function,
    ) -> Result<PinnedObject, JsError> {
        // Retrieve and remove the accumulated buffer
        let (data, final_offset) = {
            let mut buffers = get_chunk_buffers().lock().map_err(to_js_err)?;
            buffers
                .remove(&(session_id as usize))
                .ok_or_else(|| JsError::new("Invalid session ID or session already finalized"))?
        };

        // Verify all data was written
        if final_offset != data.len() {
            return Err(JsError::new(&format!(
                "Incomplete upload: expected {} bytes, got {} bytes",
                data.len(),
                final_offset
            )));
        }

        log::info!("finalizeChunkedUpload: uploading {} bytes", data.len());

        // Calculate progress metadata
        let slab_data_size = options.data_shards as usize * SECTOR_SIZE;
        let num_slabs = if data.is_empty() {
            0
        } else {
            data.len().div_ceil(slab_data_size)
        };
        let total_shards = (num_slabs as u32) * options.total_shards_per_slab();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd(Some(tx));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(to_js_err)?;
        let _guard = rt.enter();
        let local = tokio::task::LocalSet::new();
        let cursor = Cursor::new(data);
        let on_progress = on_progress.clone();
        let object: indexd::Object = local
            .run_until(async {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = on_progress.call2(
                            &JsValue::NULL,
                            &JsValue::from(count),
                            &JsValue::from(total_shards),
                        );
                    }
                });
                self.inner.upload(cursor, options).await
            })
            .await
            .map_err(to_js_err)?;
        log::info!("finalizeChunkedUpload: complete");
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(object)),
        })
    }

    /// Starts a streaming upload that reads chunks on-demand from JavaScript.
    /// This bypasses WASM memory limitations by never accumulating the entire file.
    ///
    /// Returns a StreamingUpload object with a `pushChunk` method and a `promise` property.
    /// JavaScript should:
    /// 1. Start pushing chunks immediately using `pushChunk(chunk)`
    /// 2. Call `pushChunk(null)` to signal EOF when all chunks are sent
    /// 3. `await upload.promise` to get the uploaded object
    ///
    /// # Example JavaScript Usage
    /// ```javascript
    /// const totalSize = file.size;
    /// const upload = sdk.streamingUpload(totalSize, (current, total) => {
    ///   console.log(`Progress: ${current}/${total} shards`);
    /// });
    ///
    /// // Read and push chunks asynchronously
    /// (async () => {
    ///   const CHUNK_SIZE = 128 * 1024 * 1024; // 128 MB
    ///   for (let offset = 0; offset < totalSize; offset += CHUNK_SIZE) {
    ///     const chunk = file.slice(offset, offset + CHUNK_SIZE);
    ///     const data = new Uint8Array(await chunk.arrayBuffer());
    ///     upload.pushChunk(data);
    ///   }
    ///   upload.pushChunk(null); // Signal EOF
    /// })();
    ///
    /// // Wait for upload to complete
    /// const obj = await upload.promise;
    /// ```
    #[wasm_bindgen(js_name = "streamingUpload")]
    pub fn streaming_upload(
        &self,
        total_size: f64,
        options: UploadOptions,
        on_progress: &js_sys::Function,
    ) -> Result<StreamingUpload, JsError> {
        use indexd::js_chunked_reader::JsChunkedReader;

        // Generate a unique reader ID
        let reader_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        // Create the reader
        let reader = JsChunkedReader::new();

        // Register the reader state globally so pushChunk can access it
        {
            let mut readers = get_streaming_readers().lock().map_err(to_js_err)?;
            readers.insert(reader_id, reader.state().clone());
        }

        // Calculate progress metadata
        let slab_data_size = options.data_shards as usize * SECTOR_SIZE;
        let size = total_size as usize;
        let num_slabs = if size == 0 {
            0
        } else {
            size.div_ceil(slab_data_size)
        };
        let total_shards = (num_slabs as u32) * options.total_shards_per_slab();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let options = options.into_indexd(Some(tx));

        let on_progress = on_progress.clone();
        let inner = self.inner.clone();

        // Convert to a JavaScript Promise that spawns the upload task
        let promise = wasm_bindgen_futures::future_to_promise(async move {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(to_js_err)?;
            let _guard = rt.enter();
            let local = tokio::task::LocalSet::new();

            let object: indexd::Object = local
                .run_until(async move {
                    // Spawn progress tracking task
                    tokio::task::spawn_local(async move {
                        let mut count: u32 = 0;
                        while rx.recv().await.is_some() {
                            count += 1;
                            let _ = on_progress.call2(
                                &JsValue::NULL,
                                &JsValue::from(count),
                                &JsValue::from(total_shards),
                            );
                        }
                    });

                    // Run the upload
                    inner.upload(reader, options).await
                })
                .await
                .map_err(to_js_err)?;

            // Clean up the reader from the global registry
            let _ = get_streaming_readers().lock().map(|mut readers| {
                readers.remove(&reader_id);
            });

            let pinned = PinnedObject {
                inner: Arc::new(Mutex::new(object)),
            };
            Ok(JsValue::from(pinned))
        });

        Ok(StreamingUpload {
            reader_id,
            promise: js_sys::Promise::from(promise),
        })
    }

    /// Returns hosts as a JSON array.
    pub async fn hosts(&self) -> Result<JsValue, JsError> {
        let hosts = self
            .inner
            .hosts(Default::default())
            .await
            .map_err(to_js_err)?;
        serde_wasm_bindgen::to_value(&hosts).map_err(to_js_err)
    }

    /// Returns account information as a JS object.
    pub async fn account(&self) -> Result<JsValue, JsError> {
        let a = self.inner.account().await.map_err(to_js_err)?;
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
            "lastUsed": a.last_used.timestamp_millis(),
        });
        serde_wasm_bindgen::to_value(&obj).map_err(to_js_err)
    }

    /// Retrieves a pinned object by its hex-encoded key.
    pub async fn object(&self, key: &str) -> Result<PinnedObject, JsError> {
        let key = Hash256::from_str(key).map_err(to_js_err)?;
        let obj = self.inner.object(&key).await.map_err(to_js_err)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    /// Pins an object to the indexer.
    #[wasm_bindgen(js_name = "pinObject")]
    pub async fn pin_object(&self, object: &PinnedObject) -> Result<(), JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        self.inner.pin_object(&obj).await.map_err(to_js_err)
    }

    /// Updates the metadata of an object already stored in the indexer.
    #[wasm_bindgen(js_name = "updateObjectMetadata")]
    pub async fn update_object_metadata(&self, object: &PinnedObject) -> Result<(), JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        self.inner
            .update_object_metadata(&obj)
            .await
            .map_err(to_js_err)
    }

    /// Deletes an object from the indexer by its hex-encoded key.
    #[wasm_bindgen(js_name = "deleteObject")]
    pub async fn delete_object(&self, key: &str) -> Result<(), JsError> {
        let key = Hash256::from_str(key).map_err(to_js_err)?;
        self.inner.delete_object(&key).await.map_err(to_js_err)
    }

    /// Prunes unused slabs from the indexer.
    #[wasm_bindgen(js_name = "pruneSlabs")]
    pub async fn prune_slabs(&self) -> Result<(), JsError> {
        self.inner.prune_slabs().await.map_err(to_js_err)
    }

    /// Returns object events for syncing. Supports cursor-based pagination.
    ///
    /// `cursor_json` is an optional JSON string: `{"id": "hex...", "after": <epoch_ms>}`
    /// `limit` is the maximum number of events to return.
    ///
    /// Returns a JS array of objects:
    /// `[{ id: string, deleted: bool, updatedAt: number, object: PinnedObject | null }]`
    #[wasm_bindgen(js_name = "objectEvents")]
    pub async fn object_events(
        &self,
        cursor_json: Option<String>,
        limit: u32,
    ) -> Result<JsValue, JsError> {
        let cursor = match cursor_json {
            Some(json) => {
                let parsed: serde_json::Value = serde_json::from_str(&json).map_err(to_js_err)?;
                let id_str = parsed["id"].as_str().ok_or_else(|| JsError::new("cursor missing 'id'"))?;
                let after_ms = parsed["after"].as_i64().ok_or_else(|| JsError::new("cursor missing 'after'"))?;
                let id = sia::types::Hash256::from_str(id_str).map_err(to_js_err)?;
                let after = Utc.timestamp_millis_opt(after_ms)
                    .single()
                    .ok_or_else(|| JsError::new("invalid 'after' timestamp"))?;
                Some(indexd::app_client::ObjectsCursor { id, after })
            }
            None => None,
        };

        let events = self.inner.object_events(cursor, Some(limit as usize)).await.map_err(to_js_err)?;

        let arr = js_sys::Array::new();
        let js_err = |_| JsError::new("failed to set property on object");
        for event in events {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(&obj, &"id".into(), &event.id.to_string().into())
                .map_err(js_err)?;
            js_sys::Reflect::set(&obj, &"deleted".into(), &event.deleted.into())
                .map_err(js_err)?;
            js_sys::Reflect::set(
                &obj,
                &"updatedAt".into(),
                &JsValue::from_f64(event.updated_at.timestamp_millis() as f64),
            )
            .map_err(js_err)?;

            let pinned_val = match event.object {
                Some(o) => {
                    let pinned = PinnedObject {
                        inner: Arc::new(Mutex::new(o)),
                    };
                    pinned.into()
                }
                None => JsValue::NULL,
            };
            js_sys::Reflect::set(&obj, &"object".into(), &pinned_val)
                .map_err(js_err)?;

            arr.push(&obj);
        }
        Ok(arr.into())
    }

    /// Creates a share URL for an object, valid until the given timestamp (ms since epoch).
    #[wasm_bindgen(js_name = "shareObject")]
    pub fn share_object(
        &self,
        object: &PinnedObject,
        valid_until_ms: f64,
    ) -> Result<String, JsError> {
        let obj = object.inner.lock().map_err(to_js_err)?.clone();
        let duration = std::time::Duration::from_millis(valid_until_ms as u64);
        let valid_until = SystemTime::UNIX_EPOCH + duration;
        let url = self
            .inner
            .share_object(&obj, valid_until.into())
            .map_err(to_js_err)?;
        // sia:// URLs can open the mobile app when clicked
        // FIXME Alright - could leave this for the app to implement
        let url_str = url.to_string();
        Ok(if let Some(rest) = url_str.strip_prefix("https://") {
            format!("sia://{rest}")
        } else {
            url_str
        })
    }

    /// Retrieves a shared object from a signed share URL.
    /// Accepts both `https://` and `sia://` schemes.
    #[wasm_bindgen(js_name = "sharedObject")]
    pub async fn shared_object(&self, share_url: &str) -> Result<PinnedObject, JsError> {
        let url = if share_url.starts_with("sia://") {
            format!("https://{}", &share_url[6..])
        } else {
            share_url.to_string()
        };
        let obj = self.inner.shared_object(url).await.map_err(to_js_err)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }
}

// ── Builder ─────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct Builder {
    state: Arc<Mutex<Option<BuilderState>>>,
}

enum BuilderState {
    Disconnected(indexd::Builder<indexd::DisconnectedState>),
    RequestingApproval(indexd::Builder<indexd::RequestingApprovalState>),
    Approved(indexd::Builder<indexd::ApprovedState>),
    Finalized,
}

#[wasm_bindgen]
impl Builder {
    /// Creates a new SDK builder for the given indexer URL.
    #[wasm_bindgen(constructor)]
    pub fn new(indexer_url: &str) -> Result<Builder, JsError> {
        let builder = indexd::Builder::new(indexer_url).map_err(to_js_err)?;
        Ok(Builder {
            state: Arc::new(Mutex::new(Some(BuilderState::Disconnected(builder)))),
        })
    }

    /// Attempts to connect using an existing app key.
    ///
    /// Returns the SDK if authenticated, or null if the key is not recognized.
    /// Call `requestConnection` if null is returned.
    pub async fn connected(&self, app_key: &AppKey) -> Result<SDK, JsError> {
        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Disconnected(builder) => {
                match builder.connected(&app_key.0).await.map_err(to_js_err)? {
                    Some(sdk) => {
                        *self.state.lock().map_err(to_js_err)? = Some(BuilderState::Finalized);
                        Ok(SDK { inner: sdk })
                    }
                    None => {
                        *self.state.lock().map_err(to_js_err)? =
                            Some(BuilderState::Disconnected(builder));
                        Err(JsError::new("connection failed: no SDK returned"))
                    }
                }
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Disconnected"))
            }
        }
    }

    /// Requests a new app connection. Pass app metadata as a JSON object:
    /// ```json
    /// {
    ///   "app_id": [32 bytes as hex],
    ///   "name": "My App",
    ///   "description": "...",
    ///   "service_url": "https://...",
    ///   "logo_url": "https://..." (optional),
    ///   "callback_url": "https://..." (optional)
    /// }
    /// ```
    #[wasm_bindgen(js_name = "requestConnection")]
    pub async fn request_connection(&self, app_meta_json: &str) -> Result<(), JsError> {
        let meta: RegisterAppRequest = serde_json::from_str(app_meta_json).map_err(to_js_err)?;

        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Disconnected(builder) => {
                let builder = builder.request_connection(&meta).await.map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? =
                    Some(BuilderState::RequestingApproval(builder));
                Ok(())
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Disconnected"))
            }
        }
    }

    /// Transitions the builder using a pre-fetched connection response.
    /// Use this when the `POST /auth/connect` call was made out-of-band
    /// (e.g. via curl) to work around CORS restrictions.
    ///
    /// `app_id_hex` is the hex-encoded app ID used in the request.
    /// `response_json` is the JSON response from `POST /auth/connect`.
    #[wasm_bindgen(js_name = "setConnectionResponse")]
    pub fn set_connection_response(
        &self,
        app_id_hex: &str,
        response_json: &str,
    ) -> Result<(), JsError> {
        let app_id = Hash256::from_str(app_id_hex).map_err(to_js_err)?;
        let response: RegisterAppResponse =
            serde_json::from_str(response_json).map_err(to_js_err)?;

        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Disconnected(builder) => {
                let builder = builder
                    .with_connection_response(app_id, response)
                    .map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? =
                    Some(BuilderState::RequestingApproval(builder));
                Ok(())
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Disconnected"))
            }
        }
    }

    /// Returns the response URL the user must visit to authorize the connection.
    #[wasm_bindgen(js_name = "responseUrl")]
    pub fn response_url(&self) -> Result<String, JsError> {
        let state = self.state.lock().map_err(to_js_err)?;
        match state.as_ref() {
            Some(BuilderState::RequestingApproval(builder)) => {
                Ok(builder.response_url().to_owned())
            }
            _ => Err(JsError::new("invalid state: expected RequestingApproval")),
        }
    }

    /// Polls for approval. Resolves when the user approves.
    #[wasm_bindgen(js_name = "waitForApproval")]
    pub async fn wait_for_approval(&self) -> Result<(), JsError> {
        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::RequestingApproval(builder) => {
                let builder = builder.wait_for_approval().await.map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? = Some(BuilderState::Approved(builder));
                Ok(())
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected RequestingApproval"))
            }
        }
    }

    /// Registers the app using the user's recovery phrase and returns the SDK.
    pub async fn register(&self, mnemonic: &str) -> Result<SDK, JsError> {
        let state = self
            .state
            .lock()
            .map_err(to_js_err)?
            .take()
            .ok_or_else(|| JsError::new("invalid builder state"))?;

        match state {
            BuilderState::Approved(builder) => {
                let sdk = builder.register(mnemonic).await.map_err(to_js_err)?;
                *self.state.lock().map_err(to_js_err)? = Some(BuilderState::Finalized);
                Ok(SDK { inner: sdk })
            }
            other => {
                *self.state.lock().map_err(to_js_err)? = Some(other);
                Err(JsError::new("invalid state: expected Approved"))
            }
        }
    }
}

// ── Free functions ──────────────────────────────────────────────────────

/// Generates a new 12-word BIP-32 recovery phrase.
#[wasm_bindgen(js_name = "generateRecoveryPhrase")]
pub fn generate_recovery_phrase() -> String {
    let seed: [u8; 16] = rand::random();
    Seed::from_seed(seed).to_string()
}

/// Validates a BIP-32 recovery phrase.
#[wasm_bindgen(js_name = "validateRecoveryPhrase")]
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), JsError> {
    Seed::new(phrase).map_err(to_js_err)?;
    Ok(())
}

/// Connects to a host via WebTransport and fetches its settings/prices.
///
/// `address` should be a host address like `host.example.com:9883`.
/// Returns the host settings as a JS object.
#[wasm_bindgen(js_name = "fetchHostSettings")]
pub async fn fetch_host_settings(address: &str) -> Result<JsValue, JsError> {
    let settings = indexd::web_transport::fetch_host_settings(address)
        .await
        .map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&settings).map_err(to_js_err)
}
