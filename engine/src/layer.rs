use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read},
    path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use futures_util::{StreamExt, stream};
use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use tokio::{fs, io::AsyncWriteExt};
use tracing::warn;

const DEFAULT_MAX_CONCURRENT_LAYERS: usize = 4;
const DEFAULT_MAX_DECOMPRESSED_LAYER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_LAYER_COUNT: usize = 128;
const MAX_LOCAL_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.index.v1+json,",
    "application/vnd.docker.distribution.manifest.list.v2+json,",
    "application/vnd.oci.image.manifest.v1+json,",
    "application/vnd.docker.distribution.manifest.v2+json"
);
const BLOB_ACCEPT: &str = concat!(
    "application/vnd.oci.image.layer.v1.tar,",
    "application/vnd.oci.image.layer.v1.tar+gzip,",
    "application/vnd.oci.image.layer.v1.tar+zstd,",
    "application/vnd.docker.image.rootfs.diff.tar,",
    "application/vnd.docker.image.rootfs.diff.tar.gzip"
);

pub type LayerResult<T> = std::result::Result<T, LayerError>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sbom {
    pub image: String,
    pub layers: Vec<LayerSbom>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LayerSbom {
    pub digest: String,
    pub depth: usize,
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source_path: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtractOptions {
    pub max_concurrent_layers: usize,
    pub max_decompressed_layer_bytes: u64,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            max_concurrent_layers: DEFAULT_MAX_CONCURRENT_LAYERS,
            max_decompressed_layer_bytes: DEFAULT_MAX_DECOMPRESSED_LAYER_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SbomExtractor {
    client: Client,
    options: ExtractOptions,
}

impl SbomExtractor {
    pub fn new() -> Self {
        Self::with_options(ExtractOptions::default())
    }

    pub fn with_options(options: ExtractOptions) -> Self {
        Self {
            client: Client::new(),
            options,
        }
    }

    pub async fn extract(&self, image_ref: &str) -> LayerResult<Sbom> {
        let image_ref = image_ref.trim();
        if image_ref.is_empty() {
            return Err(LayerError::EmptyImageRef);
        }

        let path = Path::new(image_ref);
        if path.is_file() {
            let path = path.to_path_buf();
            let image = image_ref.to_owned();
            let options = self.options.clone();
            return tokio::task::spawn_blocking(move || {
                inspect_local_archive(&path, image, &options)
            })
            .await
            .map_err(|source| LayerError::Join {
                context: "inspecting local image archive",
                source,
            })?;
        }

        let image = ImageReference::parse(image_ref)?;
        let registry = RegistryClient::new(self.client.clone(), image.clone());
        let manifest = registry.resolve_manifest(&image.reference).await?;
        let layers = manifest.layers.ok_or(LayerError::MissingLayers)?;

        inspect_registry_layers(&registry, &image.original, layers, &self.options).await
    }
}

impl Default for SbomExtractor {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn extract(image_ref: &str) -> LayerResult<Sbom> {
    SbomExtractor::new().extract(image_ref).await
}

#[derive(Debug, Error)]
pub enum LayerError {
    #[error("image reference is empty")]
    EmptyImageRef,

    #[error("invalid image reference {reference:?}: {reason}")]
    InvalidImageRef {
        reference: String,
        reason: &'static str,
    },

    #[error("image index does not contain any manifests")]
    EmptyImageIndex,

    #[error("manifest does not contain layers")]
    MissingLayers,

    #[error("image has too many layers: {count} > {max}")]
    TooManyLayers { count: usize, max: usize },

    #[error("unsupported manifest media type {0}")]
    UnsupportedManifestMediaType(String),

    #[error("unsupported layer media type {0}")]
    UnsupportedLayerMediaType(String),

    #[error("registry request for {url} failed with status {status}")]
    RegistryStatus { url: String, status: StatusCode },

    #[error("registry authentication challenge is unsupported: {0}")]
    UnsupportedAuthChallenge(String),

    #[error("registry token response omitted a bearer token")]
    MissingRegistryToken,

    #[error("failed to read local image archive {path:?}")]
    LocalArchiveRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("local image archive is missing {path}")]
    MissingArchiveEntry { path: String },

    #[error("local image archive format is not supported: {path:?}")]
    UnsupportedLocalArchive { path: PathBuf },

    #[error("layer {digest} exceeded decompressed size limit of {limit} bytes")]
    LayerTooLarge { digest: String, limit: u64 },

    #[error("tar entry uses unsafe path {path:?}")]
    UnsafeTarPath { path: PathBuf },

    #[error("tar entry symlink or hardlink {path:?} points outside the layer to {target:?}")]
    UnsafeTarLink { path: PathBuf, target: PathBuf },

    #[error("failed to parse {context}")]
    Parse {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("http request failed")]
    Http(#[from] reqwest::Error),

    #[error("io error while {context}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("task failed while {context}")]
    Join {
        context: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
}

#[derive(Debug, Clone)]
struct ImageReference {
    original: String,
    registry: String,
    repository: String,
    reference: String,
}

impl ImageReference {
    fn parse(input: &str) -> LayerResult<Self> {
        let (name, reference) = match input.split_once('@') {
            Some((name, digest)) if !name.is_empty() && !digest.is_empty() => {
                (name.to_owned(), digest.to_owned())
            }
            Some(_) => {
                return Err(LayerError::InvalidImageRef {
                    reference: input.to_owned(),
                    reason: "digest reference is incomplete",
                });
            }
            None => split_tag(input),
        };

        if name.is_empty() {
            return Err(LayerError::InvalidImageRef {
                reference: input.to_owned(),
                reason: "repository is empty",
            });
        }

        let mut parts = name.split('/');
        let first = parts.next().ok_or_else(|| LayerError::InvalidImageRef {
            reference: input.to_owned(),
            reason: "repository is empty",
        })?;
        let has_explicit_registry =
            first.contains('.') || first.contains(':') || first == "localhost";

        let (registry, repository) = if has_explicit_registry {
            let rest = parts.collect::<Vec<_>>().join("/");
            if rest.is_empty() {
                return Err(LayerError::InvalidImageRef {
                    reference: input.to_owned(),
                    reason: "repository is empty",
                });
            }
            (first.to_owned(), rest)
        } else if name.contains('/') {
            ("registry-1.docker.io".to_owned(), name)
        } else {
            ("registry-1.docker.io".to_owned(), format!("library/{name}"))
        };

        Ok(Self {
            original: input.to_owned(),
            registry,
            repository,
            reference,
        })
    }

    fn registry_scheme(&self) -> &'static str {
        if self.registry.starts_with("localhost") || self.registry.starts_with("127.") {
            "http"
        } else {
            "https"
        }
    }
}

fn split_tag(input: &str) -> (String, String) {
    let last_segment = match input.rsplit('/').next() {
        Some(segment) => segment,
        None => input,
    };
    if let Some((name, tag)) = input.rsplit_once(':')
        && last_segment.contains(':')
        && !tag.is_empty()
    {
        return (name.to_owned(), tag.to_owned());
    }

    (input.to_owned(), "latest".to_owned())
}

#[derive(Clone)]
struct RegistryClient {
    client: Client,
    image: ImageReference,
    token: std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
}

impl RegistryClient {
    fn new(client: Client, image: ImageReference) -> Self {
        Self {
            client,
            image,
            token: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn resolve_manifest(&self, reference: &str) -> LayerResult<ImageManifest> {
        let mut current_reference = reference.to_owned();

        loop {
            let url = self.manifest_url(&current_reference);
            let response = self.authenticated_get(&url, MANIFEST_ACCEPT).await?;
            let response = ensure_success(response, &url)?;
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let bytes = response.bytes().await?;
            let manifest: ImageManifest = parse_json("image manifest", &bytes)?;

            if manifest.manifests.is_some()
                || content_type
                    .as_deref()
                    .is_some_and(is_manifest_list_media_type)
                || manifest
                    .media_type
                    .as_deref()
                    .is_some_and(is_manifest_list_media_type)
            {
                let manifests = manifest.manifests.ok_or(LayerError::EmptyImageIndex)?;
                let selected = select_platform_manifest(&manifests)?;
                current_reference = selected.digest;
                continue;
            }

            if manifest.layers.is_none()
                && let Some(media_type) = manifest.media_type.as_deref().or(content_type.as_deref())
            {
                return Err(LayerError::UnsupportedManifestMediaType(
                    media_type.to_owned(),
                ));
            }

            return Ok(manifest);
        }
    }

    async fn fetch_blob(&self, descriptor: &Descriptor) -> LayerResult<PathBuf> {
        let cache_path = cache_path_for_digest(&descriptor.digest)?;
        match fs::metadata(&cache_path).await {
            Ok(metadata) if metadata.is_file() => return Ok(cache_path),
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(LayerError::Io {
                    context: "checking layer cache",
                    source,
                });
            }
        }

        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|source| LayerError::Io {
                    context: "creating layer cache directory",
                    source,
                })?;
        }

        let url = self.blob_url(&descriptor.digest);
        let response = self.authenticated_get(&url, BLOB_ACCEPT).await?;
        let response = ensure_success(response, &url)?;
        let temp_path = cache_path.with_extension("download");
        let mut file = fs::File::create(&temp_path)
            .await
            .map_err(|source| LayerError::Io {
                context: "creating cached layer file",
                source,
            })?;
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk)
                .await
                .map_err(|source| LayerError::Io {
                    context: "writing cached layer file",
                    source,
                })?;
        }

        file.flush().await.map_err(|source| LayerError::Io {
            context: "flushing cached layer file",
            source,
        })?;
        drop(file);

        fs::rename(&temp_path, &cache_path)
            .await
            .map_err(|source| LayerError::Io {
                context: "promoting cached layer file",
                source,
            })?;

        Ok(cache_path)
    }

    async fn authenticated_get(
        &self,
        url: &str,
        accept: &'static str,
    ) -> LayerResult<reqwest::Response> {
        let token = self.token.lock().await.clone();
        let mut request = self.client.get(url).header(ACCEPT, accept);
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }

        let response = request.send().await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| LayerError::UnsupportedAuthChallenge("missing header".to_owned()))?
            .to_owned();
        let token = self.fetch_bearer_token(&challenge).await?;
        *self.token.lock().await = Some(token.clone());

        Ok(self
            .client
            .get(url)
            .header(ACCEPT, accept)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await?)
    }

    async fn fetch_bearer_token(&self, challenge: &str) -> LayerResult<String> {
        let fields = parse_auth_challenge(challenge)?;
        let realm = fields
            .get("realm")
            .ok_or_else(|| LayerError::UnsupportedAuthChallenge(challenge.to_owned()))?;
        let mut request = self.client.get(realm);
        if let Some(service) = fields.get("service") {
            request = request.query(&[("service", service)]);
        }
        if let Some(scope) = fields.get("scope") {
            request = request.query(&[("scope", scope)]);
        }

        let response = request.send().await?;
        let response = ensure_success(response, realm)?;
        let token: RegistryToken = response.json().await?;

        token
            .token
            .or(token.access_token)
            .ok_or(LayerError::MissingRegistryToken)
    }

    fn manifest_url(&self, reference: &str) -> String {
        format!(
            "{}://{}/v2/{}/manifests/{}",
            self.image.registry_scheme(),
            self.image.registry,
            self.image.repository,
            reference
        )
    }

    fn blob_url(&self, digest: &str) -> String {
        format!(
            "{}://{}/v2/{}/blobs/{}",
            self.image.registry_scheme(),
            self.image.registry,
            self.image.repository,
            digest
        )
    }
}

async fn inspect_registry_layers(
    registry: &RegistryClient,
    image: &str,
    layers: Vec<Descriptor>,
    options: &ExtractOptions,
) -> LayerResult<Sbom> {
    check_layer_count(layers.len())?;
    let max_concurrency = options.max_concurrent_layers.max(1);
    let max_decompressed_bytes = options.max_decompressed_layer_bytes;

    let tasks = stream::iter(layers.into_iter().enumerate().map(|(depth, descriptor)| {
        let registry = registry.clone();
        async move {
            let media_type = descriptor.media_type.clone();
            let digest = descriptor.digest.clone();
            let layer_path = registry.fetch_blob(&descriptor).await?;

            tokio::task::spawn_blocking(move || {
                inspect_layer_file(
                    &layer_path,
                    digest,
                    depth,
                    media_type.as_deref(),
                    max_decompressed_bytes,
                )
            })
            .await
            .map_err(|source| LayerError::Join {
                context: "inspecting cached layer",
                source,
            })?
        }
    }))
    .buffered(max_concurrency);

    futures_util::pin_mut!(tasks);
    let mut layer_sboms = Vec::new();
    while let Some(layer) = tasks.next().await {
        layer_sboms.push(layer?);
    }
    layer_sboms.sort_by_key(|layer| layer.depth);

    Ok(Sbom {
        image: image.to_owned(),
        layers: layer_sboms,
    })
}

fn inspect_local_archive(
    path: &Path,
    image: String,
    options: &ExtractOptions,
) -> LayerResult<Sbom> {
    let files = read_archive_files(path)?;

    if let Some(index) = files.get("index.json") {
        return inspect_oci_archive(index, &files, image, options);
    }

    if let Some(manifest) = files.get("manifest.json") {
        return inspect_docker_archive(manifest, &files, image, options);
    }

    let layer_bytes = std::fs::read(path).map_err(|source| LayerError::LocalArchiveRead {
        path: path.to_path_buf(),
        source,
    })?;
    let digest = sha256_digest(&layer_bytes);
    let layer = inspect_layer_bytes(
        layer_bytes,
        digest,
        0,
        None,
        options.max_decompressed_layer_bytes,
    )?;

    Ok(Sbom {
        image,
        layers: vec![layer],
    })
}

fn inspect_oci_archive(
    index: &[u8],
    files: &HashMap<String, Vec<u8>>,
    image: String,
    options: &ExtractOptions,
) -> LayerResult<Sbom> {
    let index: OciIndex = parse_json("OCI image index", index)?;
    let manifest_descriptor = select_platform_manifest(&index.manifests)?;
    let manifest_path = blob_path_for_digest(&manifest_descriptor.digest)?;
    let manifest_bytes =
        files
            .get(&manifest_path)
            .ok_or_else(|| LayerError::MissingArchiveEntry {
                path: manifest_path.clone(),
            })?;
    let manifest: ImageManifest = parse_json("OCI image manifest", manifest_bytes)?;
    let layers = manifest.layers.ok_or(LayerError::MissingLayers)?;
    check_layer_count(layers.len())?;

    let mut layer_sboms = Vec::with_capacity(layers.len());
    for (depth, descriptor) in layers.into_iter().enumerate() {
        let layer_path = blob_path_for_digest(&descriptor.digest)?;
        let layer_bytes = files
            .get(&layer_path)
            .ok_or_else(|| LayerError::MissingArchiveEntry {
                path: layer_path.clone(),
            })?
            .clone();
        layer_sboms.push(inspect_layer_bytes(
            layer_bytes,
            descriptor.digest,
            depth,
            descriptor.media_type.as_deref(),
            options.max_decompressed_layer_bytes,
        )?);
    }

    Ok(Sbom {
        image,
        layers: layer_sboms,
    })
}

fn inspect_docker_archive(
    manifest: &[u8],
    files: &HashMap<String, Vec<u8>>,
    fallback_image: String,
    options: &ExtractOptions,
) -> LayerResult<Sbom> {
    let manifests: Vec<DockerArchiveManifest> = parse_json("Docker archive manifest", manifest)?;
    let manifest = manifests
        .first()
        .ok_or(LayerError::UnsupportedLocalArchive {
            path: PathBuf::new(),
        })?;
    check_layer_count(manifest.layers.len())?;

    let image = manifest
        .repo_tags
        .as_ref()
        .and_then(|tags| tags.first())
        .cloned()
        .unwrap_or(fallback_image);

    let mut layer_sboms = Vec::with_capacity(manifest.layers.len());
    for (depth, layer_path) in manifest.layers.iter().enumerate() {
        let layer_bytes = files
            .get(layer_path)
            .ok_or_else(|| LayerError::MissingArchiveEntry {
                path: layer_path.clone(),
            })?
            .clone();
        let digest = sha256_digest(&layer_bytes);
        layer_sboms.push(inspect_layer_bytes(
            layer_bytes,
            digest,
            depth,
            None,
            options.max_decompressed_layer_bytes,
        )?);
    }

    Ok(Sbom {
        image,
        layers: layer_sboms,
    })
}

fn read_archive_files(path: &Path) -> LayerResult<HashMap<String, Vec<u8>>> {
    let file = File::open(path).map_err(|source| LayerError::LocalArchiveRead {
        path: path.to_path_buf(),
        source,
    })?;
    let mut archive = Archive::new(file);
    let entries = archive.entries().map_err(|source| LayerError::Io {
        context: "reading local image archive entries",
        source,
    })?;
    let mut files = HashMap::new();
    let mut total_size = 0_u64;

    for entry in entries {
        let mut entry = entry.map_err(|source| LayerError::Io {
            context: "reading local image archive entry",
            source,
        })?;
        let path = entry.path().map_err(|source| LayerError::Io {
            context: "reading local image archive entry path",
            source,
        })?;
        let path = path.into_owned();
        validate_tar_path(&path)?;

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            validate_link_target(&path, &mut entry)?;
            continue;
        }
        if !entry_type.is_file() {
            continue;
        }

        let size = entry.header().size().map_err(|source| LayerError::Io {
            context: "reading local image archive entry size",
            source,
        })?;
        total_size = total_size.saturating_add(size);
        if total_size > MAX_LOCAL_ARCHIVE_BYTES {
            return Err(LayerError::LayerTooLarge {
                digest: path.display().to_string(),
                limit: MAX_LOCAL_ARCHIVE_BYTES,
            });
        }

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|source| LayerError::Io {
                context: "reading local image archive entry bytes",
                source,
            })?;
        files.insert(normalize_tar_path(&path), bytes);
    }

    Ok(files)
}

fn inspect_layer_file(
    path: &Path,
    digest: String,
    depth: usize,
    media_type: Option<&str>,
    max_decompressed_bytes: u64,
) -> LayerResult<LayerSbom> {
    let file = File::open(path).map_err(|source| LayerError::Io {
        context: "opening cached layer",
        source,
    })?;

    inspect_layer_reader(file, digest, depth, media_type, max_decompressed_bytes)
}

fn inspect_layer_bytes(
    bytes: Vec<u8>,
    digest: String,
    depth: usize,
    media_type: Option<&str>,
    max_decompressed_bytes: u64,
) -> LayerResult<LayerSbom> {
    inspect_layer_reader(
        Cursor::new(bytes),
        digest,
        depth,
        media_type,
        max_decompressed_bytes,
    )
}

fn inspect_layer_reader<R: Read + 'static>(
    reader: R,
    digest: String,
    depth: usize,
    media_type: Option<&str>,
    max_decompressed_bytes: u64,
) -> LayerResult<LayerSbom> {
    let mut raw = BufReader::new(reader);
    let magic = raw.fill_buf().map_err(|source| LayerError::Io {
        context: "reading layer compression header",
        source,
    })?;
    let compression = LayerCompression::detect(media_type, magic)?;
    let decoded: Box<dyn Read> = match compression {
        LayerCompression::Tar => Box::new(raw),
        LayerCompression::Gzip => Box::new(GzDecoder::new(raw)),
        LayerCompression::Zstd => Box::new(zstd::stream::read::Decoder::new(raw).map_err(
            |source| LayerError::Io {
                context: "opening zstd-compressed layer",
                source,
            },
        )?),
    };

    let capped = CappedReader::new(decoded, digest.clone(), max_decompressed_bytes);
    inspect_tar_stream(capped, digest, depth)
}

fn inspect_tar_stream<R: Read>(reader: R, digest: String, depth: usize) -> LayerResult<LayerSbom> {
    let mut archive = Archive::new(reader);
    let entries = archive.entries().map_err(|source| LayerError::Io {
        context: "reading layer tar entries",
        source,
    })?;
    let mut packages = Vec::new();

    for entry in entries {
        let mut entry = entry.map_err(|source| LayerError::Io {
            context: "reading layer tar entry",
            source,
        })?;
        let path = entry.path().map_err(|source| LayerError::Io {
            context: "reading layer tar entry path",
            source,
        })?;
        let path = path.into_owned();
        validate_tar_path(&path)?;

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            validate_link_target(&path, &mut entry)?;
            continue;
        }
        if !entry_type.is_file() {
            continue;
        }

        let normalized = normalize_tar_path(&path);
        let source_path = format!("/{normalized}");

        match normalized.as_str() {
            "var/lib/dpkg/status" => {
                let mut contents = String::new();
                entry
                    .read_to_string(&mut contents)
                    .map_err(|source| LayerError::Io {
                        context: "reading dpkg status database",
                        source,
                    })?;
                packages.extend(parse_dpkg_status(&contents, &source_path));
            }
            "lib/apk/db/installed" => {
                let mut contents = String::new();
                entry
                    .read_to_string(&mut contents)
                    .map_err(|source| LayerError::Io {
                        context: "reading apk installed database",
                        source,
                    })?;
                packages.extend(parse_apk_installed(&contents, &source_path));
            }
            "var/lib/rpm/Packages" => {
                warn!(
                    source_path = source_path,
                    "rpm package database parsing is not implemented; skipping package DB"
                );
            }
            _ => {}
        }
    }

    Ok(LayerSbom {
        digest,
        depth,
        packages,
    })
}

fn parse_dpkg_status(contents: &str, source_path: &str) -> Vec<Package> {
    contents
        .split("\n\n")
        .filter_map(|paragraph| {
            let mut name = None;
            let mut version = None;

            for line in paragraph.lines() {
                if let Some(value) = line.strip_prefix("Package:") {
                    name = Some(value.trim());
                } else if let Some(value) = line.strip_prefix("Version:") {
                    version = Some(value.trim());
                }
            }

            match (name, version) {
                (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
                    Some(Package {
                        name: name.to_owned(),
                        version: version.to_owned(),
                        ecosystem: "dpkg".to_owned(),
                        source_path: source_path.to_owned(),
                    })
                }
                _ => None,
            }
        })
        .collect()
}

fn parse_apk_installed(contents: &str, source_path: &str) -> Vec<Package> {
    contents
        .split("\n\n")
        .filter_map(|paragraph| {
            let mut name = None;
            let mut version = None;

            for line in paragraph.lines() {
                if let Some(value) = line.strip_prefix("P:") {
                    name = Some(value.trim());
                } else if let Some(value) = line.strip_prefix("V:") {
                    version = Some(value.trim());
                }
            }

            match (name, version) {
                (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
                    Some(Package {
                        name: name.to_owned(),
                        version: version.to_owned(),
                        ecosystem: "apk".to_owned(),
                        source_path: source_path.to_owned(),
                    })
                }
                _ => None,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
struct ImageManifest {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    layers: Option<Vec<Descriptor>>,
    manifests: Option<Vec<Descriptor>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OciIndex {
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Clone, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
    platform: Option<Platform>,
}

#[derive(Debug, Clone, Deserialize)]
struct Platform {
    architecture: Option<String>,
    os: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistryToken {
    token: Option<String>,
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DockerArchiveManifest {
    #[serde(rename = "RepoTags")]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum LayerCompression {
    Tar,
    Gzip,
    Zstd,
}

impl LayerCompression {
    fn detect(media_type: Option<&str>, magic: &[u8]) -> LayerResult<Self> {
        let media_type = media_type.unwrap_or_default();
        if media_type.contains("zstd") || magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            return Ok(Self::Zstd);
        }
        if media_type.contains("gzip") || magic.starts_with(&[0x1f, 0x8b]) {
            return Ok(Self::Gzip);
        }
        if media_type.is_empty() || media_type.ends_with(".tar") || media_type.ends_with(".tar+") {
            return Ok(Self::Tar);
        }
        if media_type.contains("layer") && media_type.contains("tar") {
            return Ok(Self::Tar);
        }

        Err(LayerError::UnsupportedLayerMediaType(media_type.to_owned()))
    }
}

struct CappedReader<R> {
    inner: R,
    digest: String,
    read: u64,
    limit: u64,
}

impl<R> CappedReader<R> {
    fn new(inner: R, digest: String, limit: u64) -> Self {
        Self {
            inner,
            digest,
            read: 0,
            limit,
        }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.read >= self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LayerError::LayerTooLarge {
                    digest: self.digest.clone(),
                    limit: self.limit,
                }
                .to_string(),
            ));
        }

        let remaining = (self.limit - self.read) as usize;
        let max = remaining.min(buf.len());
        let count = self.inner.read(&mut buf[..max])?;
        self.read += count as u64;
        Ok(count)
    }
}

fn select_platform_manifest(manifests: &[Descriptor]) -> LayerResult<Descriptor> {
    if manifests.is_empty() {
        return Err(LayerError::EmptyImageIndex);
    }

    if let Some(manifest) = manifests.iter().find(|manifest| {
        manifest.platform.as_ref().is_some_and(|platform| {
            platform.os.as_deref() == Some("linux")
                && platform.architecture.as_deref() == Some("amd64")
        })
    }) {
        return Ok(manifest.clone());
    }

    Ok(manifests[0].clone())
}

fn check_layer_count(count: usize) -> LayerResult<()> {
    if count > MAX_LAYER_COUNT {
        return Err(LayerError::TooManyLayers {
            count,
            max: MAX_LAYER_COUNT,
        });
    }

    Ok(())
}

fn validate_tar_path(path: &Path) -> LayerResult<()> {
    let raw = path.as_os_str().to_string_lossy();
    if raw.starts_with('/') || raw.starts_with('\\') || raw.is_empty() {
        return Err(LayerError::UnsafeTarPath {
            path: path.to_path_buf(),
        });
    }

    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(LayerError::UnsafeTarPath {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    Ok(())
}

fn validate_link_target<R: Read>(path: &Path, entry: &mut tar::Entry<'_, R>) -> LayerResult<()> {
    let target = entry.link_name().map_err(|source| LayerError::Io {
        context: "reading tar link target",
        source,
    })?;

    if let Some(target) = target {
        let target = target.into_owned();
        if validate_tar_path(&target).is_err() {
            return Err(LayerError::UnsafeTarLink {
                path: path.to_path_buf(),
                target,
            });
        }
    }

    Ok(())
}

fn normalize_tar_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            Component::CurDir => None,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn blob_path_for_digest(digest: &str) -> LayerResult<String> {
    let (algorithm, value) = digest
        .split_once(':')
        .ok_or_else(|| LayerError::InvalidImageRef {
            reference: digest.to_owned(),
            reason: "digest is missing algorithm",
        })?;
    if algorithm.is_empty() || value.is_empty() {
        return Err(LayerError::InvalidImageRef {
            reference: digest.to_owned(),
            reason: "digest is incomplete",
        });
    }

    Ok(format!("blobs/{algorithm}/{value}"))
}

fn cache_path_for_digest(digest: &str) -> LayerResult<PathBuf> {
    let mut cache_dir = cache_root()?;
    cache_dir.push(digest.replace(':', "_"));
    Ok(cache_dir)
}

fn cache_root() -> LayerResult<PathBuf> {
    if let Some(path) = env::var_os("MANIFESTVAULT_CACHE_DIR") {
        return Ok(PathBuf::from(path));
    }

    if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(path).join("manifestvault").join("layers"));
    }

    if let Some(path) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        return Ok(PathBuf::from(path)
            .join(".cache")
            .join("manifestvault")
            .join("layers"));
    }

    Err(LayerError::InvalidImageRef {
        reference: "cache directory".to_owned(),
        reason: "neither MANIFESTVAULT_CACHE_DIR, XDG_CACHE_HOME, USERPROFILE, nor HOME is set",
    })
}

fn ensure_success(response: reqwest::Response, url: &str) -> LayerResult<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(LayerError::RegistryStatus {
            url: url.to_owned(),
            status,
        })
    }
}

fn parse_json<T: DeserializeOwned>(context: &'static str, bytes: &[u8]) -> LayerResult<T> {
    serde_json::from_slice(bytes).map_err(|source| LayerError::Parse { context, source })
}

fn parse_auth_challenge(challenge: &str) -> LayerResult<HashMap<String, String>> {
    let challenge = challenge.trim();
    let params = challenge
        .strip_prefix("Bearer ")
        .ok_or_else(|| LayerError::UnsupportedAuthChallenge(challenge.to_owned()))?;
    let mut parsed = HashMap::new();

    for field in params.split(',') {
        let Some((key, value)) = field.trim().split_once('=') else {
            continue;
        };
        parsed.insert(
            key.trim().to_owned(),
            value.trim().trim_matches('"').to_owned(),
        );
    }

    Ok(parsed)
}

fn is_manifest_list_media_type(media_type: &str) -> bool {
    media_type.contains("image.index") || media_type.contains("manifest.list")
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity("sha256:".len() + digest.len() * 2);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        ExtractOptions, LayerError, Package, SbomExtractor, inspect_layer_bytes,
        parse_apk_installed, parse_dpkg_status, validate_tar_path,
    };

    #[test]
    fn parses_dpkg_status_packages() {
        let packages = parse_dpkg_status(
            "Package: base-files\nVersion: 13ubuntu10\n\nPackage: libc6\nVersion: 2.39-0ubuntu8\n",
            "/var/lib/dpkg/status",
        );

        assert_eq!(
            packages,
            vec![
                Package {
                    name: "base-files".to_owned(),
                    version: "13ubuntu10".to_owned(),
                    ecosystem: "dpkg".to_owned(),
                    source_path: "/var/lib/dpkg/status".to_owned(),
                },
                Package {
                    name: "libc6".to_owned(),
                    version: "2.39-0ubuntu8".to_owned(),
                    ecosystem: "dpkg".to_owned(),
                    source_path: "/var/lib/dpkg/status".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn parses_apk_installed_packages() {
        let packages = parse_apk_installed(
            "P:alpine-baselayout\nV:3.6.8-r1\n\nP:busybox\nV:1.36.1-r29\n",
            "/lib/apk/db/installed",
        );

        assert_eq!(
            packages,
            vec![
                Package {
                    name: "alpine-baselayout".to_owned(),
                    version: "3.6.8-r1".to_owned(),
                    ecosystem: "apk".to_owned(),
                    source_path: "/lib/apk/db/installed".to_owned(),
                },
                Package {
                    name: "busybox".to_owned(),
                    version: "1.36.1-r29".to_owned(),
                    ecosystem: "apk".to_owned(),
                    source_path: "/lib/apk/db/installed".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn rejects_tar_path_traversal() {
        let err = validate_tar_path(Path::new("../var/lib/dpkg/status"))
            .expect_err("unsafe path should fail");

        assert!(matches!(err, LayerError::UnsafeTarPath { .. }));
    }

    #[test]
    fn extracts_apk_packages_from_layer_tar() {
        let mut tar = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar);
            let contents = "P:alpine-baselayout\nV:3.6.8-r1\n\nP:busybox\nV:1.36.1-r29\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "lib/apk/db/installed", contents.as_bytes())
                .expect("append apk db");
            builder.finish().expect("finish tar");
        }

        let sbom = inspect_layer_bytes(tar, "sha256:test".to_owned(), 0, None, 1024 * 1024)
            .expect("layer sbom");

        assert_eq!(sbom.depth, 0);
        assert_eq!(sbom.packages.len(), 2);
        assert_eq!(sbom.packages[1].name, "busybox");
    }

    #[tokio::test]
    async fn extracts_sbom_from_alpine_fixture() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("alpine-3.20-oci.tar");
        let extractor = SbomExtractor::with_options(ExtractOptions {
            max_concurrent_layers: 2,
            max_decompressed_layer_bytes: 10 * 1024 * 1024,
        });

        let sbom = extractor
            .extract(&fixture.display().to_string())
            .await
            .expect("fixture sbom");
        let packages = &sbom.layers[0].packages;

        assert_eq!(sbom.layers[0].depth, 0);
        assert!(packages.len() >= 5);
        assert!(packages.iter().any(|package| {
            package.name == "alpine-baselayout" && package.version == "3.6.5-r0"
        }));
        assert!(
            packages
                .iter()
                .any(|package| package.name == "busybox" && package.version == "1.36.1-r29")
        );
    }
}
