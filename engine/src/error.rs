use std::path::PathBuf;

use thiserror::Error;

use crate::{layer::LayerError, manifest::ManifestError};

pub type Result<T> = std::result::Result<T, EngineError>;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("{component} is not implemented yet")]
    Unimplemented { component: &'static str },

    #[error("failed to read scan target {path:?}")]
    ReadTarget {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read CVE feed {path:?}")]
    ReadCveFeed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse CVE feed {path:?}")]
    ParseCveFeed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("invalid CVE feed {path:?}: {reason}")]
    InvalidCveFeed {
        path: PathBuf,
        reason: &'static str,
    },

    #[error("manifest parser failed")]
    Manifest(#[from] ManifestError),

    #[error("SBOM loader failed")]
    Layer(#[from] LayerError),

    #[error("failed to render report")]
    RenderReport(#[from] serde_json::Error),
}
