use std::path::PathBuf;

use thiserror::Error;

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

    #[error("failed to render report")]
    RenderReport(#[from] serde_json::Error),
}
