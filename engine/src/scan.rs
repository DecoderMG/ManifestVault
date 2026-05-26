use std::path::PathBuf;

use crate::{
    error::{EngineError, Result},
    report::Report,
};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub target: PathBuf,
}

impl ScanOptions {
    pub fn new(target: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
        }
    }
}

pub async fn scan(options: ScanOptions) -> Result<Report> {
    tracing::info!(
        manifest_path = %options.target.display(),
        "starting placeholder manifest scan"
    );

    tokio::fs::metadata(&options.target)
        .await
        .map_err(|source| EngineError::ReadTarget {
            path: options.target.clone(),
            source,
        })?;

    Ok(Report::empty(options.target.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::{ScanOptions, scan};

    #[tokio::test]
    async fn placeholder_scan_returns_empty_report() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sample = dir.path().join("sample.yaml");
        std::fs::write(&sample, "apiVersion: v1\nkind: Pod\n").expect("sample manifest");

        let report = scan(ScanOptions::new(sample.clone()))
            .await
            .expect("placeholder scan");

        assert_eq!(report.target, sample.display().to_string());
        assert!(report.findings.is_empty());
    }
}
