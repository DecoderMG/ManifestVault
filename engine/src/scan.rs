use std::path::{Path, PathBuf};

use crate::{
    error::Result,
    layer::{ContainerSbom, Sbom, load_container_sbom},
    manifest::{Workload, parse_path},
    report::Report,
    score::{CveDatabase, score},
};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub target: PathBuf,
    pub cve_feed: PathBuf,
}

impl ScanOptions {
    pub fn new(target: impl Into<PathBuf>, cve_feed: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
            cve_feed: cve_feed.into(),
        }
    }
}

pub async fn scan(options: ScanOptions) -> Result<Report> {
    tracing::info!(
        manifest_path = %options.target.display(),
        cve_feed = %options.cve_feed.display(),
        "starting manifest scan"
    );

    let workloads = parse_path(&options.target).await?;
    let cves = CveDatabase::load_from_dir(&options.cve_feed)?;
    let base_dir = target_base_dir(&options.target);
    let mut workload_reports = Vec::with_capacity(workloads.len());

    for workload in &workloads {
        let sbom = load_workload_sbom(workload, base_dir, &options.cve_feed)?;
        workload_reports.push(score(workload, &sbom, &cves));
    }

    Ok(Report::new(workload_reports))
}

fn load_workload_sbom(workload: &Workload, base_dir: &Path, cve_feed: &Path) -> Result<Sbom> {
    let mut sbom = Sbom::empty();

    for container in &workload.containers {
        let container_sbom = match container.image.as_deref().and_then(|image| {
            resolve_sbom_path(image, base_dir, cve_feed)
        }) {
            Some(path) => load_container_sbom(&path, &container.name, container.image.clone())?,
            None => ContainerSbom::empty(container.name.clone(), container.image.clone()),
        };
        sbom.containers.push(container_sbom);
    }

    Ok(sbom)
}

fn target_base_dir(target: &Path) -> &Path {
    if target.is_dir() {
        target
    } else {
        target.parent().unwrap_or_else(|| Path::new("."))
    }
}

fn resolve_sbom_path(image: &str, base_dir: &Path, cve_feed: &Path) -> Option<PathBuf> {
    let image_path = Path::new(image);
    let mut candidates = Vec::new();

    if image_path.is_absolute() {
        candidates.push(image_path.to_path_buf());
    } else {
        candidates.push(base_dir.join(image_path));
    }

    let sanitized = sanitize_image_ref(image);
    candidates.push(base_dir.join("sbom").join(format!("{sanitized}.json")));
    candidates.push(cve_feed.join("sbom").join(format!("{sanitized}.json")));

    candidates
        .into_iter()
        .find(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "json")
        })
}

fn sanitize_image_ref(image: &str) -> String {
    image
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{ScanOptions, scan};

    #[tokio::test]
    async fn scan_returns_empty_workload_report_without_sbom() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sample = dir.path().join("sample.yaml");
        let cve_feed = dir.path().join("cves");
        std::fs::create_dir(&cve_feed).expect("cve feed dir");
        std::fs::write(
            &sample,
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  containers:
    - name: api
      image: nginx:1.27
"#,
        )
        .expect("sample manifest");

        let report = scan(ScanOptions::new(sample, cve_feed))
            .await
            .expect("scan");

        assert_eq!(report.workloads.len(), 1);
        assert!(report.workloads[0].findings.is_empty());
    }

    #[tokio::test]
    async fn scan_uses_sbom_sidecar_from_cve_bundle() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sample = dir.path().join("sample.yaml");
        let cve_feed = dir.path().join("cves");
        let sbom_dir = cve_feed.join("sbom");
        std::fs::create_dir_all(&sbom_dir).expect("sbom dir");
        std::fs::write(
            &sample,
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  containers:
    - name: app
      image: alpine:3.18
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
"#,
        )
        .expect("sample manifest");
        std::fs::write(
            cve_feed.join("openssl.json"),
            r#"
{
  "id": "CVE-TEST-OPENSSL",
  "severity": [{"type": "CVSS_V3", "score": "8.1"}],
  "affected": [{
    "package": {"ecosystem": "Alpine", "name": "openssl"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-r0"}]}]
  }]
}
"#,
        )
        .expect("cve feed");
        std::fs::write(
            sbom_dir.join("alpine_3_18.json"),
            r#"
{
  "layers": [
    {
      "digest": "sha256:base",
      "depth": 0,
      "packages": [
        {
          "name": "openssl",
          "version": "3.1.0-r0",
          "ecosystem": "alpine",
          "source_path": "/lib/apk/db/installed"
        }
      ]
    }
  ]
}
"#,
        )
        .expect("sbom");

        let report = scan(ScanOptions::new(sample, cve_feed))
            .await
            .expect("scan");

        assert_eq!(report.workloads[0].findings.len(), 1);
        assert_eq!(report.workloads[0].cii_total, 4.9);
    }
}
