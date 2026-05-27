use std::path::{Path, PathBuf};

use k8s_openapi::api::{
    apps::v1::{DaemonSet, Deployment, StatefulSet},
    batch::v1::{CronJob, Job},
    core::v1::{Container, Pod, PodSpec, SecurityContext},
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_yaml::Value;
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Manifest {
    pub path: PathBuf,
}

impl Manifest {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    pub kind: WorkloadKind,
    pub name: String,
    pub namespace: Option<String>,
    pub containers: Vec<ContainerRef>,
    pub service_account: Option<String>,
    pub host_network: bool,
    pub host_pid: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum WorkloadKind {
    Pod,
    Deployment,
    StatefulSet,
    DaemonSet,
    Job,
    CronJob,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerRef {
    pub name: String,
    pub image: Option<String>,
    pub image_pull_policy: Option<String>,
    pub security_context: Option<ContainerSecurityContext>,
    pub command: Vec<String>,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerSecurityContext {
    pub allow_privilege_escalation: Option<bool>,
    pub privileged: Option<bool>,
    pub read_only_root_filesystem: Option<bool>,
    pub run_as_group: Option<i64>,
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SourceLocation {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to read manifest path {path:?}")]
    ReadPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read manifest directory {path:?}")]
    ReadDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read manifest file {path:?}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "failed to parse manifest {path:?} document {document_index} at line {line}, column {column}"
    )]
    InvalidYaml {
        path: PathBuf,
        document_index: usize,
        line: usize,
        column: usize,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("failed to parse manifest {path:?} document {document_index}")]
    InvalidYamlWithoutLocation {
        path: PathBuf,
        document_index: usize,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("manifest {path:?} document {document_index} is empty")]
    EmptyDocument {
        path: PathBuf,
        document_index: usize,
    },

    #[error("manifest {path:?} document {document_index} is missing required field {field}")]
    MissingRequiredField {
        path: PathBuf,
        document_index: usize,
        field: &'static str,
    },

    #[error(
        "manifest {path:?} document {document_index} uses unsupported apiVersion {api_version:?} for kind {kind:?}"
    )]
    UnsupportedApiVersion {
        path: PathBuf,
        document_index: usize,
        api_version: String,
        kind: String,
    },

    #[error("manifest {path:?} document {document_index} uses unsupported kind {kind:?}")]
    UnsupportedKind {
        path: PathBuf,
        document_index: usize,
        kind: String,
    },

    #[error("manifest {path:?} document {document_index} contains unknown field {field_path}")]
    UnknownField {
        path: PathBuf,
        document_index: usize,
        field_path: String,
    },

    #[error("manifest {path:?} document {document_index} is not a valid {kind:?}")]
    Decode {
        path: PathBuf,
        document_index: usize,
        kind: WorkloadKind,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("manifest path {path:?} is neither a file nor a directory")]
    UnsupportedPath { path: PathBuf },

    #[error("manifest parse task failed for {path:?}")]
    Join {
        path: PathBuf,
        #[source]
        source: tokio::task::JoinError,
    },
}

impl ManifestError {
    pub fn path(&self) -> &Path {
        match self {
            Self::ReadPath { path, .. }
            | Self::ReadDirectory { path, .. }
            | Self::ReadFile { path, .. }
            | Self::InvalidYaml { path, .. }
            | Self::InvalidYamlWithoutLocation { path, .. }
            | Self::EmptyDocument { path, .. }
            | Self::MissingRequiredField { path, .. }
            | Self::UnsupportedApiVersion { path, .. }
            | Self::UnsupportedKind { path, .. }
            | Self::UnknownField { path, .. }
            | Self::Decode { path, .. }
            | Self::UnsupportedPath { path }
            | Self::Join { path, .. } => path,
        }
    }

    pub fn location(&self) -> Option<SourceLocation> {
        match self {
            Self::InvalidYaml { line, column, .. } => Some(SourceLocation {
                line: *line,
                column: *column,
            }),
            Self::InvalidYamlWithoutLocation { .. }
            | Self::ReadPath { .. }
            | Self::ReadDirectory { .. }
            | Self::ReadFile { .. }
            | Self::EmptyDocument { .. }
            | Self::MissingRequiredField { .. }
            | Self::UnsupportedApiVersion { .. }
            | Self::UnsupportedKind { .. }
            | Self::UnknownField { .. }
            | Self::Decode { .. }
            | Self::UnsupportedPath { .. }
            | Self::Join { .. } => None,
        }
    }
}

pub async fn parse_path(path: &Path) -> Result<Vec<Workload>, ManifestError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|source| ManifestError::ReadPath {
            path: path.to_path_buf(),
            source,
        })?;

    if metadata.is_file() {
        return parse_file(path).await;
    }

    if metadata.is_dir() {
        return parse_directory(path).await;
    }

    Err(ManifestError::UnsupportedPath {
        path: path.to_path_buf(),
    })
}

async fn parse_directory(path: &Path) -> Result<Vec<Workload>, ManifestError> {
    let mut entries =
        tokio::fs::read_dir(path)
            .await
            .map_err(|source| ManifestError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            })?;
    let mut files = Vec::new();

    while let Some(entry) =
        entries
            .next_entry()
            .await
            .map_err(|source| ManifestError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            })?
    {
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .await
            .map_err(|source| ManifestError::ReadDirectory {
                path: entry_path.clone(),
                source,
            })?;

        if file_type.is_file() {
            files.push(entry_path);
        }
    }

    files.sort();

    let mut handles = Vec::with_capacity(files.len());
    for file in files {
        let task_path = file.clone();
        let handle = tokio::spawn(async move { parse_file(&task_path).await });
        handles.push((file, handle));
    }

    let mut workloads = Vec::new();
    for (file, handle) in handles {
        let mut parsed = handle
            .await
            .map_err(|source| ManifestError::Join { path: file, source })??;
        workloads.append(&mut parsed);
    }

    Ok(workloads)
}

async fn parse_file(path: &Path) -> Result<Vec<Workload>, ManifestError> {
    let content =
        tokio::fs::read_to_string(path)
            .await
            .map_err(|source| ManifestError::ReadFile {
                path: path.to_path_buf(),
                source,
            })?;

    parse_content(path, &content)
}

fn parse_content(path: &Path, content: &str) -> Result<Vec<Workload>, ManifestError> {
    let mut workloads = Vec::new();

    for (document_index, document) in serde_yaml::Deserializer::from_str(content).enumerate() {
        let document_index = document_index + 1;
        let value = Value::deserialize(document)
            .map_err(|source| yaml_error(path, document_index, source))?;
        workloads.push(parse_document(path, document_index, value)?);
    }

    Ok(workloads)
}

fn parse_document(
    path: &Path,
    document_index: usize,
    value: Value,
) -> Result<Workload, ManifestError> {
    if value == Value::Null {
        return Err(ManifestError::EmptyDocument {
            path: path.to_path_buf(),
            document_index,
        });
    }

    let api_version = required_string(path, document_index, &value, "apiVersion")?;
    let kind = required_string(path, document_index, &value, "kind")?;
    let workload_kind = workload_kind(path, document_index, &api_version, &kind)?;

    match workload_kind {
        WorkloadKind::Pod => {
            let pod: Pod = deserialize_strict(path, document_index, workload_kind, value)?;
            let spec = pod
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec"))?;
            normalize_workload(path, document_index, workload_kind, &pod.metadata, spec)
        }
        WorkloadKind::Deployment => {
            let deployment: Deployment =
                deserialize_strict(path, document_index, workload_kind, value)?;
            let spec = deployment
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec"))?;
            let pod_spec = spec
                .template
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec.template.spec"))?;
            normalize_workload(
                path,
                document_index,
                workload_kind,
                &deployment.metadata,
                pod_spec,
            )
        }
        WorkloadKind::StatefulSet => {
            let stateful_set: StatefulSet =
                deserialize_strict(path, document_index, workload_kind, value)?;
            let spec = stateful_set
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec"))?;
            let pod_spec = spec
                .template
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec.template.spec"))?;
            normalize_workload(
                path,
                document_index,
                workload_kind,
                &stateful_set.metadata,
                pod_spec,
            )
        }
        WorkloadKind::DaemonSet => {
            let daemon_set: DaemonSet =
                deserialize_strict(path, document_index, workload_kind, value)?;
            let spec = daemon_set
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec"))?;
            let pod_spec = spec
                .template
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec.template.spec"))?;
            normalize_workload(
                path,
                document_index,
                workload_kind,
                &daemon_set.metadata,
                pod_spec,
            )
        }
        WorkloadKind::Job => {
            let job: Job = deserialize_strict(path, document_index, workload_kind, value)?;
            let spec = job
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec"))?;
            let pod_spec = spec
                .template
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec.template.spec"))?;
            normalize_workload(path, document_index, workload_kind, &job.metadata, pod_spec)
        }
        WorkloadKind::CronJob => {
            let cron_job: CronJob = deserialize_strict(path, document_index, workload_kind, value)?;
            let spec = cron_job
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec"))?;
            let job_spec = spec
                .job_template
                .spec
                .as_ref()
                .ok_or_else(|| missing_field(path, document_index, "spec.jobTemplate.spec"))?;
            let pod_spec = job_spec.template.spec.as_ref().ok_or_else(|| {
                missing_field(path, document_index, "spec.jobTemplate.spec.template.spec")
            })?;
            normalize_workload(
                path,
                document_index,
                workload_kind,
                &cron_job.metadata,
                pod_spec,
            )
        }
    }
}

fn deserialize_strict<T>(
    path: &Path,
    document_index: usize,
    kind: WorkloadKind,
    value: Value,
) -> Result<T, ManifestError>
where
    T: DeserializeOwned,
{
    let mut ignored_field = None;
    let parsed = serde_ignored::deserialize(value, |field_path| {
        if ignored_field.is_none() {
            ignored_field = Some(field_path.to_string());
        }
    })
    .map_err(|source| ManifestError::Decode {
        path: path.to_path_buf(),
        document_index,
        kind,
        source,
    })?;

    if let Some(field_path) = ignored_field {
        return Err(ManifestError::UnknownField {
            path: path.to_path_buf(),
            document_index,
            field_path,
        });
    }

    Ok(parsed)
}

fn normalize_workload(
    path: &Path,
    document_index: usize,
    kind: WorkloadKind,
    metadata: &ObjectMeta,
    spec: &PodSpec,
) -> Result<Workload, ManifestError> {
    let name = metadata
        .name
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| missing_field(path, document_index, "metadata.name"))?;
    let containers = normalize_containers(&spec.containers);

    if containers.is_empty() {
        return Err(missing_field(path, document_index, "spec.containers"));
    }

    let privileged = containers.iter().any(|container| {
        container
            .security_context
            .as_ref()
            .is_some_and(|security_context| security_context.privileged == Some(true))
    });

    Ok(Workload {
        kind,
        name,
        namespace: metadata.namespace.clone(),
        containers,
        service_account: spec
            .service_account_name
            .clone()
            .or_else(|| spec.service_account.clone()),
        host_network: spec.host_network == Some(true),
        host_pid: spec.host_pid == Some(true),
        privileged,
    })
}

fn normalize_containers(containers: &[Container]) -> Vec<ContainerRef> {
    containers
        .iter()
        .map(|container| ContainerRef {
            name: container.name.clone(),
            image: container.image.clone(),
            image_pull_policy: container.image_pull_policy.clone(),
            security_context: container
                .security_context
                .as_ref()
                .map(normalize_security_context),
            command: container.command.clone().unwrap_or_default(),
            args: container.args.clone().unwrap_or_default(),
        })
        .collect()
}

fn normalize_security_context(security_context: &SecurityContext) -> ContainerSecurityContext {
    ContainerSecurityContext {
        allow_privilege_escalation: security_context.allow_privilege_escalation,
        privileged: security_context.privileged,
        read_only_root_filesystem: security_context.read_only_root_filesystem,
        run_as_group: security_context.run_as_group,
        run_as_non_root: security_context.run_as_non_root,
        run_as_user: security_context.run_as_user,
    }
}

fn workload_kind(
    path: &Path,
    document_index: usize,
    api_version: &str,
    kind: &str,
) -> Result<WorkloadKind, ManifestError> {
    match (api_version, kind) {
        ("v1", "Pod") => Ok(WorkloadKind::Pod),
        ("apps/v1", "Deployment") => Ok(WorkloadKind::Deployment),
        ("apps/v1", "StatefulSet") => Ok(WorkloadKind::StatefulSet),
        ("apps/v1", "DaemonSet") => Ok(WorkloadKind::DaemonSet),
        ("batch/v1", "Job") => Ok(WorkloadKind::Job),
        ("batch/v1", "CronJob") => Ok(WorkloadKind::CronJob),
        ("v1" | "apps/v1" | "batch/v1", _) => Err(ManifestError::UnsupportedKind {
            path: path.to_path_buf(),
            document_index,
            kind: kind.to_owned(),
        }),
        _ => Err(ManifestError::UnsupportedApiVersion {
            path: path.to_path_buf(),
            document_index,
            api_version: api_version.to_owned(),
            kind: kind.to_owned(),
        }),
    }
}

fn required_string(
    path: &Path,
    document_index: usize,
    value: &Value,
    field: &'static str,
) -> Result<String, ManifestError> {
    let field_value = value
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String(field.to_owned())))
        .ok_or_else(|| missing_field(path, document_index, field))?;

    field_value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| missing_field(path, document_index, field))
}

fn missing_field(path: &Path, document_index: usize, field: &'static str) -> ManifestError {
    ManifestError::MissingRequiredField {
        path: path.to_path_buf(),
        document_index,
        field,
    }
}

fn yaml_error(path: &Path, document_index: usize, source: serde_yaml::Error) -> ManifestError {
    if let Some(location) = source.location() {
        return ManifestError::InvalidYaml {
            path: path.to_path_buf(),
            document_index,
            line: location.line(),
            column: location.column(),
            source,
        };
    }

    ManifestError::InvalidYamlWithoutLocation {
        path: path.to_path_buf(),
        document_index,
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ManifestError, WorkloadKind, parse_path};

    #[tokio::test]
    async fn parses_pod_and_deployment() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pod = dir.path().join("pod.yaml");
        let deployment = dir.path().join("deployment.yaml");
        std::fs::write(&pod, pod_manifest("api", "nginx:1.27")).expect("pod manifest");
        std::fs::write(&deployment, deployment_manifest("web", "nginx:1.27"))
            .expect("deployment manifest");

        let pod_workloads = parse_path(&pod).await.expect("parse pod");
        let deployment_workloads = parse_path(&deployment).await.expect("parse deployment");

        assert_eq!(pod_workloads[0].kind, WorkloadKind::Pod);
        assert_eq!(pod_workloads[0].name, "api");
        assert_eq!(pod_workloads[0].namespace.as_deref(), Some("platform"));
        assert_eq!(pod_workloads[0].service_account.as_deref(), Some("api-sa"));
        assert_eq!(
            pod_workloads[0].containers[0].image.as_deref(),
            Some("nginx:1.27")
        );
        assert_eq!(
            pod_workloads[0].containers[0].image_pull_policy.as_deref(),
            Some("IfNotPresent")
        );
        assert_eq!(deployment_workloads[0].kind, WorkloadKind::Deployment);
        assert_eq!(deployment_workloads[0].name, "web");
    }

    #[tokio::test]
    async fn parses_multi_document_yaml() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("multi.yaml");
        std::fs::write(
            &path,
            format!(
                "{}\n---\n{}",
                pod_manifest("api", "nginx:1.27"),
                job_manifest("batch", "busybox:1.36")
            ),
        )
        .expect("multi manifest");

        let workloads = parse_path(&path).await.expect("parse multi doc");

        assert_eq!(workloads.len(), 2);
        assert_eq!(workloads[0].kind, WorkloadKind::Pod);
        assert_eq!(workloads[1].kind, WorkloadKind::Job);
    }

    #[tokio::test]
    async fn malformed_yaml_reports_path_and_location() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("broken.yaml");
        std::fs::write(
            &path,
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: broken\n  :",
        )
        .expect("broken manifest");

        let err = parse_path(&path).await.expect_err("malformed YAML");

        assert_eq!(err.path(), path.as_path());
        assert!(err.location().is_some());
        assert!(matches!(
            err,
            ManifestError::InvalidYaml { .. } | ManifestError::InvalidYamlWithoutLocation { .. }
        ));
    }

    #[tokio::test]
    async fn unsupported_kind_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("service.yaml");
        std::fs::write(
            &path,
            r#"
apiVersion: v1
kind: Service
metadata:
  name: api
"#,
        )
        .expect("service manifest");

        let err = parse_path(&path).await.expect_err("unsupported kind");

        assert!(matches!(
            err,
            ManifestError::UnsupportedKind { kind, .. } if kind == "Service"
        ));
    }

    #[tokio::test]
    async fn unknown_fields_are_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("unknown-field.yaml");
        std::fs::write(
            &path,
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  madeUpField: true
  containers:
    - name: api
      image: nginx:1.27
"#,
        )
        .expect("unknown field manifest");

        let err = parse_path(&path).await.expect_err("unknown field");

        assert!(matches!(err, ManifestError::UnknownField { .. }));
    }

    #[tokio::test]
    async fn detects_privileged_container() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("privileged.yaml");
        std::fs::write(
            &path,
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-api
spec:
  containers:
    - name: api
      image: nginx:1.27
      securityContext:
        privileged: true
"#,
        )
        .expect("privileged manifest");

        let workloads = parse_path(&path).await.expect("parse privileged pod");

        assert!(workloads[0].privileged);
        assert_eq!(
            workloads[0].containers[0]
                .security_context
                .as_ref()
                .and_then(|security_context| security_context.privileged),
            Some(true)
        );
    }

    fn pod_manifest(name: &str, image: &str) -> String {
        format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: platform
spec:
  serviceAccountName: api-sa
  hostNetwork: true
  hostPID: false
  containers:
    - name: api
      image: {image}
      imagePullPolicy: IfNotPresent
      command: ["/bin/server"]
      args: ["--port", "8080"]
"#
        )
    }

    fn deployment_manifest(name: &str, image: &str) -> String {
        format!(
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
spec:
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
        - name: web
          image: {image}
"#
        )
    }

    fn job_manifest(name: &str, image: &str) -> String {
        format!(
            r#"
apiVersion: batch/v1
kind: Job
metadata:
  name: {name}
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: worker
          image: {image}
"#
        )
    }

    #[test]
    fn error_path_returns_path_for_all_pathful_variants() {
        let path = Path::new("sample.yaml");
        let err = ManifestError::UnsupportedPath {
            path: path.to_path_buf(),
        };

        assert_eq!(err.path(), path);
    }
}
