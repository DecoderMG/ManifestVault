use manifestvault_engine::{WorkloadKind, parse_path};

#[tokio::test]
async fn parses_directory_with_mixed_manifests_deterministically() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut expected_names = Vec::new();

    for index in 0..60 {
        let name = format!("workload-{index:03}");
        expected_names.push(name.clone());
        let file = dir.path().join(format!("{index:03}-manifest.yaml"));
        let manifest = match index % 3 {
            0 => pod_manifest(&name),
            1 => deployment_manifest(&name),
            _ => job_manifest(&name),
        };

        std::fs::write(file, manifest).expect("manifest file");
    }

    let workloads = parse_path(dir.path()).await.expect("parse directory");
    let names = workloads
        .iter()
        .map(|workload| workload.name.as_str())
        .collect::<Vec<_>>();
    let expected = expected_names
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    assert_eq!(workloads.len(), 60);
    assert_eq!(names, expected);
    assert_eq!(workloads[0].kind, WorkloadKind::Pod);
    assert_eq!(workloads[1].kind, WorkloadKind::Deployment);
    assert_eq!(workloads[2].kind, WorkloadKind::Job);
}

fn pod_manifest(name: &str) -> String {
    format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  containers:
    - name: app
      image: nginx:1.27
"#
    )
}

fn deployment_manifest(name: &str) -> String {
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
        - name: app
          image: nginx:1.27
"#
    )
}

fn job_manifest(name: &str) -> String {
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
        - name: app
          image: busybox:1.36
"#
    )
}
