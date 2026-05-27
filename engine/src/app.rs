use crate::{
    cli::{Cli, Command},
    error::Result,
    report,
    scan::{ScanOptions, scan},
};

pub async fn run(cli: Cli) -> Result<String> {
    match cli.command {
        Command::Scan(args) => {
            let report = scan(ScanOptions::new(args.path, args.cve_feed)).await?;
            report::render(&report, args.output)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::{Cli, Command, OutputFormat, ScanArgs},
        run,
    };

    #[tokio::test]
    async fn scan_command_renders_json_report() {
        let dir = tempfile::tempdir().expect("temp dir");
        let sample = dir.path().join("sample.yaml");
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

        let cli = Cli {
            command: Command::Scan(ScanArgs {
                path: sample.clone(),
                cve_feed: dir.path().join("cves"),
                output: OutputFormat::Json,
            }),
        };
        std::fs::create_dir(dir.path().join("cves")).expect("cve feed");

        let rendered = run(cli).await.expect("scan output");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(parsed["workloads"][0]["workload_ref"]["name"], "api");
        assert_eq!(parsed["workloads"][0]["findings"], serde_json::json!([]));
    }
}
