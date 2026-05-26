use crate::{
    cli::{Cli, Command},
    error::Result,
    report,
    scan::{ScanOptions, scan},
};

pub async fn run(cli: Cli) -> Result<String> {
    match cli.command {
        Command::Scan(args) => {
            let report = scan(ScanOptions::new(args.path)).await?;
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
        std::fs::write(&sample, "apiVersion: v1\nkind: Pod\n").expect("sample manifest");

        let cli = Cli {
            command: Command::Scan(ScanArgs {
                path: sample.clone(),
                output: OutputFormat::Json,
            }),
        };

        let rendered = run(cli).await.expect("scan output");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(parsed["target"], sample.display().to_string());
        assert_eq!(parsed["findings"], serde_json::json!([]));
    }
}
