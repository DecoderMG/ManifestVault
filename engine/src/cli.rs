use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "manifestvault")]
#[command(about = "Analyze deployment manifests and produce a ManifestVault report.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    pub path: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, OutputFormat};
    use clap::Parser;

    #[test]
    fn parses_scan_command_with_json_output() {
        let cli = Cli::parse_from([
            "manifestvault",
            "scan",
            "./examples/sample.yaml",
            "--output",
            "json",
        ]);

        match cli.command {
            Command::Scan(args) => {
                assert_eq!(
                    args.path,
                    std::path::PathBuf::from("./examples/sample.yaml")
                );
                assert_eq!(args.output, OutputFormat::Json);
            }
        }
    }
}
