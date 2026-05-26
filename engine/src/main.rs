use anyhow::Result;
use clap::Parser;
use manifestvault_engine::{Cli, run};
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let rendered = run(cli).await?;
    println!("{rendered}");

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
