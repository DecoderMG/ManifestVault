use std::path::PathBuf;

use manifestvault_engine::{
    OutputFormat,
    report::render,
    scan::{ScanOptions, scan},
};

#[tokio::test]
async fn known_vulnerable_fixture_matches_golden_json() {
    let manifest = fixture("known-vulnerable.yaml");
    let cve_feed = fixture("osv");
    let expected = std::fs::read_to_string(golden("known-vulnerable.json")).expect("golden file");

    let report = scan(ScanOptions::new(manifest, cve_feed))
        .await
        .expect("scan");
    let rendered = render(&report, OutputFormat::Json).expect("render json");

    assert_eq!(rendered, expected.trim_end());
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn golden(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
}
