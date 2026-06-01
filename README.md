# ManifestVault

ManifestVault analyzes deployment manifests and produces a structured report. The Rust engine includes strict Kubernetes manifest parsing, local SBOM loading, OSV CVE matching, and Component Importance Index scoring.

The parser targets Kubernetes 1.30 through the single pinned `k8s-openapi` feature `v1_30`.

## Branch protection

The default branch should require the GitHub Actions `ci` workflow to pass before merge. Configure branch protection on `main` to mark the `ci` check (fmt, clippy, test jobs) as required. Release artifacts for tagged commits are produced by the `release` workflow on `v*` tags.

## Prerequisites

- Rust 1.95.0, installed with `rustup`
- Cargo and Clippy from the pinned toolchain

```powershell
rustup toolchain install 1.95.0 --component clippy
```

## Build

```powershell
cargo build --release
```

## Test

```powershell
cargo test
cargo clippy -- -D warnings
```

## Run

```powershell
cargo run -p manifestvault-engine --bin manifestvault -- scan ./examples/sample.yaml --cve-feed ./engine/tests/fixtures/osv --output json
```

The scan pipeline requires a local OSV feed:

```powershell
cargo run -p manifestvault-engine --bin manifestvault -- scan ./examples/sample.yaml --cve-feed ./engine/tests/fixtures/osv --output json
```

For air-gapped runs, local SBOM JSON can be referenced directly from the container image field or provided as `sbom/<sanitized-image>.json` under the feed bundle. For example, `alpine:3.18` resolves to `sbom/alpine_3_18.json`.
