# ManifestVault

ManifestVault analyzes deployment manifests and produces a structured report. This repository currently contains the Rust engine scaffold: a CLI binary, async scan pipeline entry point, and empty module surfaces for later manifest parsing, layer/SBOM extraction, and scoring work.

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
cargo run -p manifestvault-engine --bin manifestvault -- scan ./examples/sample.yaml --output json
```

The scan pipeline is intentionally a placeholder. It verifies that the requested target exists, then emits a valid report with an empty `findings` array.
