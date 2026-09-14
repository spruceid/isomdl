# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**isomdl** is a Rust implementation of ISO/IEC 18013-5 (mDL — mobile Driver's License). It provides a library for building device and reader applications that exchange mDL data, plus a CLI tool (`isomdl-utils`).

Repository: https://github.com/spruceid/isomdl

## Development Commands

```bash
# Build
cargo build --all-targets

# Test (CI runs both)
cargo test
cargo test --all-features
cd macros && cargo test

# Lint
cargo clippy --all-targets --all-features --no-deps
cargo fmt --all -- --check

# Check unused dependencies
cargo machete

# Check dependency licenses
cargo deny check licenses

# Generate docs
cargo doc --all-features --no-deps
cd macros && cargo doc --all-features --no-deps

# Run a single test
cargo test <test_name>
cargo test --test simulated_device_and_reader_interaction

# CLI tool (requires cli feature)
cargo run --features cli -- --help
cat test/stringified-mdl.txt | cargo run --features cli -- get-namespaces -
```

CI sets `RUSTFLAGS="-Dwarnings"` and `RUSTDOCFLAGS="-Dwarnings"` — all warnings are errors.

## Feature Flags

- **`cli`** — Enables the `isomdl-utils` binary (clap, tokio).
- **`reqwest`** — HTTP client for CRL (Certificate Revocation List) fetching (reqwest, moka cache).
- No default features are enabled.

## Architecture

### Crate Structure

- **`isomdl`** (root) — Main library + optional CLI binary.
- **`isomdl-macros`** (`macros/`) — Proc macro crate providing `FromJson` and `ToCbor` derives with `#[isomdl(...)]` attributes.

### Core Modules

- **`definitions/`** — ISO 18013-5 data structures: device engagement, device request/response, issuer-signed items, MSO (Mobile Security Object), session management, X.509/CRL validation, namespaces (ISO 18013-5.1 + AAMVA).
  - **`app_attestation`** — Application attestation structures.
  - **`mcd`** — Mobile Credential Data definitions.
  - **`validity_info`** — Credential validity periods.
  - **`issuer_signed_dehydrated`** — Dehydrated (compact) issuer-signed data.
  - **`helpers/`** — Utility types: `NonEmptyMap`, `NonEmptyVec`, `ByteStr`, `Tag24`.
  - **`traits/`** — `ToCbor` and `FromJson` traits for CBOR/JSON conversion.
  - **`x509/`** — Certificate validation, CRL revocation, trust anchors.
- **`presentation/`** — Device-Reader interaction layer.
  - **`device`** — Device-side state machine (see below).
  - **`reader`** — Reader-side session management.
  - **`reader_utils`** — Reader-side helper utilities.
  - **`authentication`** — Request/response authentication, `AuthenticationStatus`.
- **`issuance/`** — Document issuance (`Mdoc`, `Namespaces`).
- **`vical/`** — VICAL (Verifiable Identity Credential Attestation List) support.
- **`cbor`** — CBOR encoding/decoding utilities (wraps `ciborium`).
- **`cose`** — COSE sign1/mac0 operations (wraps `coset`).

### Device State Machine

The device side uses a typestate pattern:

```
SessionManagerInit → SessionManagerEngaged → SessionManager
                                                ├─ AwaitingRequest
                                                ├─ Signing (prepare_response / get_next_signature_payload)
                                                └─ ReadyToRespond (submit_next_signature → retrieve_response)
```

The reader side is simpler: `SessionManager` with `establish_session` and `handle_response`.

### Serialization

- CBOR via `ciborium` + `coset` for COSE structures.
- Custom proc-macro derives `FromJson` and `ToCbor` (from `isomdl-macros`).
- `serde` with `serde_bytes` for byte string handling.
- `Tag24<T>` wrapper for CBOR tag 24 (embedded CBOR).
- `MaybeTagged<T>` for optional CBOR tagging in COSE structures.

### Error Handling

- `thiserror` for typed errors throughout the library.
- `anyhow` only in the CLI binary.

## Testing

- Integration tests in `tests/` serve as usage examples (see `tests/README.md`).
- `tests/common.rs` has shared Device/Reader simulation helpers.
- Test data lives in `tests/data/` and `test/` (per-module fixtures).
- Uses `#[tokio::test]`, `#[test_log::test(tokio::test)]`, and `rstest` for parameterized tests.
- `wiremock` for HTTP mocking (CRL tests).

## Conventions

- `cargo-deny` checks dependency licenses (`deny.toml` at root). CI runs `cargo deny check licenses`.
- `generic-array` is pinned to `=0.14.7` for RustCrypto compatibility.
- `serde_bytes` is listed in cargo-machete's ignore list (used via derive attributes).
- Async signing uses `async-signature` / `async-trait` traits.
