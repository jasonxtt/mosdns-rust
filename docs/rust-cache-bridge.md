# Rust Cache Bridge (Stage 1 Skeleton)

This repository now includes a stage-1 Rust cache runtime skeleton under:

- `rust/cache-core`

The current Go cache plugin behavior is unchanged by default. The Rust bridge is optional and guarded by build tags plus an environment variable.

## Build Rust Static Library

```bash
./scripts/build-rust-cache-core.sh
```

This produces:

- `rust/cache-core/target/release/libmosdns_cache_core.a`

## Build Go Binary With Rust Bridge

Enable cgo and pass the `mosdns_rust_cache` build tag:

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags mosdns_rust_cache ./...
```

## Runtime Opt-In

Set `MOSDNS_CACHE_BACKEND=rust` to request Rust runtime initialization.

- If initialization succeeds, startup logs include the Rust runtime version.
- If initialization fails, the plugin logs a warning and falls back to the existing Go cache logic.

Optional transition flag:

- `MOSDNS_RUST_CACHE_GO_MIRROR=1` enables Go mirror write/load for observability/rollback transition.
- Default is disabled, so rust mode reads/writes the rust cache directly without Go cache read fallback.

## Current Status

- Rust runtime probe (`ping` and `version`) is available.
- Rust cache `lookup/store` is wired through C ABI and integrated into Go cache hot path.
- Rust cache also provides key-based C ABI (`lookup_by_key` / `store_by_key`), and Go rust-mode path now uses prebuilt query keys to reduce repeated query parsing overhead.
- Rust mode now uses the same local Go L1 hot cache fast-path before cgo lookup, reducing Rust<->Go crossing on repeated cache hits.
- Go cache remains as fallback when Rust initialization or Rust calls fail.
- Rust cache `flush` is wired through C ABI.
- Rust dump export/import is wired through C ABI and used by Go `dumpCache/loadDump` in rust mode.
- `show` API in rust mode now reads Rust dump bytes directly instead of enumerating the Go cache backend.
- Go mirror path is now optional via env (`MOSDNS_RUST_CACHE_GO_MIRROR=1`), and `show` no longer depends on it.
