# Project Instructions

## Project Overview

`spf-check` is a Rust web service that verifies whether a `target` domain is authorized to send mail on behalf of another `domain` according to that domain's SPF (Sender Policy Framework) record.

The service exposes:

- `GET /api/v1/check-spf?domain={domain}&target={target}` — the core check
- `GET /health` — liveness probe
- `GET /ui` — minimal HTML UI (single embedded page)

Built on `axum` (HTTP), `tokio` (async runtime), `trust-dns-resolver` (DNS), `decon-spf` (SPF parsing), and `serde`.

## Repository Layout

This is a **Cargo workspace** with two crates:

- The **binary** `spf-check` at the workspace root (axum HTTP service).
- The **library** `spf_checker` under `crates/spf_checker/` (core SPF resolution logic, reusable as a standalone library).

```
spf-check/
├── Cargo.toml                          # workspace + binary `spf-check`, edition 2021
├── src/
│   ├── main.rs                         # axum server, routing, HTTP handlers, response types
│   └── html/ui.html                    # UI, embedded at compile time via include_str!
├── crates/
│   └── spf_checker/
│       ├── Cargo.toml                  # library `spf_checker`
│       └── src/lib.rs                  # SpfChecker + SpnResolver trait + tests
├── spf-check.http                      # manual HTTP requests (JetBrains/VSCode REST client)
├── test-service.js                     # external Node.js smoke-test script
├── Dockerfile, docker-compose.yml
└── .github/workflows/                  # test.yml, clippy.yml, publish.yml, update-dockerhub-readme.yml
```

There is currently **no top-level `tests/` directory and no `benches/` directory**. Create them when first needed (see "Testing & Benchmarking").

### Module Map

- **`src/main.rs`** (binary `spf-check`) — server bootstrap (listen address from `LISTEN_ADDR`, default `0.0.0.0:8080`), axum router, request/response structs (`SpfCheckParams`, `SpfCheckResponse`, `ErrorResponse`), `log_message` helper, and the `TokioAsyncResolver` factory. Depends on `spf_checker` via path dependency.
- **`crates/spf_checker/src/lib.rs`** (library `spf_checker`) — `SpfChecker` struct holding an `Arc<dyn SpnResolver + Send + Sync>`. The `SpnResolver` trait abstracts DNS so tests can substitute a `MockResolver` instead of hitting real DNS. `TokioAsyncResolver` implements `SpnResolver` for production. `DNS_LOOKUP_LIMIT = 10` enforces the SPF lookup budget. SPF-specific dependencies (`decon-spf`, `ipnetwork`, `async-trait`, `trust-dns-resolver`) live here.
- **`src/html/ui.html`** — a self-contained HTML page; no separate frontend build step.

## Check Behavior

The check verifies that the `domain` authorizes every sending IP the `target` advertises. `SpfChecker::check` resolves both SPF chains with a single walker (`resolve`) and compares the results.

A `target` is considered "covered" by `domain` if **either**:

1. **Coverage via include** — `domain`'s SPF chain includes the `target` by name (e.g. `include:spf.easybill-mail.de`), at any depth; **or**
2. **Coverage by IP** — every `ip4`/`ip6` network in the `target`'s resolved SPF chain is contained in some `ip4`/`ip6` network of `domain`'s resolved chain. A wider network on the `domain` side covers a narrower one on the `target` side (e.g. `ip4:192.0.2.0/24` covers `ip4:192.0.2.10`), but not the other way around. IPv4 never covers IPv6. A `target` without any `ip4`/`ip6` networks is never covered by IP.

### Resolving a Chain (`resolve`)

1. Fetch the SPF record of the domain (`SpnResolver::find_spf_record`). A domain with more than one SPF record fails with `MULTIPLE_SPF_RECORDS` (RFC 7208, section 4.5).
2. Collect every pass-qualified (`+`, the default) `ip4`/`ip6` network and every pass-qualified `include:` domain. Mechanisms with `-`, `~` or `?` qualifiers are ignored, as they never authorize anything.
3. Follow `include:` references first (in record order), then `redirect=`. A `redirect` is ignored if the record contains an `all` mechanism (RFC 7208, section 6.1).
4. **DNS lookup budget.** At most 10 lookups for `include` and `redirect` per chain; the lookup of the domain itself does not count. When the budget is reached, resolution stops and the networks and include names collected so far are used for the comparison. This is logged, not treated as an error.

`a`, `mx`, `ptr` and `exists` mechanisms are **intentionally not resolved**.

`fallback_check` in `CheckResult` and in the API response is kept for compatibility only and is always `false`; the former string-based fallback check no longer exists.

## Development Workflow

- **Run the service**: `cargo run` — listens on `0.0.0.0:8080` by default; override with `LISTEN_ADDR=<ip>:<port>`.
- **UI**: open `http://localhost:8080/ui` in the browser.
- **Health probe**: `GET http://localhost:8080/health` returns 200.
- **Manual API tests**: `spf-check.http` (REST-client compatible).
- **External smoke test**: `node test-service.js` (Node.js, hits the running service).
- **Release build**: `cargo build --release` then `./target/release/spf-check`.
- **Lint**: `cargo clippy --workspace --all-targets -- -D warnings`.
- **Tests**: `cargo test --workspace` (or just `cargo test` — the workspace's `default-members` already covers both crates).

## API Contract

`GET /api/v1/check-spf?domain={domain}&target={target}` — both query parameters are required.

**Success (`200 OK`)** — JSON body matching `SpfCheckResponse` in `main.rs`:

```json
{
  "found": true,
  "checked_domains": 2,
  "domain": "example.com",
  "target": "spf.easybill-mail.de",
  "elapsed_ms": 42,
  "has_spf_record": true,
  "spf_record": "v=spf1 include:spf.easybill-mail.de ~all",
  "included_domains": ["spf.easybill-mail.de"],
  "fallback_check": false
}
```

**Failure (`404 NOT_FOUND`)** — currently used for any resolution error (DNS failure, SPF parse failure, multiple SPF records). Body: `{ "error": "<message>" }`. The status mapping is intentionally coarse today; revisit if richer client-side error handling is needed.

## Language & Documentation

- All content in the codebase must be in English. This includes source code, identifiers, comments, commit messages, `CLAUDE.md`, skill files, and any other repository artifacts.
- Write comments only at code locations that are particularly complex or non-obvious. Do not narrate what the code does — well-named identifiers handle that.
- Add doc blocks (`///`) to every **public API** to explain its purpose, parameters, return values, and any invariants the caller must respect.

## Code Quality & Linting

- Run `cargo clippy` after **every** change to lint the project.
- Use `cargo clippy --fix` to auto-resolve fixable issues.
- Any clippy warnings or errors that remain after `--fix` must be addressed manually before the task is considered complete.
- **CI enforcement**: `.github/workflows/linting.yml` runs `cargo clippy --workspace --all-targets --locked -- -D warnings` and `.github/workflows/tests.yml` runs `cargo test --workspace --all-targets --locked` on every PR against `main`. Keep them green locally before pushing — CI is the authoritative gate.

## Testing & Benchmarking

- **Unit tests** belong next to the module under `#[cfg(test)] mod tests` and must use the `SpnResolver` trait with a mock (see `MockResolver` in `crates/spf_checker/src/lib.rs`). Never hit real DNS in unit tests.
- The `TokioAsyncResolver` implementation of `SpnResolver` cannot be tested with the mock. It is tested in `crates/spf_checker/tests/tokio_resolver.rs` against a minimal fake DNS server on localhost (built with `trust-dns-proto`), so it does not hit real DNS either.
- **Integration tests** belong in a dedicated top-level `tests/` directory (create it on first need). The pre-existing `#[tokio::test]` in `main.rs` that hits real DNS is legacy; migrate it to `tests/` and replace it with a mock-backed variant when convenient.
- **Benchmarks**: there is no `benches/` directory yet. Add one (with `criterion` or similar) before relying on `cargo bench`.
- Performance budgets are not formally defined. Until they are, treat regressions in `elapsed_ms` from the existing handler tests as the informal signal.

## Architecture & Design

- Follow these standards rigorously: **DRY**, **SOLID**, and **No Leaky Abstraction**.
- The `SpnResolver` trait is the canonical seam between the SPF logic and DNS. Add new SPF-resolution code on top of this abstraction, not directly against `TokioAsyncResolver`, so tests stay deterministic.

## Data Types & Allocation

- Think carefully about which data type fits the access pattern. For example, if the workload performs many front/back inserts and deletes, prefer `VecDeque` over `Vec`.
- Avoid heap allocation when stack allocation is feasible. Prefer fixed-size arrays whenever the size is known at compile time.

## Rust Style

- Edition: **2021**. Avoid 2024-edition-only constructs.
- Prefer "easymode" Rust: instead of fighting the borrow checker for marginal performance gains, use `Copy` and `Clone`. Try `Copy` first; only fall back to implementing `Clone` when the value is too complex to copy cheaply.
- Prefer `impl Fn` / `impl FnOnce` / `impl FnMut` (`impl Trait` in argument position) over generic type parameters when accepting closures, to keep signatures clean.
- Async traits use the `async-trait` crate (see `SpnResolver`). Stay with `async-trait` for object-safe traits like this one; native AFIT is not yet sufficient for the trait-object usage in `SpfChecker`.

## Error Handling

- For application/binary code that uses `Result`, use [`anyhow`](https://docs.rs/anyhow) (`use anyhow::Result;`). Both the binary `spf-check` and the library `spf_checker` currently use `anyhow`.
- The `spf_checker` library should eventually expose typed errors via [`thiserror`](https://docs.rs/thiserror) so consumers can match on and react to specific variants. This conversion has not happened yet — the library still surfaces `anyhow::Error`. Switch to `thiserror` for `spf_checker`'s public API when refactoring its error surface.

## Dependencies & Build

- `decon-spf` is pinned to a fork: `https://github.com/coreequip/rust-decon-spf`, because of an upstream bug. Revisit on dependency updates and switch back to crates.io once the fix lands upstream. The dependency lives in `crates/spf_checker/Cargo.toml`, not the binary.
- `decon-spf` still depends on `ipnetwork` 0.20, so `Cargo.lock` contains both 0.20 and the newer version `spf_checker` uses directly. This is harmless: `ip4`/`ip6` values are taken from `decon-spf` as strings and parsed with our own `ipnetwork` version. Drop the duplicate once `decon-spf` is updated.
- Release profile already enables LTO:
  ```toml
  [profile.release]
  lto = true
  codegen-units = 1
  ```
  Keep both settings — they are required to maximize runtime performance.
- No MSRV is promised. The latest stable toolchain is the supported target.
