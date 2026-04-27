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

- **`src/main.rs`** (binary `spf-check`) — server bootstrap on `0.0.0.0:8080`, axum router, request/response structs (`SpfCheckParams`, `SpfCheckResponse`, `ErrorResponse`), `log_message` helper, and the `TokioAsyncResolver` factory. Depends on `spf_checker` via path dependency.
- **`crates/spf_checker/src/lib.rs`** (library `spf_checker`) — `SpfChecker` struct holding an `Arc<dyn SpnResolver + Send + Sync>`. The `SpnResolver` trait abstracts DNS so tests can substitute a `MockResolver` instead of hitting real DNS. `TokioAsyncResolver` implements `SpnResolver` for production. `DNS_LOOKUP_LIMIT = 10` enforces the SPF lookup budget. SPF-specific dependencies (`decon-spf`, `async-trait`, `trust-dns-resolver`) live here.
- **`src/html/ui.html`** — a self-contained HTML page; no separate frontend build step.

## Current Behavior (legacy)

Today the service walks the `domain`'s SPF `include:` chain recursively and reports `found = true` if the literal `target` domain appears anywhere in that chain. It is a *string-level inclusion check* over include references (`check_direct_include`), with a fallback (`check_target_mechanisms`) that compares raw mechanism strings between the target's and domain's SPF records.

## Target Behavior (where we are heading)

The semantic is changing. Going forward the check must verify that **all `ip4` and `ip6` mechanisms declared by the `target` domain's SPF record are effectively authorized by the `domain`'s SPF record** — i.e. the `domain` must actually resolve to the same set of sending IPs that the `target` advertises.

A `target` is considered "covered" by `domain` if **either**:

1. **Indirect coverage via include** — `domain`'s SPF chain transitively includes the `target` (e.g. `include:spf.easybill-mail.de`), so the `target`'s `ip4`/`ip6` mechanisms are implicitly inherited; **or**
2. **Direct coverage by IP** — every `ip4` and `ip6` address listed by the `target`'s SPF record is also listed (directly or via another include) in the `domain`'s effective SPF record.

The unit of comparison is the **resolved set of `ip4`/`ip6` mechanisms**, not the textual presence of an `include:` token. Mechanisms such as `a`, `mx`, `redirect`, and nested `include` must be fully expanded down to concrete IPs before the comparison.

### Resolving Chain

1. **Resolve / verify the target SPF.** Fetch the SPF record for `target` and collect every `ip4` and `ip6` mechanism it declares. This is the reference set the `domain` must cover.
2. **Resolve the SPF for `domain`.** Fetch the top-level SPF record for `domain`.
3. **Match on each hit.** For every mechanism encountered while walking `domain`'s record, check:
   - whether the entry is a direct `include:<target>` of the target domain, **or**
   - whether the entry is an `ip4` / `ip6` mechanism that belongs to the reference set collected in step 1.
4. **Follow `redirect` and `include` if no match yet.** When the current record does not yet satisfy coverage, descend into its `redirect=` and `include:` references and repeat the matching logic recursively.
5. **DNS lookup budget.** Honor the SPF specification limit: **at most 10 DNS lookups** for `include` and `redirect` entries combined per evaluation. Exceeding the budget must terminate the resolution with an error rather than continuing to query.

### Migration Status

The legacy behavior is implemented in `check_direct_include` + `check_target_mechanisms`. The target behavior — full mechanism expansion down to concrete `ip4`/`ip6` sets — is **not yet implemented**. The failing test `test_target_redirect_with_ip4_ip6_mechanism_instead_of_include` in `crates/spf_checker/src/lib.rs` documents the gap and is the entry point for the migration work.

## Development Workflow

- **Run the service**: `cargo run` — listens on `0.0.0.0:8080`.
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

**Failure (`404 NOT_FOUND`)** — currently used for any resolution error (DNS failure, SPF parse failure, lookup budget exceeded). Body: `{ "error": "<message>" }`. The status mapping is intentionally coarse today; revisit if richer client-side error handling is needed.

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
- Release profile already enables LTO:
  ```toml
  [profile.release]
  lto = true
  codegen-units = 1
  ```
  Keep both settings — they are required to maximize runtime performance.
- No MSRV is promised. The latest stable toolchain is the supported target.
