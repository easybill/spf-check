# Project Instructions

## Project Overview

`spf-check` is a high-performance Rust web service that verifies whether a `target` domain is authorized to send mail on behalf of another `domain` according to that domain's SPF (Sender Policy Framework) record.

The service exposes:

- `GET /api/v1/check-spf?domain={domain}&target={target}` — the core check
- `GET /health` — liveness probe
- `GET /ui` — minimal HTML UI

Built on `axum` (HTTP), `tokio` (async runtime), `trust-dns-resolver` (DNS), `decon-spf` (SPF parsing), and `serde`.

### Current Behavior (legacy)

Today the service walks the `domain`'s SPF `include:` chain recursively and reports `found = true` if the literal `target` domain appears anywhere in that chain. It is a *string-level inclusion check* over include references.

### Target Behavior (where we are heading)

The semantic is changing. Going forward the check must verify that **all `ip4` and `ip6` mechanisms declared by the `target` domain's SPF record are effectively authorized by the `domain`'s SPF record** — i.e. the `domain` must actually resolve to the same set of sending IPs that the `target` advertises.

A `target` is considered "covered" by `domain` if **either**:

1. **Indirect coverage via include** — `domain`'s SPF chain transitively includes the `target` (e.g. `include:spf.easybill-mail.de`), so the `target`'s `ip4`/`ip6` mechanisms are implicitly inherited; **or**
2. **Direct coverage by IP** — every `ip4` and `ip6` address listed by the `target`'s SPF record is also listed (directly or via another include) in the `domain`'s effective SPF record.

The unit of comparison is the **resolved set of `ip4`/`ip6` mechanisms**, not the textual presence of an `include:` token. Mechanisms such as `a`, `mx`, `redirect`, and nested `include` must be fully expanded down to concrete IPs before the comparison.

#### Resolving Chain

1. **Resolve / verify the target SPF.** Fetch the SPF record for `target` and collect every `ip4` and `ip6` mechanism it declares. This is the reference set the `domain` must cover.
2. **Resolve the SPF for `domain`.** Fetch the top-level SPF record for `domain`.
3. **Match on each hit.** For every mechanism encountered while walking `domain`'s record, check:
   - whether the entry is a direct `include:<target>` of the target domain, **or**
   - whether the entry is an `ip4` / `ip6` mechanism that belongs to the reference set collected in step 1.
4. **Follow `redirect` and `include` if no match yet.** When the current record does not yet satisfy coverage, descend into its `redirect=` and `include:` references and repeat the matching logic recursively.
5. **DNS lookup budget.** Honor the SPF specification limit: **at most 10 DNS lookups** for `include` and `redirect` entries combined per evaluation. Exceeding the budget must terminate the resolution with an error rather than continuing to query.

## Language & Documentation

- All content in the codebase must be in English. This includes source code, identifiers, comments, commit messages, `CLAUDE.md`, skill files, and any other repository artifacts.
- Write comments only at code locations that are particularly complex or non-obvious. Do not narrate what the code does — well-named identifiers handle that.
- Add doc blocks (`///`) to every **public API** to explain its purpose, parameters, return values, and any invariants the caller must respect.

## Code Quality & Linting

- Run `cargo clippy` after **every** change to lint the project.
- Use `cargo clippy --fix` to auto-resolve fixable issues.
- Any clippy warnings or errors that remain after `--fix` must be addressed manually before the task is considered complete.

## Testing & Benchmarking

- Integration tests live in the dedicated top-level `tests/` directory, not inside `src/`.
- Use `cargo bench` to verify and monitor the project's performance.

## Architecture & Design

- Follow these standards rigorously: **DRY**, **SOLID**, and **No Leaky Abstraction**.

## Data Types & Allocation

- Think carefully about which data type fits the access pattern. For example, if the workload performs many front/back inserts and deletes, prefer `VecDeque` over `Vec`.
- Avoid heap allocation when stack allocation is feasible. Prefer fixed-size arrays whenever the size is known at compile time.

## Rust Style

- Prefer "easymode" Rust: instead of fighting the borrow checker for marginal performance gains, use `Copy` and `Clone`. Try `Copy` first; only fall back to implementing `Clone` when the value is too complex to copy cheaply.
- Prefer `impl Fn` / `impl FnOnce` / `impl FnMut` (`impl Trait` in argument position) over generic type parameters when accepting closures, to keep signatures clean.

## Error Handling

- For application/binary code that uses `Result`, use [`anyhow`](https://docs.rs/anyhow) (`use anyhow::Result;`).
- For library crates (e.g. `spf_checker`), use [`thiserror`](https://docs.rs/thiserror) so consumers can match on and react to specific error variants.

## Build Configuration

- Enable **Link-Time Optimization (LTO)** in the release profile to maximize runtime performance.
