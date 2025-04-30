use anyhow::{Context, Result};
use axum::extract::State;
use axum::response::Response;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use decon_spf::Spf;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

static CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");
static CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
struct SpfChecker {
    resolver: Arc<TokioAsyncResolver>,
    max_depth: usize,
}

#[derive(Debug, Deserialize)]
struct SpfCheckParams {
    domain: String,
    target: String,
}

#[derive(Debug, Serialize)]
struct SpfCheckResponse {
    found: bool,
    checked_domains: usize,
    domain: String,
    target: String,
    elapsed_ms: u64,
    has_spf_record: bool,
    spf_record: Option<String>,
    included_domains: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

struct CheckResult {
    found: bool,
    visited: usize,
    spf_record: Option<String>,
    included_domains: Option<Vec<String>>,
}

impl SpfChecker {
    fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(2);
        opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Self {
            resolver: Arc::new(resolver),
            max_depth: 10,
        }
    }

    async fn get_spf(&self, domain: &str) -> Result<Option<String>> {
        let response = self
            .resolver
            .txt_lookup(domain)
            .await
            .context("DNS_LOOKUP_FAILED")?;

        Ok(response.iter().find_map(|record| {
            let txt = record.to_string();
            txt.starts_with("v=spf1").then_some(txt)
        }))
    }

    async fn check(&self, root_domain: &String, target: &String) -> Result<CheckResult> {
        let mut to_visit = vec![root_domain.to_owned()];
        let mut visited = HashSet::new();

        let mut root_spf_record = None;
        let mut root_includes = None;

        while let Some(current_domain) = to_visit.pop() {
            if visited.len() >= self.max_depth {
                log_message(format!(
                    "Maximum recursion depth of {} reached. Visited domains: {:?}",
                    self.max_depth,
                    visited.iter().collect::<Vec<_>>()
                ));
                break;
            }

            if visited.contains(&current_domain) {
                // Already visited
                continue;
            }
            visited.insert(current_domain.clone());

            let Some(spf_txt) = self.get_spf(&current_domain).await? else {
                continue;
            };

            let spf = Spf::from_str(&spf_txt).context("SPF_PARSE_FAILED")?;

            let includes: Vec<String> = spf
                .iter()
                .filter(|m| m.kind().is_include())
                .map(|m| m.raw())
                .collect();

            let redirect = spf
                .iter()
                .map(|m| m.raw())
                .find(|raw| raw.starts_with("redirect="))
                .map(|raw| raw.trim_start_matches("redirect=").to_string());

            if root_domain == &current_domain {
                // Save root domain information
                root_spf_record = Some(spf_txt);
                root_includes = Some(includes.clone());
            }

            if includes.contains(target) {
                // Target found
                return Ok(CheckResult {
                    found: true,
                    visited: visited.len(),
                    spf_record: root_spf_record,
                    included_domains: root_includes,
                });
            }

            to_visit.extend(includes);

            if let Some(redirect_domain) = redirect {
                to_visit.push(redirect_domain);
            }
        }

        // Target not found in any domain
        Ok(CheckResult {
            found: false,
            visited: visited.len(),
            spf_record: root_spf_record,
            included_domains: root_includes,
        })
    }
}

fn log_message(msg: impl AsRef<str>) {
    println!(
        "[{}] {}",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
        msg.as_ref()
    );
}

async fn check_spf(
    Query(params): Query<SpfCheckParams>,
    checker: State<Arc<SpfChecker>>,
) -> Response {
    let start = std::time::Instant::now();

    match checker.check(&params.domain, &params.target).await {
        Ok(CheckResult {
            found,
            visited,
            spf_record,
            included_domains,
        }) => {
            let elapsed_ms = start.elapsed().as_millis() as u64;

            log_message(format!(
                "Successfully checked \"{}\" for \"{}\" ({}ms)",
                params.domain, params.target, elapsed_ms
            ));

            let response = SpfCheckResponse {
                found,
                checked_domains: visited,
                domain: params.domain,
                target: params.target,
                elapsed_ms,
                has_spf_record: spf_record.is_some(),
                spf_record,
                included_domains,
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => {
            let elapsed_ms = start.elapsed().as_millis() as u64;

            log_message(format!(
                "Failed to check \"{}\" for \"{}\": {} ({}ms)",
                params.domain, params.target, err, elapsed_ms
            ));

            let error = ErrorResponse {
                error: err.to_string(),
            };

            (StatusCode::NOT_FOUND, Json(error)).into_response()
        }
    }
}

async fn health() -> StatusCode {
    StatusCode::OK
}

#[tokio::main]
async fn main() -> Result<()> {
    print_logo();

    log_message(format!("> {CARGO_PKG_NAME} v{CARGO_PKG_VERSION}"));

    let checker = Arc::new(SpfChecker::new());

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
        .with_state(checker);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    log_message(format!("Listening on {}", addr));

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[rustfmt::skip]
fn print_logo() {
    log_message("  ______________________________       _________ .__                   __");
    log_message(" /   _____/\\______   \\_   _____/       \\_   ___ \\|  |__   ____   ____ |  | __");
    log_message(" \\_____  \\  |     ___/|    __)  ______ /    \\  \\/|  |  \\_/ __ \\_/ ___\\|  |/ /");
    log_message(" /        \\ |    |    |     \\  /_____/ \\     \\___|   Y  \\  ___/\\  \\___|    <");
    log_message("/_______  / |____|    \\___  /           \\______  /___|  /\\___  >\\___  >__|_ \\");
    log_message("        \\/                \\/                   \\/     \\/     \\/     \\/     \\/");
}
