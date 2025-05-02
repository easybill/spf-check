mod spf_checker;

use crate::spf_checker::{CheckResult, SpfChecker};
use axum::extract::State;
use axum::response::Response;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

static CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");
static CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

type Result<T> = anyhow::Result<T>;

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

fn log_message(msg: impl AsRef<str>) {
    println!(
        "[{}] {}",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
        msg.as_ref()
    );
}

async fn check_spf(Query(params): Query<SpfCheckParams>, checker: State<SpfChecker>) -> Response {
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

fn app() -> Router<SpfChecker> {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
}

#[tokio::main]
async fn main() -> Result<()> {
    print_logo();

    log_message(format!("> {CARGO_PKG_NAME} v{CARGO_PKG_VERSION}"));

    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(2);
    opts.attempts = 2;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
    let spf_checker = SpfChecker::new(resolver);

    let app = app().with_state(spf_checker);

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
