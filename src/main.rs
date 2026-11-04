use anyhow::Context;
use axum::response::Html;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use spf_checker::{CheckResult, SpfChecker};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpListener;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

static CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");
static CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

const LISTEN_ADDR_ENV: &str = "LISTEN_ADDR";
const DEFAULT_LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);

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
    fallback_check: bool,
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
            fallback_check,
        }) => {
            let elapsed_ms = start.elapsed().as_millis() as u64;

            let status_msg = match (fallback_check, found) {
                (true, true) => {
                    format!(
                        "Successfully found all mechanisms from \"{}\" in \"{}\" via fallback check ({}ms)",
                        params.target, params.domain, elapsed_ms
                    )
                }
                (true, false) => {
                    format!(
                        "Fallback check completed for \"{}\" in \"{}\" - not all mechanisms found ({}ms)",
                        params.target, params.domain, elapsed_ms
                    )
                }
                (false, _) => {
                    format!(
                        "Successfully checked \"{}\" for \"{}\" ({}ms)",
                        params.domain, params.target, elapsed_ms
                    )
                }
            };

            log_message(status_msg);

            let response = SpfCheckResponse {
                found,
                checked_domains: visited,
                domain: params.domain,
                target: params.target,
                elapsed_ms,
                has_spf_record: spf_record.is_some(),
                spf_record,
                included_domains,
                fallback_check,
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

fn create_tokio_async_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(2);
    opts.attempts = 2;
    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
}

fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
        .route("/ui", get(serve_ui))
        .with_state(SpfChecker::new(create_tokio_async_resolver()))
}

fn parse_listen_addr(value: Option<&str>) -> Result<SocketAddr> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(DEFAULT_LISTEN_ADDR),
        Some(v) => v.parse().with_context(|| {
            format!("Invalid {LISTEN_ADDR_ENV} \"{v}\", expected <ip>:<port> (e.g. 127.0.0.1:8080 or [::]:8080)")
        }),
    }
}

fn listen_addr_from_env() -> Result<SocketAddr> {
    parse_listen_addr(std::env::var(LISTEN_ADDR_ENV).ok().as_deref())
}

async fn serve_ui() -> Html<&'static str> {
    Html(include_str!("html/ui.html"))
}

#[tokio::main]
async fn main() -> Result<()> {
    log_message(format!("> {CARGO_PKG_NAME} v{CARGO_PKG_VERSION}"));

    let addr = listen_addr_from_env()?;

    log_message(format!("Listening on {}", addr));

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;
    axum::serve(listener, app()).await?;

    Ok(())
}

// https://github.com/tokio-rs/axum/blob/main/examples/testing/src/main.rs
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn listen_addr_defaults_when_unset_or_blank() {
        assert_eq!(parse_listen_addr(None).unwrap(), DEFAULT_LISTEN_ADDR);
        assert_eq!(parse_listen_addr(Some("  ")).unwrap(), DEFAULT_LISTEN_ADDR);
    }

    #[test]
    fn listen_addr_parses_ipv4_and_ipv6() {
        assert_eq!(
            parse_listen_addr(Some("127.0.0.1:3000")).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 3000))
        );
        assert_eq!(
            parse_listen_addr(Some("[::1]:9000")).unwrap(),
            "[::1]:9000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn listen_addr_rejects_invalid_values() {
        assert!(parse_listen_addr(Some("localhost:8080")).is_err());
        assert!(parse_listen_addr(Some("127.0.0.1")).is_err());
        assert!(parse_listen_addr(Some("127.0.0.1:99999")).is_err());
    }

    #[tokio::test]
    #[ignore = "An example for integration test against axum. Not yet fully implemented"]
    async fn test_check_spf_with_provided_domains() {
        let app = app();

        let url = format!(
            "/api/v1/check-spf?domain={}&target={}",
            "auc-online.de", "spf.easybill-mail.de"
        );

        let response = app
            .oneshot(Request::get(url).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
