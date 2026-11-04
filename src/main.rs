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
use spf_checker::{normalize_domain, CheckResult, SpfChecker};
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

    let params = SpfCheckParams {
        domain: normalize_domain(&params.domain),
        target: normalize_domain(&params.target),
    };

    if params.domain.is_empty() || params.target.is_empty() {
        let error = ErrorResponse {
            error: "INVALID_DOMAIN".to_string(),
        };

        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

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
                        "\"{}\" covers all IP networks of \"{}\" ({}ms)",
                        params.domain, params.target, elapsed_ms
                    )
                }
                (true, false) => {
                    format!(
                        "\"{}\" does not cover all IP networks of \"{}\" ({}ms)",
                        params.domain, params.target, elapsed_ms
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

fn app(checker: SpfChecker) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
        .route("/ui", get(serve_ui))
        .with_state(checker)
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
    axum::serve(
        listener,
        app(SpfChecker::new(create_tokio_async_resolver())),
    )
    .await?;

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

    /// The real-world setups from the library tests: one customer including easybill by name,
    /// one redirecting to a flattened record that lists easybill's IP directly.
    async fn test_app() -> Router {
        let resolver = fake_dns::resolver(fake_dns::Zone::from([
            (
                "spf.easybill-mail.de",
                vec![vec!["v=spf1 include:ipv4.spf.easybill-mail.de"]],
            ),
            (
                "ipv4.spf.easybill-mail.de",
                vec![vec!["v=spf1 ip4:167.235.178.61"]],
            ),
            (
                "example.com",
                vec![vec!["v=spf1 include:spf.easybill-mail.de ~all"]],
            ),
            (
                "auc-online.de",
                vec![vec!["v=spf1 redirect=auc-online.de.spf.hornetdmarc.com"]],
            ),
            (
                "auc-online.de.spf.hornetdmarc.com",
                vec![vec!["v=spf1 ip4:167.235.178.61 ~all"]],
            ),
            ("other.com", vec![vec!["v=spf1 ip4:192.0.2.10 -all"]]),
        ]))
        .await;

        app(SpfChecker::new(resolver))
    }

    async fn get_json(uri: &str) -> (StatusCode, serde_json::Value) {
        let response = test_app()
            .await
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn test_check_spf_found_by_include() {
        let (status, body) =
            get_json("/api/v1/check-spf?domain=example.com&target=spf.easybill-mail.de").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["found"], true);
        assert_eq!(body["fallback_check"], false);
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["target"], "spf.easybill-mail.de");
        assert_eq!(body["has_spf_record"], true);
        assert_eq!(
            body["spf_record"],
            "v=spf1 include:spf.easybill-mail.de ~all"
        );
        assert_eq!(
            body["included_domains"],
            serde_json::json!(["spf.easybill-mail.de", "ipv4.spf.easybill-mail.de"])
        );
        assert_eq!(body["checked_domains"], 3);
    }

    #[tokio::test]
    async fn test_check_spf_found_by_ip() {
        let (status, body) =
            get_json("/api/v1/check-spf?domain=auc-online.de&target=spf.easybill-mail.de").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["found"], true);
        assert_eq!(body["fallback_check"], true);
        assert_eq!(body["included_domains"], serde_json::json!([]));
        assert_eq!(body["checked_domains"], 4);
    }

    #[tokio::test]
    async fn test_check_spf_not_found() {
        let (status, body) =
            get_json("/api/v1/check-spf?domain=other.com&target=spf.easybill-mail.de").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["found"], false);
        assert_eq!(body["fallback_check"], true);
    }

    #[tokio::test]
    async fn test_check_spf_normalizes_domains() {
        let (status, body) =
            get_json("/api/v1/check-spf?domain=%20Example.COM.&target=SPF.Easybill-Mail.de.").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["found"], true);
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["target"], "spf.easybill-mail.de");
    }

    #[tokio::test]
    async fn test_check_spf_rejects_empty_domains() {
        for uri in [
            "/api/v1/check-spf?domain=&target=spf.easybill-mail.de",
            "/api/v1/check-spf?domain=example.com&target=%20.%20",
        ] {
            let (status, body) = get_json(uri).await;

            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"], "INVALID_DOMAIN");
        }
    }

    #[tokio::test]
    async fn test_check_spf_reports_lookup_failure() {
        let (status, body) =
            get_json("/api/v1/check-spf?domain=unknown.example&target=spf.easybill-mail.de").await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "DNS_LOOKUP_FAILED");
    }
}
