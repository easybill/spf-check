use anyhow::{Context, Result};
use axum::http::header;
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

impl SpfChecker {
    async fn new() -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(2);
        opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Ok(Self {
            resolver: Arc::new(resolver),
            max_depth: 10,
        })
    }

    async fn get_spf(&self, domain: &str) -> Result<Option<String>> {
        let response = self
            .resolver
            .txt_lookup(domain)
            .await
            .context("DNS_LOOKUP_FAILED")?;

        Ok(response.iter().find_map(|record| {
            let txt = record
                .txt_data()
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<String>();
            txt.starts_with("v=spf1").then_some(txt)
        }))
    }

    async fn check(
        &self,
        domain: String,
        target: String,
        visited: &mut HashSet<String>,
    ) -> Result<(bool, Option<String>, Option<Vec<String>>)> {
        if visited.len() >= self.max_depth {
            log_message(&format!(
                "Maximum recursion depth of {} reached. Visited domains: {:?}",
                self.max_depth,
                visited.iter().collect::<Vec<_>>()
            ));
            return Ok((false, None, None));
        }

        if !visited.insert(domain.clone()) {
            return Ok((false, None, None));
        }

        let spf_txt = self.get_spf(&domain).await?;

        let Some(spf_txt) = spf_txt else {
            return Ok((false, None, None));
        };

        let spf = Spf::from_str(&spf_txt).context("SPF_PARSE_FAILED")?;

        let includes: Vec<String> = spf
            .iter()
            .filter(|m| m.kind().is_include())
            .map(|m| m.raw())
            .collect();

        if visited.len() == 1 {
            if includes.contains(&target) {
                return Ok((true, Some(spf_txt), Some(includes)));
            }

            let futures: Vec<_> = includes
                .iter()
                .map(|include| {
                    let checker = self.clone();
                    let target = target.clone();
                    let visited = visited.clone();
                    async move {
                        checker
                            .check(include.clone(), target, &mut visited.clone())
                            .await
                    }
                })
                .collect();

            let results = futures::future::join_all(futures).await;
            let found = results.into_iter().any(|r| r.unwrap_or_default().0);

            return Ok((found, Some(spf_txt), Some(includes)));
        }

        if includes.contains(&target) {
            return Ok((true, None, None));
        }

        let futures: Vec<_> = includes
            .into_iter()
            .map(|include| {
                let checker = self.clone();
                let target = target.clone();
                let visited = visited.clone();
                async move { checker.check(include, target, &mut visited.clone()).await }
            })
            .collect();

        let results = futures::future::join_all(futures).await;
        Ok((
            results.into_iter().any(|r| r.unwrap_or_default().0),
            None,
            None,
        ))
    }
}

fn log_message(msg: &str) {
    println!("[{}] {}", chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"), msg);
}

async fn check_spf(
    Query(params): Query<SpfCheckParams>,
    checker: axum::extract::State<Arc<SpfChecker>>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    let mut visited = HashSet::new();

    match checker
        .check(params.domain.clone(), params.target.clone(), &mut visited)
        .await
    {
        Ok((found, spf_record, included_domains)) => {
            let elapsed_ms = start.elapsed().as_millis() as u64;
            log_message(&format!(
                "Successfully checked \"{}\" for \"{}\" ({}ms)",
                params.domain,
                params.target,
                elapsed_ms
            ));

            let response = SpfCheckResponse {
                found,
                checked_domains: visited.len(),
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
            log_message(&format!(
                "Failed to check \"{}\" for \"{}\": {} ({}ms)",
                params.domain,
                params.target,
                err,
                elapsed_ms
            ));

            let error = ErrorResponse {
                error: err.to_string(),
            };
            (StatusCode::NOT_FOUND, Json(error)).into_response()
        }
    }
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn serve_ui() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("ui.html"),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    log_message("  ______________________________       _________ .__                   __    ");
    log_message(" /   _____/\\______   \\_   _____/       \\_   ___ \\|  |__   ____   ____ |  | __");
    log_message(" \\_____  \\  |     ___/|    __)  ______ /    \\  \\/|  |  \\_/ __ \\_/ ___\\|  |/ /");
    log_message(" /        \\ |    |    |     \\  /_____/ \\     \\___|   Y  \\  ___/\\  \\___|    < ");
    log_message("/_______  / |____|    \\___  /           \\______  /___|  /\\___  >\\___  >__|_ \\");
    log_message("        \\/                \\/                   \\/     \\/     \\/     \\/     \\/");

    log_message(&format!("> {} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")));

    let checker = Arc::new(SpfChecker::new().await?);

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
        .route("/ui", get(serve_ui))
        .with_state(checker);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    log_message(&format!("Listening on {}", addr));

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
