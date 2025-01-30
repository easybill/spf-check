use axum::{
    extract::Query,
    routing::get,
    Router,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use decon_spf::Spf;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use anyhow::{Result, Context};

#[derive(Debug, Clone)]
struct SpfChecker {
    resolver: Arc<TokioAsyncResolver>,
    visited: Arc<tokio::sync::Mutex<HashSet<String>>>,
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
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl SpfChecker {
    async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Ok(Self {
            resolver: Arc::new(resolver),
            visited: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        })
    }

    async fn get_spf(&self, domain: &str) -> Result<Option<String>> {
        let response = self.resolver
            .txt_lookup(domain)
            .await
            .context("DNS lookup failed")?;

        Ok(response
            .iter()
            .find_map(|record| {
                let txt = record
                    .txt_data()
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect::<String>();
                txt.starts_with("v=spf1").then_some(txt)
            }))
    }

    async fn check(&self, domain: String, target: String) -> Result<bool> {
        {
            let mut visited = self.visited.lock().await;
            if !visited.insert(domain.clone()) {
                return Ok(false);
            }
        }

        let Some(spf_txt) = self.get_spf(&domain).await? else {
            return Ok(false);
        };

        let spf = Spf::from_str(&spf_txt)
            .context("Failed to parse SPF record")?;

        let includes: Vec<String> = spf
            .iter()
            .filter(|m| m.kind().is_include())
            .map(|m| m.raw())
            .collect();

        if includes.contains(&target) {
            return Ok(true);
        }

        let futures: Vec<_> = includes
            .into_iter()
            .map(|include| {
                let checker = self.clone();
                let target = target.clone();
                async move { checker.check(include, target).await }
            })
            .collect();

        let results = futures::future::join_all(futures).await;
        Ok(results.into_iter().any(|r| r.unwrap_or(false)))
    }

    async fn visited_count(&self) -> usize {
        self.visited.lock().await.len()
    }

    async fn reset_visited(&self) {
        self.visited.lock().await.clear();
    }
}

async fn check_spf(
    Query(params): Query<SpfCheckParams>,
    checker: axum::extract::State<Arc<SpfChecker>>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();

    checker.reset_visited().await;

    match checker.check(params.domain.clone(), params.target.clone()).await {
        Ok(found) => {
            let response = SpfCheckResponse {
                found,
                checked_domains: checker.visited_count().await,
                domain: params.domain,
                target: params.target,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => {
            let error = ErrorResponse {
                error: err.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

#[tokio::main]
async fn main() -> Result<()> {
    let checker = Arc::new(SpfChecker::new().await?);

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
        .with_state(checker);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
