use anyhow::{Context, Result};
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
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self {
            resolver: Arc::new(resolver),
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

const LOG_TIMESTAMP_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%.3f";

async fn check_spf(
    Query(params): Query<SpfCheckParams>,
    checker: axum::extract::State<Arc<SpfChecker>>,
) -> impl IntoResponse {
    println!(
        "[{}] Request to check \"{}\" for \"{}\"",
        chrono::Local::now().format(LOG_TIMESTAMP_FORMAT),
        params.domain,
        params.target
    );

    let start = std::time::Instant::now();
    let mut visited = HashSet::new();

    match checker
        .check(params.domain.clone(), params.target.clone(), &mut visited)
        .await
    {
        Ok((found, spf_record, included_domains)) => {
            let response = SpfCheckResponse {
                found,
                checked_domains: visited.len(),
                domain: params.domain,
                target: params.target,
                elapsed_ms: start.elapsed().as_millis() as u64,
                has_spf_record: spf_record.is_some(),
                spf_record,
                included_domains,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => {
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

#[tokio::main]
async fn main() -> Result<()> {
    let checker = Arc::new(SpfChecker::new().await?);

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/check-spf", get(check_spf))
        .with_state(checker);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!(
        "[{}] Listening on {}",
        chrono::Local::now().format(LOG_TIMESTAMP_FORMAT),
        addr
    );

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
