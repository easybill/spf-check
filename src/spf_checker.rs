use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use anyhow::Context;
use decon_spf::Spf;
use trust_dns_resolver::TokioAsyncResolver;
use crate::log_message;
use async_trait::async_trait;

#[async_trait]
pub trait SpnResolver: Debug {
    async fn resolve(&self, domain: &str) -> anyhow::Result<Option<String>>;
}

#[async_trait]
impl SpnResolver for TokioAsyncResolver {
    async fn resolve(&self, domain: &str) -> anyhow::Result<Option<String>> {
        let response = self
            .txt_lookup(domain)
            .await
            .context("DNS_LOOKUP_FAILED")?;

        Ok(response.iter().find_map(|record| {
            let txt = record.to_string();
            txt.starts_with("v=spf1").then_some(txt)
        }))
    }
}

pub struct CheckResult {
    pub found: bool,
    pub visited: usize,
    pub spf_record: Option<String>,
    pub included_domains: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct SpfChecker {
    resolver: Arc<dyn SpnResolver + Send + Sync + 'static>,
    max_depth: usize,
}

impl SpfChecker {
    pub fn new<R: SpnResolver + Send + Sync + 'static>(resolver: R) -> Self {
        Self {
            resolver: Arc::new(resolver),
            max_depth: 10,
        }
    }

    pub async fn check(&self, root_domain: &String, target: &String) -> anyhow::Result<CheckResult> {
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

            let Some(spf_txt) = self.resolver.resolve(&current_domain).await? else {
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
