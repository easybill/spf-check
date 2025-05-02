use crate::{log_message, Result};
use anyhow::Context;
use async_trait::async_trait;
use decon_spf::Spf;
use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;

#[async_trait]
pub trait SpnResolver: Debug {
    async fn find_spf_record(&self, domain: &str) -> Result<Option<String>>;
}

#[async_trait]
impl SpnResolver for TokioAsyncResolver {
    async fn find_spf_record(&self, domain: &str) -> Result<Option<String>> {
        let response = self.txt_lookup(domain).await.context("DNS_LOOKUP_FAILED")?;

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

/// https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
///
/// > SPF implementations MUST limit the total number of those terms to 10
/// > during SPF evaluation, to avoid unreasonable load on the DNS.
const DNS_LOOKUP_LIMIT: usize = 10;

#[derive(Clone, Debug)]
pub struct SpfChecker {
    resolver: Arc<dyn SpnResolver + Send + Sync + 'static>,
}

impl SpfChecker {
    pub fn new<R>(resolver: R) -> Self
    where
        R: SpnResolver + Send + Sync + 'static,
    {
        Self {
            resolver: Arc::new(resolver),
        }
    }

    pub async fn check(&self, root_domain: &String, target: &String) -> Result<CheckResult> {
        let mut to_visit_stack = vec![root_domain.to_owned()];
        let mut visited = HashSet::new();

        let mut root_spf_record = None;
        let mut included_domains: Vec<String> = Vec::new();

        while let Some(current_domain) = to_visit_stack.pop() {
            if visited.len() >= DNS_LOOKUP_LIMIT {
                log_message(format!(
                    "Maximum DNS lookup limit reached of {} reached. Visited domains: {:?}",
                    DNS_LOOKUP_LIMIT,
                    visited.iter().collect::<Vec<_>>()
                ));
                break;
            }

            if !visited.insert(current_domain.clone()) {
                // Already visited
                continue;
            }

            let Some(spf_txt) = self.resolver.find_spf_record(&current_domain).await? else {
                continue;
            };

            let spf = Spf::from_str(&spf_txt).context("SPF_PARSE_FAILED")?;

            if root_domain == &current_domain {
                root_spf_record = Some(spf_txt);
            }

            let includes: Vec<String> = spf
                .iter()
                .filter(|mechanism| mechanism.kind().is_include())
                .map(|mechanism| mechanism.raw())
                .collect();

            included_domains.extend(includes.iter().cloned());

            if includes.contains(target) {
                // Target found
                return Ok(CheckResult {
                    found: true,
                    visited: visited.len(),
                    spf_record: root_spf_record,
                    included_domains: Some(included_domains),
                });
            }

            // https://datatracker.ietf.org/doc/html/rfc7208#section-6.1
            //
            // > Any "redirect" modifier MUST be ignored if there is an "all" mechanism anywhere in
            // > the record."
            if !spf.iter().any(|mechanism| mechanism.kind().is_all()) {
                let redirect = spf
                    .iter()
                    .filter(|mechanism| mechanism.kind().is_redirect())
                    .map(|mechanism| mechanism.raw());

                to_visit_stack.extend(redirect);
            }

            // Prefer `include` before `redirect` by pushing them onto the top of the stack.
            to_visit_stack.extend(includes);
        }

        // Target not found in any domain
        Ok(CheckResult {
            found: false,
            visited: visited.len(),
            spf_record: root_spf_record,
            included_domains: Some(included_domains),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    struct MockResolver {
        records: Arc<Mutex<HashMap<String, String>>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                records: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn add_record(&self, domain: &str, spf_record: &str) {
            let mut records = self.records.lock().unwrap();
            records.insert(domain.to_string(), spf_record.to_owned());
        }
    }

    #[async_trait]
    impl SpnResolver for MockResolver {
        async fn find_spf_record(&self, domain: &str) -> Result<Option<String>> {
            let records = self.records.lock().expect("mutex poisoned");
            Ok(records.get(domain).cloned())
        }
    }

    #[tokio::test]
    async fn test_target_in_first_record() {
        let root_domain = "example.com".to_string();
        let target_domain = "mail.easybill.de".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 include:mail.easybill.de ~all");

        let checker = SpfChecker::new(mock_resolver.clone());
        let result = checker.check(&root_domain, &target_domain).await.unwrap();

        assert!(result.found);
        assert_eq!(result.visited, 1);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 include:mail.easybill.de ~all".to_string()),
        );
        assert_eq!(result.included_domains, Some(vec![target_domain]));
    }

    #[tokio::test]
    async fn test_target_not_in_first_record() {
        let root_domain = "_spf.example.com".to_string();
        let target_domain = "mail.other.com".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 include:mail.easybill.de ~all");

        let checker = SpfChecker::new(mock_resolver.clone());
        let result = checker.check(&root_domain, &target_domain).await.unwrap();

        assert!(!result.found);
        assert_eq!(result.visited, 2);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 include:mail.easybill.de ~all".to_string()),
        );
        assert_eq!(
            result.included_domains,
            Some(vec!["mail.easybill.de".to_string()])
        );
    }

    #[tokio::test]
    async fn test_target_in_redirected_record() {
        let root_domain = "example.com".to_string();
        let redirect_domain = "spf.easybill-mail.de".to_string();
        let target_domain = "mail.easybill.de".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 redirect=spf.easybill-mail.de");
        mock_resolver.add_record(&redirect_domain, "v=spf1 include:mail.easybill.de ~all");

        let checker = SpfChecker::new(mock_resolver.clone());
        let result = checker.check(&root_domain, &target_domain).await.unwrap();

        assert!(result.found);
        assert_eq!(result.visited, 2);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 redirect=spf.easybill-mail.de".to_string()),
        );
        assert_eq!(result.included_domains, Some(vec![target_domain]));
    }

    #[tokio::test]
    async fn test_target_not_in_redirected_record() {
        let root_domain = "example.com".to_string();
        let redirect_domain = "spf.easybill-mail.de".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 redirect=spf.easybill-mail.de");
        mock_resolver.add_record(&redirect_domain, "v=spf1 include:mail.easybill.de ~all");

        let checker = SpfChecker::new(mock_resolver.clone());

        let target = "other.com".to_string();
        let result = checker.check(&root_domain, &target).await.unwrap();

        assert!(!result.found);
        assert_eq!(result.visited, 3);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 redirect=spf.easybill-mail.de".to_string()),
        );
        assert_eq!(
            result.included_domains,
            Some(vec!["mail.easybill.de".to_string()])
        );
    }
}
