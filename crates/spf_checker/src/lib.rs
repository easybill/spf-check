use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use decon_spf::Spf;
use ipnetwork::IpNetwork;
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

        // A single TXT record may consist of several character-strings (each at most
        // 255 bytes); RFC 7208, section 3.3 requires joining them without a separator.
        let txt_records = response.iter().map(|record| {
            record
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk))
                .collect::<String>()
        });

        select_single_spf_record(txt_records)
    }
}

fn is_spf_record(txt: &str) -> bool {
    txt == "v=spf1" || txt.starts_with("v=spf1 ")
}

fn select_single_spf_record(
    txt_records: impl IntoIterator<Item = String>,
) -> Result<Option<String>> {
    let mut spf_records = txt_records.into_iter().filter(|txt| is_spf_record(txt));

    let first = spf_records.next();

    if spf_records.next().is_some() {
        bail!("MULTIPLE_SPF_RECORDS");
    }

    Ok(first)
}

#[derive(Debug)]
pub struct CheckResult {
    /// Whether the checked domain authorizes every sending IP of the target, either by
    /// including the target by name or by listing networks that cover all of its IPs.
    pub found: bool,
    /// Number of SPF records looked up across the checked domain and the target.
    pub visited: usize,
    /// The top-level SPF record of the checked domain, if it publishes one.
    pub spf_record: Option<String>,
    /// Every `include:` domain found while following the checked domain's SPF chain.
    pub included_domains: Option<Vec<String>>,
    /// Kept for API compatibility. The string-based fallback check no longer exists,
    /// so this is always `false`.
    pub fallback_check: bool,
}

/// https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
///
/// > SPF implementations MUST limit the total number of those terms to 10
/// > during SPF evaluation, to avoid unreasonable load on the DNS.
const DNS_LOOKUP_LIMIT: usize = 10;

fn log_message(msg: impl AsRef<str>) {
    println!(
        "[{}] {}",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
        msg.as_ref()
    );
}

/// One domain's SPF chain, flattened by following all `include` and `redirect` references.
#[derive(Debug, Default)]
struct ResolvedSpf {
    record: Option<String>,
    included_domains: Vec<String>,
    networks: Vec<IpNetwork>,
    visited: usize,
}

impl ResolvedSpf {
    fn covers(&self, network: &IpNetwork) -> bool {
        self.networks
            .iter()
            .any(|own| network_contains(own, network))
    }
}

fn network_contains(outer: &IpNetwork, inner: &IpNetwork) -> bool {
    match (outer, inner) {
        (IpNetwork::V4(outer), IpNetwork::V4(inner)) => {
            outer.prefix() <= inner.prefix() && outer.contains(inner.network())
        }
        (IpNetwork::V6(outer), IpNetwork::V6(inner)) => {
            outer.prefix() <= inner.prefix() && outer.contains(inner.network())
        }
        _ => false,
    }
}

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
        let root = self.resolve(root_domain).await?;

        if root.included_domains.contains(target) {
            return Ok(CheckResult {
                found: true,
                visited: root.visited,
                spf_record: root.record,
                included_domains: Some(root.included_domains),
                fallback_check: false,
            });
        }

        let target_spf = self.resolve(target).await?;

        let uncovered: Vec<&IpNetwork> = target_spf
            .networks
            .iter()
            .filter(|network| !root.covers(network))
            .collect();

        let found = !target_spf.networks.is_empty() && uncovered.is_empty();

        if !found {
            log_message(format!(
                "\"{root_domain}\" does not cover \"{target}\". Target networks: {:?}, uncovered: {uncovered:?}",
                target_spf.networks
            ));
        }

        Ok(CheckResult {
            found,
            visited: root.visited + target_spf.visited,
            spf_record: root.record,
            included_domains: Some(root.included_domains),
            fallback_check: false,
        })
    }

    async fn resolve(&self, domain: &str) -> Result<ResolvedSpf> {
        let mut resolved = ResolvedSpf::default();
        let mut visited = HashSet::new();
        let mut to_visit_stack = vec![domain.to_owned()];

        while let Some(current_domain) = to_visit_stack.pop() {
            if visited.contains(&current_domain) {
                continue;
            }

            // The lookup of the domain itself does not count towards the limit.
            if visited.len() > DNS_LOOKUP_LIMIT {
                log_message(format!(
                    "DNS lookup limit of {DNS_LOOKUP_LIMIT} reached while resolving \"{domain}\". \
                     Continuing with the records collected so far, skipping \"{current_domain}\" \
                     and {} more.",
                    to_visit_stack.len()
                ));
                break;
            }

            visited.insert(current_domain.clone());

            let Some(spf_txt) = self.resolver.find_spf_record(&current_domain).await? else {
                continue;
            };

            let spf = Spf::from_str(&spf_txt).context("SPF_PARSE_FAILED")?;

            let mut includes = Vec::new();
            let mut redirect = None;
            let mut has_all = false;

            for mechanism in spf.iter() {
                let kind = mechanism.kind();

                if kind.is_all() {
                    has_all = true;
                } else if kind.is_redirect() {
                    redirect = Some(mechanism.raw());
                } else if !mechanism.qualifier().is_pass() {
                    continue;
                } else if kind.is_include() {
                    includes.push(mechanism.raw());
                } else if kind.is_ip() {
                    // `Spf::from_str` already rejects invalid `ip4`/`ip6` values, so parsing
                    // the validated value again cannot fail.
                    resolved
                        .networks
                        .extend(IpNetwork::from_str(&mechanism.raw()).ok());
                }
            }

            if current_domain == domain {
                resolved.record = Some(spf_txt);
            }

            resolved.included_domains.extend(includes.iter().cloned());

            // https://datatracker.ietf.org/doc/html/rfc7208#section-6.1
            //
            // > Any "redirect" modifier MUST be ignored if there is an "all" mechanism anywhere in
            // > the record.
            if !has_all {
                to_visit_stack.extend(redirect);
            }

            // Pushed last and reversed, so includes are followed before the redirect and in
            // the order they appear in the record.
            to_visit_stack.extend(includes.into_iter().rev());
        }

        resolved.visited = visited.len();

        Ok(resolved)
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
        failing_domains: Arc<Mutex<HashSet<String>>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                records: Arc::new(Mutex::new(HashMap::new())),
                failing_domains: Arc::new(Mutex::new(HashSet::new())),
            }
        }

        fn add_record(&self, domain: &str, spf_record: &str) {
            let mut records = self.records.lock().unwrap();
            records.insert(domain.to_string(), spf_record.to_owned());
        }

        fn fail_lookup(&self, domain: &str) {
            let mut failing_domains = self.failing_domains.lock().unwrap();
            failing_domains.insert(domain.to_string());
        }
    }

    #[async_trait]
    impl SpnResolver for MockResolver {
        async fn find_spf_record(&self, domain: &str) -> Result<Option<String>> {
            if self.failing_domains.lock().unwrap().contains(domain) {
                bail!("DNS_LOOKUP_FAILED");
            }

            let records = self.records.lock().expect("mutex poisoned");
            Ok(records.get(domain).cloned())
        }
    }

    fn txt_records(records: &[&str]) -> Vec<String> {
        records.iter().map(|record| record.to_string()).collect()
    }

    #[test]
    fn test_select_single_spf_record_among_other_txt_records() {
        let records = txt_records(&[
            "google-site-verification=abc123",
            "v=spf1 include:spf.easybill-mail.de ~all",
            "MS=ms12345678",
        ]);

        let result = select_single_spf_record(records).unwrap();

        assert_eq!(
            result,
            Some("v=spf1 include:spf.easybill-mail.de ~all".to_string())
        );
    }

    #[test]
    fn test_select_single_spf_record_without_spf_record() {
        let records = txt_records(&["google-site-verification=abc123"]);

        let result = select_single_spf_record(records).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn test_select_single_spf_record_rejects_multiple_spf_records() {
        let records = txt_records(&[
            "v=spf1 include:_spf.google.com ~all",
            "v=spf1 include:spf.easybill-mail.de ~all",
        ]);

        let error = select_single_spf_record(records).unwrap_err();

        assert_eq!(error.to_string(), "MULTIPLE_SPF_RECORDS");
    }

    #[test]
    fn test_select_single_spf_record_ignores_other_versions() {
        let records = txt_records(&["v=spf10 ip4:192.0.2.1", "v=spf1 ip4:192.0.2.2 -all"]);

        let result = select_single_spf_record(records).unwrap();

        assert_eq!(result, Some("v=spf1 ip4:192.0.2.2 -all".to_string()));
    }

    #[test]
    fn test_select_single_spf_record_accepts_bare_version() {
        let records = txt_records(&["v=spf1"]);

        let result = select_single_spf_record(records).unwrap();

        assert_eq!(result, Some("v=spf1".to_string()));
    }

    async fn check(mock_resolver: &MockResolver, root_domain: &str, target: &str) -> CheckResult {
        SpfChecker::new(mock_resolver.clone())
            .check(&root_domain.to_string(), &target.to_string())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_target_in_first_record() {
        let root_domain = "example.com".to_string();
        let target_domain = "mail.easybill.de".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 include:mail.easybill.de ~all");

        let result = check(&mock_resolver, &root_domain, &target_domain).await;

        assert!(result.found);
        assert_eq!(result.visited, 2);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 include:mail.easybill.de ~all".to_string()),
        );
        assert_eq!(result.included_domains, Some(vec![target_domain]));
        assert!(!result.fallback_check);
    }

    #[tokio::test]
    async fn test_target_not_in_first_record() {
        let root_domain = "_spf.example.com".to_string();
        let target_domain = "mail.other.com".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 include:mail.easybill.de ~all");

        let result = check(&mock_resolver, &root_domain, &target_domain).await;

        assert!(!result.found);
        assert_eq!(result.visited, 3);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 include:mail.easybill.de ~all".to_string()),
        );
        assert_eq!(
            result.included_domains,
            Some(vec!["mail.easybill.de".to_string()])
        );
        assert!(!result.fallback_check);
    }

    #[tokio::test]
    async fn test_target_in_redirected_record() {
        let root_domain = "example.com".to_string();
        let redirect_domain = "spf.easybill-mail.de".to_string();
        let target_domain = "mail.easybill.de".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 redirect=spf.easybill-mail.de");
        mock_resolver.add_record(&redirect_domain, "v=spf1 include:mail.easybill.de ~all");

        let result = check(&mock_resolver, &root_domain, &target_domain).await;

        assert!(result.found);
        assert_eq!(result.visited, 3);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 redirect=spf.easybill-mail.de".to_string()),
        );
        assert_eq!(result.included_domains, Some(vec![target_domain]));
        assert!(!result.fallback_check);
    }

    #[tokio::test]
    async fn test_target_redirect_with_ip4_ip6_mechanism_instead_of_include() {
        let target_domain = "spf.easybill-mail.de".to_string();
        let target_include_domain = "ipv4.spf.easybill-mail.de".to_string();

        let root_domain = "auc-online.de".to_string();
        let redirect_domain = "auc-online.de.spf.hornetdmarc.com".to_string();

        let mock_resolver = MockResolver::new();

        // The target publishes its IPs behind an include.
        mock_resolver.add_record(&target_domain, "v=spf1 include:ipv4.spf.easybill-mail.de");
        mock_resolver.add_record(&target_include_domain, "v=spf1 ip4:167.235.178.61");

        // The root domain redirects to a flattened record that lists the target's IP directly.
        mock_resolver.add_record(
            &root_domain,
            "v=spf1 redirect=auc-online.de.spf.hornetdmarc.com",
        );
        mock_resolver.add_record(&redirect_domain, "v=spf1 ip4:167.235.178.61 ~all");

        let result = check(&mock_resolver, &root_domain, &target_domain).await;

        assert!(result.found);
        assert_eq!(result.visited, 4);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 redirect=auc-online.de.spf.hornetdmarc.com".to_string()),
        );
        assert_eq!(result.included_domains, Some(vec![]));
        assert!(!result.fallback_check);
    }

    #[tokio::test]
    async fn test_target_not_in_redirected_record() {
        let root_domain = "example.com".to_string();
        let redirect_domain = "spf.easybill-mail.de".to_string();

        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(&root_domain, "v=spf1 redirect=spf.easybill-mail.de");
        mock_resolver.add_record(&redirect_domain, "v=spf1 include:mail.easybill.de ~all");

        let target = "other.com".to_string();
        let result = check(&mock_resolver, &root_domain, &target).await;

        assert!(!result.found);
        assert_eq!(result.visited, 4);
        assert_eq!(
            result.spf_record,
            Some("v=spf1 redirect=spf.easybill-mail.de".to_string()),
        );
        assert_eq!(
            result.included_domains,
            Some(vec!["mail.easybill.de".to_string()])
        );
        assert!(!result.fallback_check);
    }

    #[tokio::test]
    async fn test_target_ip4_and_ip6_covered_through_nested_includes() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 ip6:2001:db8::10 -all");
        mock_resolver.add_record("example.com", "v=spf1 include:_spf.example.com ~all");
        mock_resolver.add_record(
            "_spf.example.com",
            "v=spf1 include:_v6.example.com ip4:192.0.2.10",
        );
        mock_resolver.add_record("_v6.example.com", "v=spf1 ip6:2001:db8::10");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(result.found);
        assert!(!result.fallback_check);
    }

    #[tokio::test]
    async fn test_target_partially_covered() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 ip4:192.0.2.20 -all");
        mock_resolver.add_record("example.com", "v=spf1 ip4:192.0.2.10 ~all");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
    }

    #[tokio::test]
    async fn test_target_covered_by_wider_range() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record(
            "target.com",
            "v=spf1 ip4:192.0.2.10 ip4:192.0.2.64/28 ip6:2001:db8:1::/64 -all",
        );
        mock_resolver.add_record(
            "example.com",
            "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all",
        );

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(result.found);
    }

    #[tokio::test]
    async fn test_target_not_covered_by_narrower_range() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.0/24 -all");
        mock_resolver.add_record("example.com", "v=spf1 ip4:192.0.2.10 ~all");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
    }

    #[tokio::test]
    async fn test_ip4_does_not_cover_ip6() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip6:::ffff:192.0.2.10 -all");
        mock_resolver.add_record("example.com", "v=spf1 ip4:0.0.0.0/0 ~all");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
    }

    #[tokio::test]
    async fn test_non_pass_qualified_mechanisms_do_not_cover() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 -all");
        mock_resolver.add_record(
            "example.com",
            "v=spf1 ~ip4:192.0.2.10 -include:other.example.com ?all",
        );
        mock_resolver.add_record("other.example.com", "v=spf1 ip4:192.0.2.10");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
        assert_eq!(result.included_domains, Some(vec![]));
    }

    #[tokio::test]
    async fn test_redirect_ignored_when_all_present() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 -all");
        mock_resolver.add_record("example.com", "v=spf1 redirect=_spf.example.com ~all");
        mock_resolver.add_record("_spf.example.com", "v=spf1 ip4:192.0.2.10");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
    }

    #[tokio::test]
    async fn test_target_without_ip_mechanisms_not_found() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 a mx -all");
        mock_resolver.add_record("example.com", "v=spf1 a mx ~all");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
    }

    async fn check_error(mock_resolver: &MockResolver, root_domain: &str, target: &str) -> String {
        SpfChecker::new(mock_resolver.clone())
            .check(&root_domain.to_string(), &target.to_string())
            .await
            .unwrap_err()
            .to_string()
    }

    #[tokio::test]
    async fn test_domain_reached_twice_is_resolved_once() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 -all");
        mock_resolver.add_record(
            "example.com",
            "v=spf1 include:_a.example.com include:_b.example.com ~all",
        );
        mock_resolver.add_record("_a.example.com", "v=spf1 include:_shared.example.com");
        mock_resolver.add_record("_b.example.com", "v=spf1 include:_shared.example.com");
        mock_resolver.add_record("_shared.example.com", "v=spf1 ip4:192.0.2.10");

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(result.found);
        assert_eq!(result.visited, 5);
        assert_eq!(
            result.included_domains,
            Some(vec![
                "_a.example.com".to_string(),
                "_b.example.com".to_string(),
                "_shared.example.com".to_string(),
                "_shared.example.com".to_string(),
            ])
        );
    }

    #[tokio::test]
    async fn test_lookup_failure_of_domain_fails_the_check() {
        let mock_resolver = MockResolver::new();
        mock_resolver.fail_lookup("example.com");

        let error = check_error(&mock_resolver, "example.com", "target.com").await;

        assert_eq!(error, "DNS_LOOKUP_FAILED");
    }

    #[tokio::test]
    async fn test_lookup_failure_of_target_fails_the_check() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("example.com", "v=spf1 ip4:192.0.2.10 ~all");
        mock_resolver.fail_lookup("target.com");

        let error = check_error(&mock_resolver, "example.com", "target.com").await;

        assert_eq!(error, "DNS_LOOKUP_FAILED");
    }

    #[tokio::test]
    async fn test_invalid_record_fails_the_check() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("example.com", "v=spf1 ip4:300.0.0.1 ~all");

        let error = check_error(&mock_resolver, "example.com", "target.com").await;

        assert_eq!(error, "SPF_PARSE_FAILED");
    }

    fn add_include_chain(mock_resolver: &MockResolver, root_domain: &str, includes: usize) {
        let mut current = root_domain.to_string();

        for index in 1..=includes {
            let next = format!("_spf{index}.example.com");
            mock_resolver.add_record(&current, &format!("v=spf1 include:{next} ~all"));
            current = next;
        }

        mock_resolver.add_record(&current, "v=spf1 ip4:192.0.2.10");
    }

    #[tokio::test]
    async fn test_lookup_limit_allows_ten_includes() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 -all");
        add_include_chain(&mock_resolver, "example.com", DNS_LOOKUP_LIMIT);

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(result.found);
        assert_eq!(result.visited, DNS_LOOKUP_LIMIT + 2);
    }

    #[tokio::test]
    async fn test_lookup_limit_stops_resolving_further_includes() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 -all");
        add_include_chain(&mock_resolver, "example.com", DNS_LOOKUP_LIMIT + 1);

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(!result.found);
        assert_eq!(result.visited, DNS_LOOKUP_LIMIT + 2);
    }

    #[tokio::test]
    async fn test_lookup_limit_keeps_records_collected_before_the_limit() {
        let mock_resolver = MockResolver::new();
        mock_resolver.add_record("target.com", "v=spf1 ip4:192.0.2.10 -all");
        add_include_chain(&mock_resolver, "_chain.example.com", DNS_LOOKUP_LIMIT + 1);
        mock_resolver.add_record(
            "example.com",
            "v=spf1 ip4:192.0.2.10 include:_chain.example.com ~all",
        );

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(result.found);
    }

    #[tokio::test]
    async fn test_lookup_limit_keeps_included_target_found_before_the_limit() {
        let mock_resolver = MockResolver::new();
        add_include_chain(&mock_resolver, "_chain.example.com", DNS_LOOKUP_LIMIT + 1);
        mock_resolver.add_record(
            "example.com",
            "v=spf1 include:_chain.example.com include:target.com ~all",
        );

        let result = check(&mock_resolver, "example.com", "target.com").await;

        assert!(result.found);
    }
}
