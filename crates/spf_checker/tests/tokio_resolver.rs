//! Tests the `SpnResolver` implementation of `TokioAsyncResolver` against a minimal DNS
//! server on localhost, so no real DNS is involved.

use fake_dns::Zone;
use spf_checker::SpnResolver;

#[tokio::test]
async fn test_finds_spf_record_among_other_txt_records() {
    let resolver = fake_dns::resolver(Zone::from([(
        "example.com",
        vec![
            vec!["google-site-verification=abc123"],
            vec!["v=spf1 include:spf.easybill-mail.de ~all"],
        ],
    )]))
    .await;

    let record = resolver.find_spf_record("example.com").await.unwrap();

    assert_eq!(
        record,
        Some("v=spf1 include:spf.easybill-mail.de ~all".to_string())
    );
}

#[tokio::test]
async fn test_joins_character_strings_of_one_txt_record_without_separator() {
    let resolver = fake_dns::resolver(Zone::from([(
        "example.com",
        vec![vec![
            "v=spf1 include:_spf.google.com ",
            "include:spf.easybill-mail.de ~all",
        ]],
    )]))
    .await;

    let record = resolver.find_spf_record("example.com").await.unwrap();

    assert_eq!(
        record,
        Some("v=spf1 include:_spf.google.com include:spf.easybill-mail.de ~all".to_string())
    );
}

#[tokio::test]
async fn test_returns_none_without_spf_record() {
    let resolver = fake_dns::resolver(Zone::from([(
        "example.com",
        vec![vec!["google-site-verification=abc123"]],
    )]))
    .await;

    let record = resolver.find_spf_record("example.com").await.unwrap();

    assert_eq!(record, None);
}

#[tokio::test]
async fn test_rejects_multiple_spf_records() {
    let resolver = fake_dns::resolver(Zone::from([(
        "example.com",
        vec![
            vec!["v=spf1 include:_spf.google.com ~all"],
            vec!["v=spf1 include:spf.easybill-mail.de ~all"],
        ],
    )]))
    .await;

    let error = resolver.find_spf_record("example.com").await.unwrap_err();

    assert_eq!(error.to_string(), "MULTIPLE_SPF_RECORDS");
}

#[tokio::test]
async fn test_fails_for_unknown_domain() {
    let resolver = fake_dns::resolver(Zone::new()).await;

    let error = resolver.find_spf_record("example.com").await.unwrap_err();

    assert_eq!(error.to_string(), "DNS_LOOKUP_FAILED");
}
