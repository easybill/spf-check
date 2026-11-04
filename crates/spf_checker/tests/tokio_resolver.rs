//! Tests the `SpnResolver` implementation of `TokioAsyncResolver` against a minimal DNS
//! server on localhost, so no real DNS is involved.

use spf_checker::SpnResolver;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::rdata::TXT;
use trust_dns_proto::rr::{RData, Record};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// TXT records per domain. Each TXT record is a list of character-strings.
type Zone = HashMap<&'static str, Vec<Vec<&'static str>>>;

/// Answers every query from `zone` and returns NXDOMAIN for unknown domains.
async fn start_dns_server(zone: Zone) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buffer = [0u8; 512];

        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_bytes(&buffer[..length]).unwrap();
            let query = request.queries()[0].clone();
            let domain = query.name().to_ascii().to_lowercase();

            let mut response = Message::new();
            response
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_op_code(request.op_code())
                .set_recursion_desired(request.recursion_desired())
                .set_recursion_available(true)
                .add_query(query.clone());

            match zone.get(domain.trim_end_matches('.')) {
                Some(txt_records) => {
                    for strings in txt_records {
                        let txt = TXT::new(strings.iter().map(|s| s.to_string()).collect());
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            60,
                            RData::TXT(txt),
                        ));
                    }
                }
                None => {
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }

            socket
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        }
    });

    address
}

async fn resolver_for(zone: Zone) -> TokioAsyncResolver {
    let address = start_dns_server(zone).await;

    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig::new(address, Protocol::Udp));

    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_secs(2);
    options.cache_size = 0;

    TokioAsyncResolver::tokio(config, options)
}

#[tokio::test]
async fn test_finds_spf_record_among_other_txt_records() {
    let resolver = resolver_for(Zone::from([(
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
    let resolver = resolver_for(Zone::from([(
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
    let resolver = resolver_for(Zone::from([(
        "example.com",
        vec![vec!["google-site-verification=abc123"]],
    )]))
    .await;

    let record = resolver.find_spf_record("example.com").await.unwrap();

    assert_eq!(record, None);
}

#[tokio::test]
async fn test_rejects_multiple_spf_records() {
    let resolver = resolver_for(Zone::from([(
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
    let resolver = resolver_for(Zone::new()).await;

    let error = resolver.find_spf_record("example.com").await.unwrap_err();

    assert_eq!(error.to_string(), "DNS_LOOKUP_FAILED");
}
