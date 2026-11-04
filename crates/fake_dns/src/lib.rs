//! A minimal DNS server on localhost for tests, so code using `TokioAsyncResolver` can be
//! tested without hitting real DNS. It answers every query with the TXT records of the
//! queried domain from a fixed zone, and with NXDOMAIN for domains not in the zone.

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

/// TXT records per domain (lowercase, without trailing dot). Each TXT record is a list of
/// character-strings, which DNS clients join without a separator.
pub type Zone = HashMap<&'static str, Vec<Vec<&'static str>>>;

/// Starts a DNS server for `zone` on a free UDP port on localhost and returns its address.
///
/// The server runs as a task on the current Tokio runtime until that runtime shuts down.
pub async fn start(zone: Zone) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buffer = [0u8; 512];

        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_bytes(&buffer[..length]).unwrap();
            let response = answer(&zone, &request);

            socket
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        }
    });

    address
}

/// Starts a DNS server for `zone` and returns a resolver that only queries that server.
pub async fn resolver(zone: Zone) -> TokioAsyncResolver {
    let address = start(zone).await;

    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig::new(address, Protocol::Udp));

    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_secs(2);
    options.cache_size = 0;

    TokioAsyncResolver::tokio(config, options)
}

fn answer(zone: &Zone, request: &Message) -> Message {
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

    response
}
