# SPF Check

<!--DESC:Service checks if a domain is within another's SPF record chain.:DESC-->
A high-performance web service that checks if a target domain is included (directly or indirectly) in another domain's SPF (Sender Policy Framework) record chain.


## Features

- 🚀 Fast asynchronous DNS lookups
- 🔄 Recursive checking of SPF include chains
- 📋 Returns complete SPF record and include chain information
- 💓 Health check endpoint
- 🔒 Secure and efficient with Rust
- 🌐 Easy to use HTML UI

## API

### Check SPF Record

Checks if a target domain is included in another domain's SPF record chain.

```http
GET /api/v1/check-spf?domain={domain}&target={target}
```

#### Parameters

- `domain`: The domain to check the SPF record for (e.g., `example.com`)
- `target`: The domain to look for in the SPF include chain (e.g., `_spf.example.com`)

#### Success Response

```json
{
    "found": true,
    "checked_domains": 3,
    "domain": "example.com",
    "target": "spf.protection.outlook.com",
    "elapsed_ms": 42,
    "has_spf_record": true,
    "spf_record": "v=spf1 include:spf.protection.outlook.com -all",
    "included_domains": ["spf.protection.outlook.com"]
}
```

- `found`: Boolean indicating if the target was found in the SPF chain
- `checked_domains`: Number of domains checked in the process
- `domain`: The original domain that was checked
- `target`: The domain that was searched for
- `elapsed_ms`: Time taken for the check in milliseconds
- `has_spf_record`: Boolean indicating if the domain has an SPF record
- `spf_record`: The complete SPF record of the main domain (if exists, otherwise `null`)
- `included_domains`: List of domains included in the main SPF record (if exists, otherwise `null`)

#### Error Response

```json
{
    "error": "DNS_LOOKUP_FAILED"
}
```

Common error codes:
- `DNS_LOOKUP_FAILED`: Unable to perform DNS lookup or `TXT` record does not exist
- `SPF_PARSE_FAILED`: Invalid SPF record format

### Health Check

```http
GET /health
```

Returns `200 OK` if the service is running.

### HTML UI

```url
http://localhost:8080/ui
```
Returns a simple HTML UI for checking SPF records.

## Example Usage

Check if outlook.com's SPF is included in example.com's SPF chain:

```bash
curl "http://localhost:8080/api/v1/check-spf?domain=example.com&target=spf.protection.outlook.com"
```

## Installation

1. Ensure you have Rust installed
2. Clone the repository
3. Build and run:

```bash
cargo build --release
./target/release/spf-check
```

The service will listen on `0.0.0.0:8080` by default.

## Performance

- Asynchronous processing allows handling multiple requests simultaneously
- Each request maintains its own state, preventing cross-request interference
- Efficient DNS caching through the trust-dns-resolver

## Dependencies

- axum: Web framework
- tokio: Async runtime
- trust-dns-resolver: DNS resolution
- decon-spf: SPF record parsing
- serde: Serialization/Deserialization
- chrono: Timestamp formatting
