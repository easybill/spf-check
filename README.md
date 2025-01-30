# spf-check

A fast, asynchronous SPF record chain validator with a focus on user-friendly debugging. Built as a REST service for Kubernetes deployments.

## Features
- 🚀 Parallel DNS lookups and SPF record validation
- 🔍 Deep inspection of SPF include chains
- 💡 Human-friendly recommendations and error messages
- 🔄 Kubernetes-ready with health endpoint
- ⚡ Built with Rust for performance and reliability

## Use Case
Helps email administrators and non-technical users debug SPF record configurations by tracing include chains and providing clear, actionable feedback.

## API

Simple REST API that checks if a target SPF record exists in a domain's SPF chain.

### Endpoints

#### Check SPF Record

```http request
GET /api/v1/check-spf?domain={domain}&target={target}
```
Parameters:
- `domain`: The domain to check (e.g., `example.com`)
- `target`: The SPF record to find (e.g., `_spf.example.com`)

Example:
```bash
curl "http://localhost:8080/api/v1/check-spf?domain=example.com&target=_spf.example.com"
```
Response:
```json
{
  "found": true,
  "checked_domains": 3,
  "domain": "example.com",
  "target": "_spf.example.com",
  "elapsed_ms": 42
}
```
#### Health Check
```
GET /health
```
Example:
```bash
curl "http://localhost:8080/health"
```
Response:
```
HTTP/1.1 200 OK
```
