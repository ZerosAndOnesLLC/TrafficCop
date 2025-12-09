# Traffic Management

A high-performance reverse proxy and load balancer written in Rust, designed to handle 750k+ requests/second with predictable latency and zero garbage collection pauses.

## Features

- **High Performance**: Built with Rust for maximum throughput and minimal latency
- **Zero GC Pauses**: No garbage collector means consistent, predictable response times
- **HTTP/1.1 & HTTP/2**: Automatic protocol detection with ALPN negotiation for TLS
- **WebSocket Proxying**: Full WebSocket upgrade and bidirectional streaming support
- **Hot Config Reload**: Configuration changes applied without restart or dropping connections
- **Graceful Shutdown**: Connection draining with configurable timeout
- **Load Balancing**: Round-robin, smooth weighted round-robin, least connections, random
- **Health Checks**: HTTP health checks with configurable thresholds
- **Circuit Breaker**: Automatic backend isolation on failures with recovery
- **TLS Termination**: Native TLS support via rustls (no OpenSSL dependency)
- **Request Timeouts**: Configurable connect and request timeouts per service
- **Middleware Pipeline**: Rate limiting, headers, retry with exponential backoff, compression
- **Compression**: gzip and brotli response compression
- **Access Logging**: Structured JSON access logs
- **Metrics**: Prometheus-compatible metrics endpoint
- **Traefik-Compatible Rules**: Familiar rule syntax for routing

## Quick Start

### Build

```bash
cargo build --release
```

### Run

```bash
./target/release/traffic_management -c config.yaml
```

### Validate Configuration

```bash
./target/release/traffic_management -c config.yaml --validate
```

## Configuration

Configuration is defined in YAML format. See `config/example.yaml` for a complete example.

### Basic Example

```yaml
entrypoints:
  web:
    address: "0.0.0.0:80"
  websecure:
    address: "0.0.0.0:443"
    tls:
      cert_file: "/etc/certs/server.crt"
      key_file: "/etc/certs/server.key"

services:
  api:
    load_balancer:
      strategy: round_robin
    servers:
      - url: "http://10.0.0.1:8080"
      - url: "http://10.0.0.2:8080"
    health_check:
      path: "/health"
      interval_seconds: 10

routers:
  api-router:
    entrypoints:
      - websecure
    rule: "Host(`api.example.com`) && PathPrefix(`/v1`)"
    service: api
```

### Routing Rules

Rules use a Traefik-compatible syntax:

| Function | Description | Example |
|----------|-------------|---------|
| `Host` | Match hostname | `Host(\`example.com\`)` |
| `HostRegexp` | Match hostname regex | `HostRegexp(\`.*\\.example\\.com\`)` |
| `Path` | Exact path match | `Path(\`/api/v1/users\`)` |
| `PathPrefix` | Path prefix match | `PathPrefix(\`/api\`)` |
| `PathRegexp` | Path regex match | `PathRegexp(\`/api/v[0-9]+\`)` |
| `Header` | Match header value | `Header(\`X-Custom\`, \`value\`)` |
| `Method` | Match HTTP method | `Method(\`POST\`)` |

Combine rules with `&&` (AND), `||` (OR), and `!` (NOT).

### Load Balancing Strategies

- `round_robin` - Distribute requests evenly across servers
- `weighted` - Distribute based on server weights
- `least_conn` - Send to server with fewest active connections
- `random` - Random server selection

### Middlewares

```yaml
middlewares:
  rate-limit:
    rate_limit:
      average: 100
      burst: 50
      period_seconds: 1

  headers:
    headers:
      request_headers:
        X-Request-ID: "${uuid}"
      response_headers:
        X-Frame-Options: "DENY"

  retry:
    retry:
      attempts: 3
      initial_interval_ms: 100

  circuit-breaker:
    circuit_breaker:
      failure_threshold: 5
      recovery_timeout_seconds: 30

  compress:
    compress:
      min_response_body_bytes: 1024
```

### Metrics

Enable Prometheus metrics endpoint:

```yaml
metrics:
  address: "0.0.0.0:9090"
```

Access metrics at `http://localhost:9090/metrics`.

## Architecture

```
┌─────────────────────────────────────┐
│         Entry Points                │
│   (HTTP/HTTPS/TCP/UDP Listeners)    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│          Router Layer               │
│  (Host, Path, Header matching)      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Middleware Pipeline            │
│ (Auth, RateLimit, Headers, etc.)    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│         Load Balancer               │
│(Round-robin, Weighted, Sticky)      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│       Connection Pool               │
│   (Backend connection reuse)        │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│       Backend Services              │
└─────────────────────────────────────┘
```

## Performance

Target performance metrics:

| Metric | Target |
|--------|--------|
| Throughput | 750k+ req/s per instance |
| p50 latency | < 1ms added |
| p99 latency | < 5ms added |
| p99.9 latency | < 10ms added |
| Memory | < 100MB base |

## Development

### Run Tests

```bash
cargo test
```

### Run Benchmarks

```bash
cargo bench
```

### Debug Mode

```bash
./target/release/traffic_management -c config.yaml --debug
```

## Project Structure

```
traffic_management/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library entry point
│   ├── config/          # Configuration parsing
│   ├── server/          # HTTP listeners
│   ├── router/          # Rule matching engine
│   ├── proxy/           # Request proxying
│   ├── balancer/        # Load balancing
│   ├── middleware/      # Middleware pipeline
│   ├── health/          # Health checking
│   ├── pool/            # Connection pooling
│   ├── tls/             # TLS/ACME
│   └── metrics/         # Prometheus metrics
├── config/
│   └── example.yaml     # Example configuration
└── benches/
    └── proxy_benchmark.rs
```

## License

MIT
