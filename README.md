# TrafficCop

A high-performance reverse proxy and load balancer written in Rust with **Traefik v3 compatible configuration**. Designed to handle 750k+ requests/second with predictable latency and zero garbage collection pauses.

## Features

- **Traefik v3 Compatible**: Drop-in replacement for Traefik using the same configuration format
- **High Performance**: Built with Rust for maximum throughput and minimal latency
- **Zero GC Pauses**: No garbage collector means consistent, predictable response times
- **HTTP/1.1 & HTTP/2**: Automatic protocol detection with ALPN negotiation for TLS
- **WebSocket Proxying**: Full WebSocket upgrade and bidirectional streaming support
- **Hot Config Reload**: Configuration changes applied without restart or dropping connections
- **Graceful Shutdown**: Connection draining with configurable timeout
- **Load Balancing**: Round-robin, weighted, least connections, random
- **Health Checks**: HTTP health checks with configurable thresholds
- **TLS Termination**: Native TLS support via rustls (no OpenSSL dependency)
- **Let's Encrypt ACME**: Automatic certificate provisioning and renewal
- **SNI-based Certificates**: Multiple certificates per listener with automatic selection
- **Middleware Pipeline**: Rate limiting, headers, retry with exponential backoff, compression, IP filtering, CORS, HTTPS redirect, authentication
- **Compression**: gzip, brotli, and zstd response compression
- **Access Logging**: Structured JSON access logs
- **Metrics**: Prometheus-compatible metrics endpoint

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

Configuration uses Traefik v3 format. See `config/example.yaml` for a complete example.

### Basic Example

```yaml
# Entry points (static config)
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true

  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt

# Dynamic HTTP config
http:
  routers:
    api-router:
      entryPoints:
        - websecure
      rule: "Host(`api.example.com`) && PathPrefix(`/v1`)"
      service: api
      middlewares:
        - rate-limit
      tls:
        certResolver: letsencrypt

  services:
    api:
      loadBalancer:
        servers:
          - url: "http://10.0.0.1:8080"
          - url: "http://10.0.0.2:8080"
        healthCheck:
          path: "/health"
          interval: "10s"
          timeout: "5s"

  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
        period: "1s"

# Certificate resolvers (ACME/Let's Encrypt)
certificatesResolvers:
  letsencrypt:
    acme:
      email: "admin@example.com"
      storage: "/data/acme.json"
      httpChallenge:
        entryPoint: web
```

### Routing Rules

Rules use Traefik-compatible syntax:

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

### Duration Format

Durations use Go-style format (same as Traefik):
- `100ms` - 100 milliseconds
- `10s` - 10 seconds
- `5m` - 5 minutes
- `1h30m` - 1 hour 30 minutes

### Services

```yaml
http:
  services:
    # Load balancer with health checks
    api:
      loadBalancer:
        servers:
          - url: "http://10.0.0.1:8080"
          - url: "http://10.0.0.2:8080"
        passHostHeader: true
        sticky:
          cookie:
            name: SERVERID
            secure: true
            httpOnly: true
        healthCheck:
          path: "/health"
          interval: "10s"
          timeout: "5s"

    # Weighted service (traffic splitting)
    canary:
      weighted:
        services:
          - name: api-v1
            weight: 90
          - name: api-v2
            weight: 10

    # Mirroring service
    shadow:
      mirroring:
        service: api
        mirrors:
          - name: shadow-api
            percent: 10
```

### Middlewares

```yaml
http:
  middlewares:
    # Rate limiting
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
        period: "1s"

    # Custom headers
    security-headers:
      headers:
        customResponseHeaders:
          X-Frame-Options: "DENY"
          X-Content-Type-Options: "nosniff"
          Server: ""  # Empty value removes header

    # CORS (via headers middleware)
    cors:
      headers:
        accessControlAllowMethods:
          - GET
          - POST
          - PUT
          - DELETE
        accessControlAllowOriginList:
          - "https://example.com"
        accessControlAllowCredentials: true
        accessControlMaxAge: 86400

    # Retry with exponential backoff
    retry-middleware:
      retry:
        attempts: 3
        initialInterval: "100ms"

    # IP allow list
    trusted-ips:
      ipAllowList:
        sourceRange:
          - "10.0.0.0/8"
          - "192.168.1.0/24"

    # IP deny list
    blocked-ips:
      ipDenyList:
        sourceRange:
          - "192.168.1.100"

    # Basic authentication
    auth:
      basicAuth:
        users:
          - "admin:$apr1$xyz..."  # htpasswd format

    # HTTPS redirect
    https-redirect:
      redirectScheme:
        scheme: https
        permanent: true

    # Strip path prefix
    strip-api:
      stripPrefix:
        prefixes:
          - "/api"

    # Add path prefix
    add-v1:
      addPrefix:
        prefix: "/v1"

    # Compression
    compress:
      compress:
        minResponseBodyBytes: 1024
        encodings:
          - zstd
          - br
          - gzip

    # Circuit breaker
    circuit-breaker:
      circuitBreaker:
        expression: "NetworkErrorRatio() > 0.5"
        checkPeriod: "10s"
        fallbackDuration: "30s"
        recoveryDuration: "30s"

    # Chain multiple middlewares
    secure-chain:
      chain:
        middlewares:
          - rate-limit
          - security-headers
          - auth
```

### TLS Configuration

```yaml
tls:
  certificates:
    - certFile: "/etc/certs/server.crt"
      keyFile: "/etc/certs/server.key"

  options:
    default:
      minVersion: "VersionTLS12"
      cipherSuites:
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
      sniStrict: true
```

### ACME (Let's Encrypt)

```yaml
certificatesResolvers:
  letsencrypt:
    acme:
      email: "admin@example.com"
      storage: "/data/acme.json"
      # Use staging for testing
      # caServer: "https://acme-staging-v02.api.letsencrypt.org/directory"
      httpChallenge:
        entryPoint: web

http:
  routers:
    secure-router:
      rule: "Host(`example.com`)"
      service: api
      tls:
        certResolver: letsencrypt
        domains:
          - main: "example.com"
            sans:
              - "www.example.com"
```

### Metrics

```yaml
metrics:
  prometheus:
    address: ":9090"
    addEntryPointsLabels: true
    addServicesLabels: true
```

Access metrics at `http://localhost:9090/metrics`.

## Architecture

```
┌─────────────────────────────────────┐
│         Entry Points                │
│   (HTTP/HTTPS Listeners)            │
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

### Docker

Build and run with Docker:

```bash
# Build image
docker build -t trafficcop .

# Run with config
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -p 9090:9090 \
  -v $(pwd)/config.yaml:/app/config/config.yaml \
  -v $(pwd)/data:/app/data \
  trafficcop

# With ACME (Let's Encrypt)
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/config.yaml:/app/config/config.yaml \
  -v acme-data:/app/data \
  trafficcop
```

## Project Structure

```
traffic_management/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library entry point
│   ├── config/          # Configuration parsing (Traefik-compatible)
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
│   ├── example.yaml     # Full example configuration
│   └── test.yaml        # Test configuration
└── benches/
    └── proxy_benchmark.rs
```

## License

MIT
