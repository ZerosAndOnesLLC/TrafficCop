# TrafficCop

A high-performance reverse proxy and load balancer written in Rust with **100% Traefik v3 compatible configuration**. Designed to handle 750k+ requests/second with predictable latency and zero garbage collection pauses.

## Features

### Core
- **Traefik v3 Compatible**: **Drop-in replacement** for Traefik using the exact same YAML configuration format
- **High Performance**: Built with Rust for maximum throughput and minimal latency
- **Zero GC Pauses**: No garbage collector means consistent, predictable response times
- **HTTP/1.1 & HTTP/2**: Automatic protocol detection with ALPN negotiation for TLS
- **WebSocket Proxying**: Full WebSocket upgrade and bidirectional streaming support
- **Hot Config Reload**: Configuration changes applied without restart or dropping connections
- **Graceful Shutdown**: Connection draining with configurable timeout

### Load Balancing
- **Algorithms**: Round-robin, weighted, least connections, random
- **Sticky Sessions**: Cookie-based session affinity with distributed support
- **Health Checks**: Active HTTP health checks with configurable thresholds
- **Passive Health Checks**: Track failures inline with sliding window
- **Circuit Breaker**: Automatic backend isolation on failure

### High Availability (v0.10.0)
- **Distributed State**: Redis/Valkey backend for cluster-wide state sharing
- **Distributed Rate Limiting**: Eventual consistency with local cache for performance
- **Distributed Sticky Sessions**: Session affinity works across cluster nodes
- **Shared Health State**: Coordinated health checking with leader election
- **Node Draining**: Graceful node removal via admin API
- **Remote Configuration**: Fetch config from HTTP/S3/Consul endpoints

### Protocol Support (v0.11.0+)
- **gRPC Proxying**: Native gRPC support with trailer handling and gRPC-specific error responses
- **gRPC-Web**: Browser-to-gRPC translation middleware with base64 encoding support
- **TCP Proxying**: Raw TCP load balancing with SNI-based routing
- **TLS Passthrough**: Forward encrypted traffic without termination
- **UDP Proxying** (v0.12.0): Datagram proxying with session tracking and IP-based routing

### Security & TLS
- **TLS Termination**: Native TLS support via rustls (no OpenSSL dependency)
- **Let's Encrypt ACME**: Automatic certificate provisioning and renewal
- **SNI-based Certificates**: Multiple certificates per listener with automatic selection
- **mTLS**: Mutual TLS with client certificates
- **JWT Validation**: Built-in JWT middleware (HS256, HS384, HS512)

### Middleware Pipeline (23 Built-in Middlewares)
- **Rate Limiting**: Token bucket with distributed support
- **Headers**: Custom request/response headers
- **Retry**: Exponential backoff with configurable attempts
- **Compression**: gzip, brotli, and zstd response compression
- **IP Filtering**: Allow/deny lists with CIDR support (includes deprecated `ipWhiteList`)
- **CORS**: Full CORS configuration via headers middleware
- **Authentication**: Basic auth, digest auth, forward auth, JWT validation
- **Path Manipulation**: Strip prefix, add prefix, replace path
- **Error Pages**: Custom error page routing (v0.13.0)
- **Failover**: Automatic service failover (v0.13.0)

### Observability
- **Access Logging**: Structured JSON access logs
- **Metrics**: Prometheus-compatible metrics endpoint
- **OpenTelemetry**: Distributed tracing with W3C, B3, Jaeger propagation
- **Admin API**: Runtime inspection dashboard and JSON endpoints

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
        mirrorBody: true  # Control whether to mirror request body (default: true)
        mirrors:
          - name: shadow-api
            percent: 10

    # Failover service (v0.13.0)
    failover-api:
      failover:
        service: primary-api      # Primary service
        fallback: backup-api      # Used when primary fails
        healthCheck:
          path: "/health"
          interval: "10s"
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

    # Custom error pages (v0.13.0)
    errors:
      errors:
        status:
          - "500-599"    # Server errors
          - "404"        # Not found
        service: error-service
        query: "/errors/{status}.html"  # {status} replaced with actual code

    # Deprecated alias (still supported for backwards compatibility)
    legacy-whitelist:
      ipWhiteList:  # Same as ipAllowList
        sourceRange:
          - "10.0.0.0/8"
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

### TCP Configuration (v0.11.0)

TCP proxying supports raw TCP connections with SNI-based routing for TLS passthrough:

```yaml
# Entry point for TCP (e.g., database proxy)
entryPoints:
  mysql:
    address: ":3306"
  postgres:
    address: ":5432"

# TCP routing configuration
tcp:
  routers:
    # MySQL proxy with TLS passthrough
    mysql-router:
      entryPoints:
        - mysql
      rule: "HostSNI(`mysql.example.com`)"
      service: mysql-cluster
      tls:
        passthrough: true

    # PostgreSQL proxy (no TLS)
    postgres-router:
      entryPoints:
        - postgres
      rule: "*"  # Catch-all
      service: postgres-cluster

    # Route by client IP
    internal-db:
      entryPoints:
        - postgres
      rule: "ClientIP(`10.0.0.0/8`)"
      service: internal-postgres

  services:
    mysql-cluster:
      loadBalancer:
        servers:
          - address: "10.0.0.1:3306"
          - address: "10.0.0.2:3306"
        healthCheck:
          interval: "10s"
          timeout: "5s"

    postgres-cluster:
      loadBalancer:
        servers:
          - address: "10.0.0.3:5432"
            weight: 2
          - address: "10.0.0.4:5432"
            weight: 1

  middlewares:
    # IP filtering for TCP
    trusted-sources:
      ipAllowList:
        sourceRange:
          - "10.0.0.0/8"
          - "192.168.0.0/16"

    # Connection limit
    conn-limit:
      inFlightConn:
        amount: 100
```

#### TCP Routing Rules

| Rule | Description | Example |
|------|-------------|---------|
| `*` | Catch-all | `rule: "*"` |
| `HostSNI` | TLS SNI hostname | `HostSNI(\`db.example.com\`)` |
| `ClientIP` | Client IP/CIDR | `ClientIP(\`10.0.0.0/8\`)` |

### UDP Configuration (v0.12.0)

UDP proxying supports datagram-based protocols like DNS, QUIC, or custom UDP services:

```yaml
# Entry points for UDP
entryPoints:
  dns:
    address: ":53"
  syslog:
    address: ":514"

# UDP routing configuration
udp:
  routers:
    # DNS proxy (catch-all)
    dns-router:
      entryPoints:
        - dns
      rule: "*"
      service: dns-cluster

    # Route by client IP for internal services
    internal-syslog:
      entryPoints:
        - syslog
      rule: "ClientIP(`10.0.0.0/8`)"
      service: internal-syslog
      priority: 100

    # Catch-all syslog
    syslog-router:
      entryPoints:
        - syslog
      rule: "*"
      service: syslog-cluster

  services:
    dns-cluster:
      loadBalancer:
        servers:
          - address: "10.0.0.1:53"
          - address: "10.0.0.2:53"
        healthCheck:
          interval: "30s"
          timeout: "5s"
          payload: "\x00\x00\x01\x00\x00\x01"  # DNS query probe (hex)

    syslog-cluster:
      loadBalancer:
        servers:
          - address: "10.0.0.3:514"
            weight: 2
          - address: "10.0.0.4:514"
            weight: 1

    internal-syslog:
      loadBalancer:
        servers:
          - address: "192.168.1.10:514"

  middlewares:
    # IP filtering for UDP
    trusted-sources:
      ipAllowList:
        sourceRange:
          - "10.0.0.0/8"

    # Rate limiting per source IP
    rate-limit:
      rateLimit:
        average: 1000  # packets per period
        burst: 100
        period: "1s"
```

#### UDP Features

- **Session Tracking**: Client source IP/port is tracked to route responses back correctly
- **Consistent Hashing**: Clients are routed to the same backend based on source IP for session affinity
- **Session Timeout**: Configurable timeout (default 60s) for inactive sessions
- **Load Balancing**: Round-robin with health-aware routing

#### UDP Routing Rules

| Rule | Description | Example |
|------|-------------|---------|
| `*` | Catch-all | `rule: "*"` |
| `ClientIP` | Client IP/CIDR | `ClientIP(\`10.0.0.0/8\`)` |

Note: UDP does not support SNI-based routing since there is no TLS handshake for connection-less protocols.

### gRPC Configuration (v0.11.0)

gRPC traffic works through HTTP routers with automatic detection:

```yaml
http:
  routers:
    grpc-router:
      entryPoints:
        - websecure
      rule: "Host(`grpc.example.com`)"
      service: grpc-service
      middlewares:
        - grpc-web  # For browser clients
      tls:
        certResolver: letsencrypt

  services:
    grpc-service:
      loadBalancer:
        servers:
          - url: "h2c://10.0.0.1:50051"  # gRPC over HTTP/2 cleartext
          - url: "h2c://10.0.0.2:50051"

  middlewares:
    # gRPC-Web for browser clients
    grpc-web:
      grpcWeb:
        allowOrigins:
          - "https://app.example.com"
          - "https://*.example.com"
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

### High Availability (Cluster Mode)

Enable distributed state sharing across multiple TrafficCop instances:

```yaml
# Cluster configuration
cluster:
  enabled: true
  # Unique node identifier (auto-generated if not specified)
  nodeId: "node-1"
  # Address other nodes can reach this node at
  advertiseAddress: "10.0.0.1:8080"
  # Heartbeat and timeout settings
  heartbeatInterval: "5s"
  nodeTimeout: "30s"
  drainTimeout: "30s"

  # Distributed state backend
  store:
    redis:
      # Single node or cluster endpoints
      endpoints:
        - "redis://redis-1:6379"
        - "redis://redis-2:6379"
      password: "${REDIS_PASSWORD}"
      db: 0
      rootKey: "trafficcop"
      timeout: "5s"
      # TLS configuration (use rediss:// for TLS)
      # tls:
      #   insecureSkipVerify: false
      #   ca: "/etc/certs/redis-ca.crt"

  # Remote configuration providers
  configProviders:
    - http:
        endpoint: "https://config-server.example.com/trafficcop/config.yaml"
        pollInterval: "30s"
        timeout: "10s"
        headers:
          Authorization: "Bearer ${CONFIG_TOKEN}"
        tls:
          insecureSkipVerify: false
```

#### Cluster with Redis Sentinel

```yaml
cluster:
  enabled: true
  store:
    redis:
      endpoints:
        - "redis://sentinel-1:26379"
        - "redis://sentinel-2:26379"
        - "redis://sentinel-3:26379"
      sentinel:
        masterName: "mymaster"
        password: "${SENTINEL_PASSWORD}"
```

#### Admin API Cluster Endpoints

When cluster mode is enabled, additional admin endpoints are available:

```bash
# Get cluster status
curl http://localhost:9091/api/cluster

# List all active nodes
curl http://localhost:9091/api/cluster/nodes

# Drain a node (graceful removal)
curl -X POST http://localhost:9091/api/cluster/drain?node_id=node-2

# Undrain a node (restore to active)
curl -X POST http://localhost:9091/api/cluster/undrain
```

#### Distributed Features

When cluster mode is enabled:

- **Rate Limiting**: Uses sliding window algorithm with eventual consistency. Local cache handles most requests (sub-microsecond), with background sync to Redis every ~100ms. Expect ~1-5% variance across nodes.

- **Sticky Sessions**: Session affinity works across all cluster nodes. Sessions are stored in Redis with configurable TTL.

- **Health Checks**: Leader election ensures only one node performs active health checks. Health status is shared via Redis pub/sub.

- **Node Draining**: Gracefully remove nodes from the cluster. New requests are routed to other nodes while existing connections complete.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                       Entry Points                              │
│            (HTTP/HTTPS/WebSocket/TCP/gRPC/UDP)                  │
└──────────────────────────┬─────────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
┌──────▼──────┐    ┌───────▼───────┐   ┌───────▼───────┐
│ HTTP Router │    │  TCP Router   │   │  UDP Router   │
│(Host/Path)  │    │ (SNI/IP)      │   │ (IP only)     │
└──────┬──────┘    └───────┬───────┘   └───────┬───────┘
       │                   │                   │
┌──────▼──────────┐ ┌──────▼──────────┐ ┌──────▼──────────┐
│   Middleware    │ │ TCP Middleware  │ │ UDP Middleware  │
│(Auth,Rate,CORS) │ │(IP Filter,Conn) │ │(IP Filter,Rate) │
└──────┬──────────┘ └──────┬──────────┘ └──────┬──────────┘
       │                   │                   │
┌──────▼──────────┐ ┌──────▼──────────┐ ┌──────▼──────────┐
│ Load Balancer   │ │TCP Load Balancer│ │UDP Load Balancer│
│(RR,Weighted,LC) │ │  (Round-Robin)  │ │  (Hash-based)   │
└──────┬──────────┘ └──────┬──────────┘ └──────┬──────────┘
       │                   │                   │
┌──────▼──────────┐ ┌──────▼──────────┐ ┌──────▼──────────┐
│Connection Pool  │ │TCP Proxy (Bidir)│ │UDP Proxy        │
│(Keep-alive,H2)  │ │(TLS Passthrough)│ │(Session Track)  │
└──────┬──────────┘ └──────┬──────────┘ └──────┬──────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────────┐
│                     Backend Services                            │
│            (HTTP/gRPC/TCP/UDP/Database/Custom)                  │
└────────────────────────────────────────────────────────────────┘
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
│   ├── server/          # HTTP/TCP/UDP listeners
│   │   ├── listener.rs  # HTTP/TLS listener
│   │   └── udp_listener.rs  # UDP listener (v0.12.0)
│   ├── router/          # Rule matching engine
│   ├── proxy/           # Request proxying (HTTP/gRPC)
│   │   ├── handler.rs   # HTTP proxy handler
│   │   ├── grpc.rs      # gRPC support and error handling
│   │   └── websocket.rs # WebSocket upgrade handling
│   ├── tcp/             # TCP proxying (v0.11.0)
│   │   ├── proxy.rs     # TCP bidirectional proxy
│   │   ├── router.rs    # SNI/IP-based routing
│   │   └── service.rs   # TCP service management
│   ├── udp/             # UDP proxying (v0.12.0)
│   │   ├── proxy.rs     # UDP datagram proxy with session tracking
│   │   ├── router.rs    # IP-based routing
│   │   └── service.rs   # UDP service management
│   ├── balancer/        # Load balancing
│   ├── middleware/      # Middleware pipeline
│   │   └── builtin/     # Built-in middlewares
│   │       └── grpc_web.rs  # gRPC-Web translation
│   ├── health/          # Health checking (local + distributed)
│   ├── pool/            # Connection pooling
│   ├── tls/             # TLS/ACME
│   ├── metrics/         # Prometheus metrics
│   ├── cluster/         # Cluster management (HA)
│   │   ├── manager.rs   # Node registration, heartbeats, leader election
│   │   └── provider.rs  # Remote config providers (HTTP, S3, Consul)
│   └── store/           # Distributed state backends
│       ├── local.rs     # In-memory store (single node)
│       └── valkey.rs    # Redis/Valkey store (cluster mode)
├── config/
│   ├── example.yaml     # Full example configuration
│   └── test.yaml        # Test configuration
└── benches/
    └── proxy_benchmark.rs
```

## License

MIT
