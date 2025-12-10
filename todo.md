# TrafficCop - Remaining Features

High-performance reverse proxy and load balancer. Current version: **v0.13.0**

---

## 🎯 Project Goal: 100% Traefik v3 Drop-in Replacement

**TrafficCop aims to be a complete drop-in replacement for Traefik v3 file-based configuration.** Users should be able to take their existing Traefik YAML configs and use them with TrafficCop without modification.

- ✅ We can have **more features** than Traefik (extensions are fine)
- ❌ We must not **break compatibility** with valid Traefik configs
- ❌ We must not **rename fields** or change expected behavior

**Current Compatibility: ~98%** - Nearly all Traefik v3 file config options are now supported!

---

## ✅ Traefik v3 Compatibility - COMPLETED in v0.13.0

All high and medium priority Traefik v3 configuration fields have been implemented:

### High Priority - Config Compatibility (DONE)

- [x] **`errors` middleware** - Custom error pages with service fallback
  - `errors.status` - Status code ranges (e.g., "500-599")
  - `errors.service` - Service to handle errors
  - `errors.query` - URL path for error page (supports `{status}` placeholder)

- [x] **Failover Service** - Automatic failover to backup service
  - `failover.service` - Primary service
  - `failover.fallback` - Fallback service when primary fails
  - `failover.healthCheck` - Health check configuration

- [x] **`ruleSyntax`** - Alternative rule syntax support on routers
  - Allows specifying rule syntax version for forward compatibility

### Medium Priority - Config Fields (DONE)

- [x] **Health Check enhancements**
  - `healthCheck.mode` - Support `grpc` mode for gRPC health protocol
  - `healthCheck.port` - Override port for health checks
  - `healthCheck.followRedirects` - Follow HTTP redirects in health checks

- [x] **Mirroring Service enhancements**
  - `mirroring.mirrorBody` - Control whether to mirror request body (default: true)

- [x] **TLS Options**
  - `preferServerCipherSuites` - Prefer server cipher order

- [x] **Entry Point Transport**
  - `transport.keepAliveMaxRequests` - Max requests per keep-alive connection
  - `transport.keepAliveMaxTime` - Max lifetime of keep-alive connection

- [x] **Forwarded Headers**
  - `forwardedHeaders.connection` - Connection header handling list

- [x] **Entry Point TLS**
  - `http.tls.options` - TLS options reference at entry point level (already supported)

### Low Priority - API/Metrics (DONE)

- [x] **API Configuration**
  - `api.debug` - Enable debug mode
  - `api.basePath` - Custom base path for API
  - `api.disabledashboardad` - Hide dashboard advertisement

- [x] **Prometheus Metrics**
  - `metrics.prometheus.addRoutersLabels` - Add router labels to metrics
  - `metrics.prometheus.entryPoint` - Serve metrics on specific entry point
  - `metrics.prometheus.buckets` - Custom histogram buckets

### Legacy/Deprecated (DONE)

- [x] **`ipWhiteList` middleware** - Deprecated alias for `ipAllowList`
  - Accepts `ipWhiteList` and treats it as `ipAllowList` for backwards compatibility

---

## 🟡 Traefik Features We Won't Implement (Out of Scope)

These are Traefik-specific features that don't apply to file-based configuration or are proprietary:

- **`plugin` middleware** - Traefik's Go plugin system (proprietary)
- **`spiffe`** - SPIFFE/SPIRE identity (enterprise feature, can add later if needed)
- **Docker Provider** - Auto-discovery from Docker labels
- **Kubernetes Providers** - CRD, Ingress, Gateway API
- **Consul Catalog Provider** - Service discovery from Consul services
- **Other Dynamic Providers** - ECS, Marathon, Rancher, Nomad, etc.

> Note: Dynamic providers are out of scope for initial drop-in compatibility. Users relying on these must migrate to file-based config. We may add select providers later.

---

## ✅ Traefik Config Compatibility (COMPLETED)

TrafficCop now uses **Traefik v3 compatible configuration format**. Existing Traefik configs should work with minimal modifications.

### Completed Items

- [x] **Restructured config to match Traefik format**
  - Dynamic config uses `http.routers`, `http.services`, `http.middlewares`
  - Static config uses `entryPoints`, `certificatesResolvers`, `providers`
  - All field names use camelCase

- [x] **Go-style duration string parsing**
  - Supports: "300ms", "1.5s", "2m", "1h30m", "24h"
  - Used in all timeout and interval configurations

- [x] **EntryPoints (static config)**
  - Address, forwardedHeaders, http redirections, transport timeouts

- [x] **Middlewares (camelCase format)**
  - rateLimit, ipAllowList, ipDenyList
  - headers (with CORS fields)
  - basicAuth, digestAuth, forwardAuth
  - compress, retry, circuitBreaker
  - redirectScheme, redirectRegex
  - stripPrefix, stripPrefixRegex, addPrefix
  - replacePath, replacePathRegex
  - chain, buffering, inFlightReq

- [x] **Services**
  - loadBalancer with servers, sticky, healthCheck, serversTransport
  - weighted service (config parsing, routing TODO)
  - mirroring service (config parsing, mirroring TODO)

- [x] **Routers**
  - entryPoints, rule, service, middlewares, priority
  - tls with certResolver, domains, options

- [x] **TLS Configuration**
  - certificates, options, stores
  - certificatesResolvers with ACME support

- [x] **Updated example configs and documentation**

---

## ✅ Completed Features

### Core
- [x] HTTP/1.1 and HTTP/2 (ALPN)
- [x] TLS termination (rustls)
- [x] WebSocket proxying
- [x] Hot config reload
- [x] Graceful shutdown with connection draining
- [x] Request/connect timeouts
- [x] Traefik v3 config format

### TLS & Security
- [x] Let's Encrypt ACME - Automatic certificate provisioning
- [x] SNI-based cert selection - Multiple certs per listener
- [x] Automatic certificate renewal (30 days before expiry)
- [x] HTTP-01 challenge handler

### Load Balancing
- [x] Round-robin
- [x] Smooth weighted round-robin
- [x] Least connections
- [x] Random (weighted)
- [x] Connection pooling

### Middleware
- [x] Rate limiting (token bucket)
- [x] Header manipulation
- [x] Retry with exponential backoff
- [x] Compression (gzip, brotli, zstd)
- [x] IP allowlist/denylist (CIDR)
- [x] CORS (via headers middleware)
- [x] HTTPS redirect
- [x] Basic authentication

### Health & Resilience
- [x] HTTP health checks
- [x] Circuit breaker
- [x] Automatic backend removal/recovery

### Observability
- [x] Prometheus metrics
- [x] Structured access logging (JSON)

### Operations
- [x] Production-ready Dockerfile
- [x] Benchmarking suite (criterion)

---

## ✅ Service Routing (COMPLETED v0.7.0)

- [x] Weighted service routing (traffic splitting between services)
- [x] Mirroring service (shadow traffic to secondary service)

## ✅ Path Middlewares (COMPLETED v0.7.0)

- [x] forwardAuth - External authentication delegation
- [x] stripPrefix - Remove path prefix
- [x] stripPrefixRegex - Remove prefix with regex
- [x] addPrefix - Add path prefix
- [x] replacePath - Replace entire path
- [x] replacePathRegex - Regex path replacement
- [x] buffering - Request/response buffering config
- [x] chain - Compose multiple middlewares

---

## ✅ Authentication & Security (COMPLETED v0.8.0)

- [x] Digest authentication (RFC 7616 with MD5)
- [x] JWT validation middleware (HS256, HS384, HS512)
- [x] Sticky sessions (cookie-based session affinity)
- [x] mTLS (mutual TLS with client certificates)

---

## ✅ Medium Priority (COMPLETED v0.9.0)

### Features
- [x] HTTP/2 upstream connections (connection pooling with multiplexing)
- [x] Query parameter routing (with URL decoding support)

### Observability
- [x] OpenTelemetry tracing integration (W3C, B3, Jaeger propagation)
- [x] Admin API for runtime inspection (dashboard, JSON endpoints)
- [x] Passive health checks (track failures inline with sliding window)

---

## ✅ High Priority (COMPLETED v0.10.0)
 - [x] HA (HA proxying with load balancing) - Eventual consistency model with local caching
 - [x] Redis / Valkey for HA back-end - Full Store trait with TLS support
 - [x] Point to configuration URLs for configuration - HTTP provider with polling and ETag caching
 - [x] Node Draining - Graceful drain via admin API with cluster coordination

## ✅ Protocols (COMPLETED v0.11.0)
- [x] gRPC proxying - Native gRPC support with proper trailer handling and gRPC-specific error responses
- [x] gRPC-Web middleware - Browser-to-gRPC translation with base64 support
- [x] TCP proxying (non-HTTP) - SNI-based routing, raw TCP load balancing, TLS passthrough

## ✅ UDP Proxying (COMPLETED v0.12.0)
- [x] UDP datagram proxying with session tracking
- [x] IP-based routing (ClientIP rule)
- [x] Consistent hashing for session affinity (based on source IP)
- [x] Session timeout with automatic cleanup
- [x] Round-robin load balancing with health awareness
- [x] UDP middleware support (IP filtering, rate limiting)
- [x] Graceful shutdown with session drain

## 🟢 Nice to Have

### Advanced Traffic
- [ ] A/B testing support
- [ ] Canary deployment helpers

### Dynamic Configuration
- [ ] HTTP API provider
- [ ] Docker provider (label-based)
- [ ] Kubernetes Ingress/CRD provider
- [ ] Consul/etcd providers

### Performance
- [ ] Worker process model
- [ ] NUMA-aware scheduling
- [ ] io_uring support (Linux)
- [ ] Memory limits and backpressure

---

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

## Performance Targets

| Metric | Target |
|--------|--------|
| Throughput | 750k+ req/s |
| p50 latency | < 1ms |
| p99 latency | < 5ms |
| p99.9 latency | < 10ms |
| Memory | < 100MB base |
