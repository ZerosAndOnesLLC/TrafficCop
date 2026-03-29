# Getting Started with TrafficCop

TrafficCop is a high-performance reverse proxy and load balancer written in Rust with **100% Traefik v3 compatible configuration**. If you've used Traefik before, your existing config files work as-is.

## Installation

### From GitHub Releases (recommended)

Download the latest release for your architecture:

```bash
# x86_64
curl -LO https://github.com/ZerosAndOnesLLC/TrafficCop/releases/latest/download/trafficcop-<VERSION>-x86_64-unknown-linux-gnu.tar.gz
tar xzf trafficcop-*-x86_64-unknown-linux-gnu.tar.gz
sudo mv trafficcop-*/trafficcop /usr/local/bin/

# aarch64 (ARM64)
curl -LO https://github.com/ZerosAndOnesLLC/TrafficCop/releases/latest/download/trafficcop-<VERSION>-aarch64-unknown-linux-gnu.tar.gz
tar xzf trafficcop-*-aarch64-unknown-linux-gnu.tar.gz
sudo mv trafficcop-*/trafficcop /usr/local/bin/
```

Replace `<VERSION>` with the release version (e.g., `1.0.4`).

### Build from Source

```bash
git clone https://github.com/ZerosAndOnesLLC/TrafficCop.git
cd TrafficCop
cargo build --release
# Binary is at ./target/release/trafficcop
```

### Docker

```bash
docker build -t trafficcop .
```

## Your First Config

Create a `config.yaml` that proxies traffic to a backend service:

```yaml
entryPoints:
  web:
    address: ":80"

http:
  routers:
    my-app:
      rule: "Host(`localhost`)"
      service: my-app
      entryPoints:
        - web

  services:
    my-app:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

This listens on port 80 and forwards requests with `Host: localhost` to a backend on port 8080.

## Running TrafficCop

```bash
# Start with your config
trafficcop -c config.yaml

# Validate config without starting
trafficcop -c config.yaml --validate

# Enable debug logging
trafficcop -c config.yaml --debug
```

Or with Docker:

```bash
docker run -d \
  -p 80:80 \
  -v $(pwd)/config.yaml:/app/config/config.yaml \
  trafficcop
```

## Common Scenarios

### Load Balancing Across Multiple Backends

Distribute traffic across several backend servers with health checks:

```yaml
entryPoints:
  web:
    address: ":80"

http:
  routers:
    api:
      rule: "PathPrefix(`/api`)"
      service: api-pool
      entryPoints:
        - web

  services:
    api-pool:
      loadBalancer:
        servers:
          - url: "http://10.0.0.1:8080"
          - url: "http://10.0.0.2:8080"
          - url: "http://10.0.0.3:8080"
        healthCheck:
          path: "/health"
          interval: "10s"
          timeout: "5s"
```

### HTTPS with Let's Encrypt

Automatic TLS certificates with HTTP-to-HTTPS redirect:

```yaml
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

certificatesResolvers:
  letsencrypt:
    acme:
      email: "you@example.com"
      storage: "/data/acme.json"
      httpChallenge:
        entryPoint: web

http:
  routers:
    my-app:
      rule: "Host(`myapp.example.com`)"
      service: my-app
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    my-app:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

### Multiple Domains with Path Routing

Route different hosts and paths to different services:

```yaml
entryPoints:
  web:
    address: ":80"

http:
  routers:
    api:
      rule: "Host(`api.example.com`) && PathPrefix(`/v1`)"
      service: api-service
      entryPoints:
        - web
      priority: 100

    frontend:
      rule: "Host(`app.example.com`)"
      service: frontend-service
      entryPoints:
        - web

  services:
    api-service:
      loadBalancer:
        servers:
          - url: "http://10.0.0.1:3000"

    frontend-service:
      loadBalancer:
        servers:
          - url: "http://10.0.0.2:8080"
```

### Adding Middleware (Rate Limiting, Auth, Headers)

Apply middleware to routers for request processing:

```yaml
entryPoints:
  web:
    address: ":80"

http:
  routers:
    api:
      rule: "Host(`api.example.com`)"
      service: api
      middlewares:
        - rate-limit
        - security-headers
        - auth
      entryPoints:
        - web

  services:
    api:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"

  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
        period: "1s"

    security-headers:
      headers:
        customResponseHeaders:
          X-Frame-Options: "DENY"
          X-Content-Type-Options: "nosniff"

    auth:
      basicAuth:
        users:
          - "admin:$apr1$xyz..."  # Generate with: htpasswd -n admin
```

### TCP Proxying (Database, etc.)

Proxy raw TCP connections like database traffic:

```yaml
entryPoints:
  postgres:
    address: ":5432"

tcp:
  routers:
    db:
      rule: "*"
      service: postgres-cluster
      entryPoints:
        - postgres

  services:
    postgres-cluster:
      loadBalancer:
        servers:
          - address: "10.0.0.1:5432"
          - address: "10.0.0.2:5432"
```

### gRPC Services

Proxy gRPC traffic with optional gRPC-Web support for browsers:

```yaml
entryPoints:
  grpc:
    address: ":50051"

http:
  routers:
    grpc-router:
      rule: "Host(`grpc.example.com`)"
      service: grpc-backend
      middlewares:
        - grpc-web
      entryPoints:
        - grpc

  services:
    grpc-backend:
      loadBalancer:
        servers:
          - url: "h2c://10.0.0.1:50051"
          - url: "h2c://10.0.0.2:50051"

  middlewares:
    grpc-web:
      grpcWeb:
        allowOrigins:
          - "https://app.example.com"
```

## Monitoring

### Prometheus Metrics

Add a metrics endpoint to your config:

```yaml
metrics:
  prometheus:
    address: ":9090"
    addEntryPointsLabels: true
    addServicesLabels: true
```

Scrape metrics at `http://localhost:9090/metrics`.

### Admin API

The admin API runs on port 9091 by default:

```bash
# View all routers
curl http://localhost:9091/api/http/routers

# View all services
curl http://localhost:9091/api/http/services

# Dashboard
open http://localhost:9091/dashboard/
```

## Hot Reload

TrafficCop watches your config file for changes and applies them without dropping connections. Just edit and save your `config.yaml` — changes take effect immediately.

## Migrating from Traefik

TrafficCop uses the same YAML configuration format as Traefik v3. To migrate:

1. Copy your existing Traefik `traefik.yaml` / dynamic config files
2. Point TrafficCop at them: `trafficcop -c traefik.yaml`
3. That's it — all routing rules, middlewares, and services work the same way

## Next Steps

- See `config/example.yaml` for a full configuration reference
- Check the [README](README.md) for the complete feature list and all 23 built-in middlewares
- Run `trafficcop -c config.yaml --validate` to check your config before deploying
