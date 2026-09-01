# Security Policy

## Supported Versions

Only the latest released version of TrafficCop receives security fixes.

| Version | Supported |
|---------|-----------|
| 1.4.x   | ✅        |
| < 1.4   | ❌        |

## Reporting a Vulnerability

Please report security vulnerabilities privately — do **not** open a public
GitHub issue.

- **Email:** support@zerosandones.us (subject line starting with `[SECURITY]`)
- **GitHub:** use [private vulnerability reporting](https://github.com/ZerosAndOnesLLC/TrafficCop/security/advisories/new)

Include, where possible:

- A description of the vulnerability and its impact
- Steps to reproduce (a minimal config is ideal)
- The TrafficCop version and platform affected

## What to Expect

- **Acknowledgement** within 72 hours
- **Assessment and severity triage** within 7 days
- **Fix and coordinated disclosure**: we aim to release a patched version
  before public disclosure, and will credit reporters in the release notes
  unless they prefer otherwise

## Scope

In scope: anything exploitable in the `trafficcop` binary or library —
authentication bypasses in middleware (basicAuth, digestAuth, jwt,
forwardAuth), request smuggling or header injection through the proxy,
TLS/ACME handling flaws, denial-of-service vectors, and unsafe defaults.

Out of scope: vulnerabilities in backends TrafficCop proxies to,
misconfiguration of deployments, and issues requiring access to the host.

## Hardening Guidance

- Set `api.token` — without it, mutating admin endpoints are disabled, but
  read endpoints remain open on the admin port; bind the admin port to a
  trusted network either way.
- Configure `forwardedHeaders.trustedIPs` on entrypoints behind a load
  balancer; by default all forwarded headers from untrusted peers are
  stripped.
- Set `transport.maxRequestBodyBytes` on internet-facing entrypoints.
