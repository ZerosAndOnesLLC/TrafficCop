# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

Only the latest release receives security updates. We recommend always running
the most recent version.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in TrafficCop, please report it
responsibly by emailing **security@zerosandones.us**. This allows us to assess
and address the issue before it is publicly disclosed.

### What to Include

- A description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Any potential impact or severity assessment
- Suggested fix, if you have one

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an assessment and expected timeline
- **Fix and disclosure** coordinated with you before any public announcement

We will credit reporters in the release notes unless you prefer to remain
anonymous.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We confirm and assess the issue
3. We develop and test a fix
4. We release the fix and publish a security advisory
5. We publicly disclose details after users have had time to update

We ask that reporters give us a reasonable window (typically 90 days) to address
the issue before any public disclosure.

## Security Best Practices

When deploying TrafficCop in production:

- **Keep up to date** — always run the latest release
- **Use TLS** — terminate TLS at the proxy or use TLS passthrough
- **Restrict the admin API** — bind it to localhost or use IP filtering
- **Use strong ACME configuration** — prefer production Let's Encrypt with
  valid email
- **Review middleware configuration** — ensure rate limiting, IP filtering, and
  authentication are configured appropriately
- **Limit permissions** — run TrafficCop with minimal OS privileges
