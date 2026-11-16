//! Provider-qualified reference normalization (`name@provider`).
//!
//! Traefik lets any cross-reference carry a provider suffix (`auth@file`,
//! `api@internal`, `svc@docker`). TrafficCop only has the file provider, so
//! `@file` references are rewritten to the bare name once at load time and any
//! other provider is a configuration error. Every consumer (validation, router,
//! middleware registry, TCP/UDP routers) then sees one canonical name.

use super::Config;
use anyhow::{Result, bail};

/// Providers whose objects live in this config.
const LOCAL_PROVIDERS: &[&str] = &["file"];

/// Normalize one reference in place.
fn normalize(name: &mut String, what: &str, owner: &str) -> Result<()> {
    if let Some((base, provider)) = name.split_once('@') {
        if base.is_empty() || provider.is_empty() || provider.contains('@') {
            bail!("{owner}: invalid {what} reference '{name}'");
        }
        if !LOCAL_PROVIDERS.contains(&provider) {
            bail!(
                "{owner}: {what} reference '{name}' uses provider '{provider}', which is not supported (only @file)"
            );
        }
        *name = base.to_string();
    }
    Ok(())
}

fn normalize_all(names: &mut [String], what: &str, owner: &str) -> Result<()> {
    names.iter_mut().try_for_each(|n| normalize(n, what, owner))
}

fn normalize_opt(name: &mut Option<String>, what: &str, owner: &str) -> Result<()> {
    match name {
        Some(n) => normalize(n, what, owner),
        None => Ok(()),
    }
}

impl Config {
    /// Rewrite `x@file` references to `x`; reject references to other providers.
    pub fn normalize_references(&mut self) -> Result<()> {
        for (ep_name, ep) in &mut self.entry_points {
            if let Some(http) = &mut ep.http {
                let owner = format!("entryPoint '{ep_name}'");
                normalize_all(&mut http.middlewares, "middleware", &owner)?;
                if let Some(tls) = &mut http.tls {
                    normalize_opt(&mut tls.options, "TLS options", &owner)?;
                }
            }
        }

        if let Some(http) = &mut self.http {
            for (name, r) in &mut http.routers {
                let owner = format!("router '{name}'");
                normalize(&mut r.service, "service", &owner)?;
                normalize_all(&mut r.middlewares, "middleware", &owner)?;
                if let Some(tls) = &mut r.tls {
                    normalize_opt(&mut tls.options, "TLS options", &owner)?;
                }
            }
            for (name, s) in &mut http.services {
                let owner = format!("service '{name}'");
                if let Some(lb) = &mut s.load_balancer {
                    normalize_opt(&mut lb.servers_transport, "serversTransport", &owner)?;
                }
                if let Some(w) = &mut s.weighted {
                    for r in &mut w.services {
                        normalize(&mut r.name, "service", &owner)?;
                    }
                }
                if let Some(m) = &mut s.mirroring {
                    normalize(&mut m.service, "service", &owner)?;
                    for r in &mut m.mirrors {
                        normalize(&mut r.name, "service", &owner)?;
                    }
                }
                if let Some(f) = &mut s.failover {
                    normalize(&mut f.service, "service", &owner)?;
                    normalize(&mut f.fallback, "service", &owner)?;
                }
            }
            for (name, m) in &mut http.middlewares {
                if let Some(chain) = &mut m.chain {
                    normalize_all(
                        &mut chain.middlewares,
                        "middleware",
                        &format!("chain '{name}'"),
                    )?;
                }
                if let Some(errors) = &mut m.errors {
                    normalize(
                        &mut errors.service,
                        "service",
                        &format!("middleware '{name}'"),
                    )?;
                }
            }
        }

        if let Some(tcp) = &mut self.tcp {
            for (name, r) in &mut tcp.routers {
                let owner = format!("TCP router '{name}'");
                normalize(&mut r.service, "service", &owner)?;
                normalize_all(&mut r.middlewares, "middleware", &owner)?;
                if let Some(tls) = &mut r.tls {
                    normalize_opt(&mut tls.options, "TLS options", &owner)?;
                }
            }
            for (name, s) in &mut tcp.services {
                let owner = format!("TCP service '{name}'");
                if let Some(lb) = &mut s.load_balancer {
                    normalize_opt(&mut lb.servers_transport, "serversTransport", &owner)?;
                }
                if let Some(w) = &mut s.weighted {
                    for r in &mut w.services {
                        normalize(&mut r.name, "service", &owner)?;
                    }
                }
            }
        }

        if let Some(udp) = &mut self.udp {
            for (name, r) in &mut udp.routers {
                let owner = format!("UDP router '{name}'");
                normalize(&mut r.service, "service", &owner)?;
                normalize_all(&mut r.middlewares, "middleware", &owner)?;
            }
            for (name, s) in &mut udp.services {
                if let Some(w) = &mut s.weighted {
                    for r in &mut w.services {
                        normalize(&mut r.name, "service", &format!("UDP service '{name}'"))?;
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Config> {
        Config::from_yaml_str(yaml)
    }

    const BASE: &str = r#"
entryPoints:
  web: {address: "127.0.0.1:8080"}
http:
  routers:
    app:
      rule: "PathPrefix(`/`)"
      service: "app@file"
      middlewares: ["auth@file", "secure"]
  middlewares:
    auth:
      basicAuth: {users: ["u:$2y$05$c3RYpRMhSVOWHM6Ld2Lp8uFV3xJ6eOTW2QHC.JxHgbm2cU0vXkLz."]}
    hdr:
      headers: {customRequestHeaders: {X-A: "1"}}
    secure:
      chain: {middlewares: ["hdr@file"]}
  services:
    app:
      loadBalancer: {servers: [{url: "http://127.0.0.1:9000"}]}
"#;

    #[test]
    fn file_suffix_is_stripped_everywhere() {
        let c = parse(BASE).unwrap();
        let r = &c.routers()["app"];
        assert_eq!(r.service, "app");
        assert_eq!(r.middlewares, vec!["auth", "secure"]);
        assert_eq!(
            c.middlewares()["secure"]
                .chain
                .as_ref()
                .unwrap()
                .middlewares,
            vec!["hdr"]
        );
        let reg = crate::middleware::MiddlewareRegistry::from_config(c.middlewares()).unwrap();
        let resolved = reg.resolve(&r.middlewares).unwrap();
        let names: Vec<_> = resolved.iter().map(|m| m.name()).collect();
        assert_eq!(names, vec!["auth", "hdr"]);
    }

    #[test]
    fn other_providers_are_rejected() {
        for bad in ["auth@docker", "auth@internal", "@file", "auth@", "a@file@x"] {
            let yaml = BASE.replace("auth@file", bad);
            assert!(parse(&yaml).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn unknown_base_name_still_fails_validation() {
        let yaml = BASE.replace("auth@file", "nope@file");
        assert!(parse(&yaml).is_err());
    }
}
