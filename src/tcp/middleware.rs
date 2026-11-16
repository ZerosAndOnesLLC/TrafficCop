//! TCP middlewares (Traefik `tcp.middlewares`): ipAllowList, ipDenyList
//! (TrafficCop extension) and inFlightConn, enforced at connection accept.

use crate::config::TcpMiddlewareConfig;
use crate::middleware::source::parse_net;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

enum Kind {
    Allow(Vec<IpNetwork>),
    Deny(Vec<IpNetwork>),
    InFlight {
        amount: i64,
        counts: Arc<DashMap<IpAddr, i64>>,
    },
}

/// Built TCP middlewares by name.
pub struct TcpMiddlewares {
    by_name: HashMap<String, Kind>,
}

/// Holds inFlightConn slots for the connection's lifetime.
pub struct ConnGuard {
    counts: Arc<DashMap<IpAddr, i64>>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.counts.get_mut(&self.ip) {
            *c -= 1;
        }
        self.counts.remove_if(&self.ip, |_, v| *v <= 0);
    }
}

fn nets(ranges: &[String], what: &str) -> Result<Vec<IpNetwork>, String> {
    if ranges.is_empty() {
        return Err(format!("{what}: sourceRange must not be empty"));
    }
    ranges
        .iter()
        .map(|r| parse_net(r).map_err(|e| format!("{what}: {e}")))
        .collect()
}

impl TcpMiddlewares {
    /// Build from config; invalid definitions are errors.
    pub fn from_config(configs: &HashMap<String, TcpMiddlewareConfig>) -> Result<Self, String> {
        let mut by_name = HashMap::new();
        for (name, c) in configs {
            let set = [
                c.ip_allow_list.is_some(),
                c.ip_deny_list.is_some(),
                c.in_flight_conn.is_some(),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if set != 1 {
                return Err(format!(
                    "TCP middleware '{name}': exactly one middleware type must be set"
                ));
            }
            let kind = if let Some(a) = &c.ip_allow_list {
                Kind::Allow(nets(
                    &a.source_range,
                    &format!("TCP middleware '{name}' ipAllowList"),
                )?)
            } else if let Some(d) = &c.ip_deny_list {
                Kind::Deny(nets(
                    &d.source_range,
                    &format!("TCP middleware '{name}' ipDenyList"),
                )?)
            } else if let Some(f) = &c.in_flight_conn {
                if f.amount <= 0 {
                    return Err(format!(
                        "TCP middleware '{name}' inFlightConn: amount must be > 0"
                    ));
                }
                Kind::InFlight {
                    amount: f.amount,
                    counts: Arc::new(DashMap::new()),
                }
            } else {
                unreachable!("exactly one type checked above")
            };
            by_name.insert(name.clone(), kind);
        }
        Ok(Self { by_name })
    }

    /// Apply the named middlewares in order. `Err` carries the reason the
    /// connection must be closed; `Ok` guards must live as long as the connection.
    pub fn admit(&self, names: &[String], ip: IpAddr) -> Result<Vec<ConnGuard>, String> {
        let mut guards = Vec::new();
        for name in names {
            let kind = self
                .by_name
                .get(name)
                .ok_or_else(|| format!("TCP middleware '{name}' not found"))?;
            match kind {
                Kind::Allow(n) if !n.iter().any(|n| n.contains(ip)) => {
                    return Err(format!("{ip} not in ipAllowList '{name}'"));
                }
                Kind::Deny(n) if n.iter().any(|n| n.contains(ip)) => {
                    return Err(format!("{ip} in ipDenyList '{name}'"));
                }
                Kind::InFlight { amount, counts } => {
                    let mut c = counts.entry(ip).or_insert(0);
                    if *c >= *amount {
                        return Err(format!("{ip} over inFlightConn '{name}' limit"));
                    }
                    *c += 1;
                    drop(c);
                    guards.push(ConnGuard {
                        counts: Arc::clone(counts),
                        ip,
                    });
                }
                _ => {}
            }
        }
        Ok(guards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mws(yaml: &str) -> Result<TcpMiddlewares, String> {
        TcpMiddlewares::from_config(&serde_norway::from_str(yaml).unwrap())
    }

    #[test]
    fn allow_deny_inflight() {
        let m = mws(
            "office: {ipAllowList: {sourceRange: [\"203.0.113.0/24\"]}}\nblock: {ipDenyList: {sourceRange: [\"203.0.113.9\"]}}\none: {inFlightConn: {amount: 1}}\n",
        )
        .unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(m.admit(&["office".into()], ip("8.8.8.8")).is_err());
        assert!(m.admit(&["office".into()], ip("203.0.113.5")).is_ok());
        assert!(
            m.admit(&["office".into(), "block".into()], ip("203.0.113.9"))
                .is_err()
        );

        let g = m.admit(&["one".into()], ip("1.1.1.1")).unwrap();
        assert!(m.admit(&["one".into()], ip("1.1.1.1")).is_err());
        assert!(m.admit(&["one".into()], ip("1.1.1.2")).is_ok());
        drop(g);
        assert!(m.admit(&["one".into()], ip("1.1.1.1")).is_ok());
        assert!(m.admit(&["missing".into()], ip("1.1.1.1")).is_err());
    }

    #[test]
    fn invalid_definitions_rejected() {
        assert!(mws("x: {ipAllowList: {sourceRange: [\"10.0.0.0/33\"]}}\n").is_err());
        assert!(mws("x: {ipAllowList: {sourceRange: []}}\n").is_err());
        assert!(mws("x: {inFlightConn: {amount: 0}}\n").is_err());
        assert!(mws("x: {}\n").is_err());
    }
}
