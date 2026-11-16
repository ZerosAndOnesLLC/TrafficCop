//! UDP middlewares (TrafficCop extension): ipAllowList, ipDenyList and a
//! per-source rateLimit, checked on every datagram.

use crate::config::UdpMiddlewareConfig;
use crate::middleware::source::parse_net;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Bound on tracked sources; UDP source addresses are spoofable, so idle
/// buckets are evicted past this size.
const MAX_BUCKETS: usize = 100_000;

struct Bucket {
    tokens: f64,
    last: Instant,
}

enum Kind {
    Allow(Vec<IpNetwork>),
    Deny(Vec<IpNetwork>),
    RateLimit {
        /// tokens per second
        rate: f64,
        capacity: f64,
        buckets: DashMap<IpAddr, Bucket>,
    },
}

/// Built UDP middlewares by name.
pub struct UdpMiddlewares {
    by_name: HashMap<String, Kind>,
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

impl UdpMiddlewares {
    /// Build from config; invalid definitions are errors.
    pub fn from_config(configs: &HashMap<String, UdpMiddlewareConfig>) -> Result<Self, String> {
        let mut by_name = HashMap::new();
        for (name, c) in configs {
            let set = [
                c.ip_allow_list.is_some(),
                c.ip_deny_list.is_some(),
                c.rate_limit.is_some(),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if set != 1 {
                return Err(format!(
                    "UDP middleware '{name}': exactly one middleware type must be set"
                ));
            }
            let kind = if let Some(a) = &c.ip_allow_list {
                Kind::Allow(nets(
                    &a.source_range,
                    &format!("UDP middleware '{name}' ipAllowList"),
                )?)
            } else if let Some(d) = &c.ip_deny_list {
                Kind::Deny(nets(
                    &d.source_range,
                    &format!("UDP middleware '{name}' ipDenyList"),
                )?)
            } else if let Some(r) = &c.rate_limit {
                let period = r.period.as_std().as_secs_f64();
                if r.average == 0 || period <= 0.0 {
                    return Err(format!(
                        "UDP middleware '{name}' rateLimit: average and period must be > 0"
                    ));
                }
                Kind::RateLimit {
                    rate: r.average as f64 / period,
                    capacity: r.burst.max(1) as f64,
                    buckets: DashMap::new(),
                }
            } else {
                unreachable!("exactly one type checked above")
            };
            by_name.insert(name.clone(), kind);
        }
        Ok(Self { by_name })
    }

    /// Apply the named middlewares to a datagram from `ip`. `Err` = drop it.
    pub fn admit(&self, names: &[String], ip: IpAddr) -> Result<(), String> {
        for name in names {
            match self
                .by_name
                .get(name)
                .ok_or_else(|| format!("UDP middleware '{name}' not found"))?
            {
                Kind::Allow(n) if !n.iter().any(|n| n.contains(ip)) => {
                    return Err(format!("{ip} not in ipAllowList '{name}'"));
                }
                Kind::Deny(n) if n.iter().any(|n| n.contains(ip)) => {
                    return Err(format!("{ip} in ipDenyList '{name}'"));
                }
                Kind::RateLimit {
                    rate,
                    capacity,
                    buckets,
                } => {
                    if buckets.len() > MAX_BUCKETS {
                        let now = Instant::now();
                        let idle = (*capacity / *rate).max(1.0);
                        buckets.retain(|_, b| now.duration_since(b.last).as_secs_f64() < idle);
                    }
                    let now = Instant::now();
                    let mut b = buckets.entry(ip).or_insert(Bucket {
                        tokens: *capacity,
                        last: now,
                    });
                    let elapsed = now.duration_since(b.last).as_secs_f64();
                    b.tokens = (b.tokens + elapsed * rate).min(*capacity);
                    b.last = now;
                    if b.tokens < 1.0 {
                        return Err(format!("{ip} over rateLimit '{name}'"));
                    }
                    b.tokens -= 1.0;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mws(yaml: &str) -> Result<UdpMiddlewares, String> {
        UdpMiddlewares::from_config(&serde_norway::from_str(yaml).unwrap())
    }

    #[test]
    fn allow_deny_ratelimit() {
        let m = mws(
            "lan: {ipAllowList: {sourceRange: [\"10.0.0.0/8\"]}}\nrl: {rateLimit: {average: 1, burst: 2, period: 1h}}\n",
        )
        .unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(m.admit(&["lan".into()], ip("8.8.8.8")).is_err());
        assert!(m.admit(&["lan".into()], ip("10.1.1.1")).is_ok());
        assert!(m.admit(&["rl".into()], ip("1.1.1.1")).is_ok());
        assert!(m.admit(&["rl".into()], ip("1.1.1.1")).is_ok());
        assert!(m.admit(&["rl".into()], ip("1.1.1.1")).is_err());
        assert!(m.admit(&["rl".into()], ip("1.1.1.2")).is_ok());
        assert!(m.admit(&["nope".into()], ip("1.1.1.2")).is_err());
    }

    #[test]
    fn invalid_definitions_rejected() {
        assert!(mws("x: {ipDenyList: {sourceRange: [\"bad\"]}}\n").is_err());
        assert!(mws("x: {rateLimit: {average: 0}}\n").is_err());
        assert!(mws("x: {}\n").is_err());
    }
}
