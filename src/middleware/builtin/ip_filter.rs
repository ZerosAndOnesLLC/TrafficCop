use crate::config::{IpAllowListConfig, IpDenyListConfig, IpStrategy};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// IP allowlist middleware (Traefik ipAllowList)
pub struct IpAllowListMiddleware {
    source_range: Vec<IpNetwork>,
    ip_strategy: Option<IpStrategy>,
    reject_status_code: u16,
}

impl IpAllowListMiddleware {
    pub fn new(config: &IpAllowListConfig) -> Self {
        let source_range = config
            .source_range
            .iter()
            .filter_map(|s| parse_network(s))
            .collect();

        Self {
            source_range,
            ip_strategy: config.ip_strategy.clone(),
            reject_status_code: config.reject_status_code.unwrap_or(403),
        }
    }

    /// Check if an IP address is allowed
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.source_range.is_empty() {
            return true; // No rules means allow all
        }

        for network in &self.source_range {
            if network.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Get the reject status code
    pub fn reject_status_code(&self) -> u16 {
        self.reject_status_code
    }

    /// Get IP from X-Forwarded-For based on strategy
    pub fn get_client_ip(&self, forwarded_for: Option<&str>, remote_addr: IpAddr) -> IpAddr {
        if let Some(strategy) = &self.ip_strategy {
            if let Some(xff) = forwarded_for {
                let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
                let depth = strategy.depth as usize;

                // Depth 0 means use the rightmost IP (closest proxy)
                // Depth 1 means skip one from right, etc.
                if depth < ips.len() {
                    let idx = ips.len() - 1 - depth;
                    if let Ok(ip) = ips[idx].parse::<IpAddr>() {
                        // Check if IP should be excluded
                        let should_exclude = strategy.excluded_ips.iter().any(|excluded| {
                            if let Some(network) = parse_network(excluded) {
                                network.contains(ip)
                            } else {
                                false
                            }
                        });

                        if !should_exclude {
                            return ip;
                        }
                    }
                }
            }
        }

        remote_addr
    }

    /// Check if filter has any rules configured
    pub fn has_rules(&self) -> bool {
        !self.source_range.is_empty()
    }
}

/// IP denylist middleware (Traefik ipDenyList)
pub struct IpDenyListMiddleware {
    source_range: Vec<IpNetwork>,
    ip_strategy: Option<IpStrategy>,
}

impl IpDenyListMiddleware {
    pub fn new(config: &IpDenyListConfig) -> Self {
        let source_range = config
            .source_range
            .iter()
            .filter_map(|s| parse_network(s))
            .collect();

        Self {
            source_range,
            ip_strategy: config.ip_strategy.clone(),
        }
    }

    /// Check if an IP address is denied
    #[inline]
    pub fn is_denied(&self, ip: IpAddr) -> bool {
        for network in &self.source_range {
            if network.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Get IP from X-Forwarded-For based on strategy
    pub fn get_client_ip(&self, forwarded_for: Option<&str>, remote_addr: IpAddr) -> IpAddr {
        if let Some(strategy) = &self.ip_strategy {
            if let Some(xff) = forwarded_for {
                let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
                let depth = strategy.depth as usize;

                if depth < ips.len() {
                    let idx = ips.len() - 1 - depth;
                    if let Ok(ip) = ips[idx].parse::<IpAddr>() {
                        let should_exclude = strategy.excluded_ips.iter().any(|excluded| {
                            if let Some(network) = parse_network(excluded) {
                                network.contains(ip)
                            } else {
                                false
                            }
                        });

                        if !should_exclude {
                            return ip;
                        }
                    }
                }
            }
        }

        remote_addr
    }

    /// Check if filter has any rules configured
    pub fn has_rules(&self) -> bool {
        !self.source_range.is_empty()
    }
}

/// Parse an IP address or CIDR notation into IpNetwork
fn parse_network(s: &str) -> Option<IpNetwork> {
    // Try parsing as CIDR first
    if let Ok(network) = s.parse::<IpNetwork>() {
        return Some(network);
    }

    // Try parsing as single IP address
    if let Ok(ip) = s.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Some(IpNetwork::V4(ipnetwork::Ipv4Network::new(v4, 32).ok()?)),
            IpAddr::V6(v6) => Some(IpNetwork::V6(ipnetwork::Ipv6Network::new(v6, 128).ok()?)),
        };
    }

    tracing::warn!("Failed to parse IP filter rule: {}", s);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_single_ip() {
        let config = IpAllowListConfig {
            source_range: vec!["192.168.1.100".to_string()],
            ip_strategy: None,
            reject_status_code: None,
        };
        let filter = IpAllowListMiddleware::new(&config);

        assert!(filter.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(!filter.is_allowed("192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn test_allow_cidr() {
        let config = IpAllowListConfig {
            source_range: vec!["10.0.0.0/8".to_string()],
            ip_strategy: None,
            reject_status_code: None,
        };
        let filter = IpAllowListMiddleware::new(&config);

        assert!(filter.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(filter.is_allowed("10.255.255.255".parse().unwrap()));
        assert!(!filter.is_allowed("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_deny_cidr() {
        let config = IpDenyListConfig {
            source_range: vec!["192.168.0.0/16".to_string()],
            ip_strategy: None,
        };
        let filter = IpDenyListMiddleware::new(&config);

        assert!(filter.is_denied("192.168.1.1".parse().unwrap()));
        assert!(!filter.is_denied("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6() {
        let config = IpAllowListConfig {
            source_range: vec!["::1".to_string(), "2001:db8::/32".to_string()],
            ip_strategy: None,
            reject_status_code: None,
        };
        let filter = IpAllowListMiddleware::new(&config);

        assert!(filter.is_allowed("::1".parse().unwrap()));
        assert!(filter.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(!filter.is_allowed("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_empty_allowlist_allows_all() {
        let config = IpAllowListConfig {
            source_range: vec![],
            ip_strategy: None,
            reject_status_code: None,
        };
        let filter = IpAllowListMiddleware::new(&config);

        assert!(filter.is_allowed("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_ip_strategy_depth() {
        let config = IpAllowListConfig {
            source_range: vec!["10.0.0.0/8".to_string()],
            ip_strategy: Some(IpStrategy {
                depth: 1,
                excluded_ips: vec![],
                ipv6_subnet: None,
            }),
            reject_status_code: None,
        };
        let filter = IpAllowListMiddleware::new(&config);

        // X-Forwarded-For: client, proxy1, proxy2
        // depth=1 means skip proxy2, use proxy1
        let client_ip =
            filter.get_client_ip(Some("10.0.0.1, 192.168.1.1, 172.16.0.1"), "127.0.0.1".parse().unwrap());

        assert_eq!(client_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    }
}
