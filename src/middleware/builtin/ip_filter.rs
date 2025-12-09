use crate::config::IpFilterConfig;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// High-performance IP filter middleware using CIDR matching
pub struct IpFilterMiddleware {
    allow_networks: Vec<IpNetwork>,
    deny_networks: Vec<IpNetwork>,
    default_allow: bool,
}

impl IpFilterMiddleware {
    pub fn new(config: IpFilterConfig) -> Self {
        let allow_networks = config
            .allow
            .iter()
            .filter_map(|s| Self::parse_network(s))
            .collect();

        let deny_networks = config
            .deny
            .iter()
            .filter_map(|s| Self::parse_network(s))
            .collect();

        let default_allow = config.default_action.to_lowercase() != "deny";

        Self {
            allow_networks,
            deny_networks,
            default_allow,
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
                IpAddr::V4(v4) => Some(IpNetwork::V4(
                    ipnetwork::Ipv4Network::new(v4, 32).ok()?,
                )),
                IpAddr::V6(v6) => Some(IpNetwork::V6(
                    ipnetwork::Ipv6Network::new(v6, 128).ok()?,
                )),
            };
        }

        tracing::warn!("Failed to parse IP filter rule: {}", s);
        None
    }

    /// Check if an IP address is allowed
    /// Order: explicit allow -> explicit deny -> default action
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Check allow list first (whitelist takes priority)
        for network in &self.allow_networks {
            if network.contains(ip) {
                return true;
            }
        }

        // Check deny list
        for network in &self.deny_networks {
            if network.contains(ip) {
                return false;
            }
        }

        // Default action
        self.default_allow
    }

    /// Check if filter has any rules configured
    pub fn has_rules(&self) -> bool {
        !self.allow_networks.is_empty() || !self.deny_networks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_single_ip() {
        let config = IpFilterConfig {
            allow: vec!["192.168.1.100".to_string()],
            deny: vec![],
            default_action: "deny".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        assert!(filter.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(!filter.is_allowed("192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn test_allow_cidr() {
        let config = IpFilterConfig {
            allow: vec!["10.0.0.0/8".to_string()],
            deny: vec![],
            default_action: "deny".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        assert!(filter.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(filter.is_allowed("10.255.255.255".parse().unwrap()));
        assert!(!filter.is_allowed("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_deny_cidr() {
        let config = IpFilterConfig {
            allow: vec![],
            deny: vec!["192.168.0.0/16".to_string()],
            default_action: "allow".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        assert!(!filter.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(filter.is_allowed("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_allow_takes_priority() {
        let config = IpFilterConfig {
            allow: vec!["192.168.1.100".to_string()],
            deny: vec!["192.168.0.0/16".to_string()],
            default_action: "deny".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        // Specific IP is allowed even though subnet is denied
        assert!(filter.is_allowed("192.168.1.100".parse().unwrap()));
        // Other IPs in subnet are denied
        assert!(!filter.is_allowed("192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn test_ipv6() {
        let config = IpFilterConfig {
            allow: vec!["::1".to_string(), "2001:db8::/32".to_string()],
            deny: vec![],
            default_action: "deny".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        assert!(filter.is_allowed("::1".parse().unwrap()));
        assert!(filter.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(!filter.is_allowed("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_default_allow() {
        let config = IpFilterConfig {
            allow: vec![],
            deny: vec![],
            default_action: "allow".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        assert!(filter.is_allowed("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_default_deny() {
        let config = IpFilterConfig {
            allow: vec![],
            deny: vec![],
            default_action: "deny".to_string(),
        };
        let filter = IpFilterMiddleware::new(config);

        assert!(!filter.is_allowed("1.2.3.4".parse().unwrap()));
    }
}
