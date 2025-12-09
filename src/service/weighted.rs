use crate::config::WeightedService;
use std::sync::atomic::{AtomicI64, Ordering};

/// Weighted service router for traffic splitting between services
/// Uses smooth weighted round-robin for even distribution
pub struct WeightedServiceRouter {
    services: Vec<WeightedServiceEntry>,
    total_weight: i64,
    // Current weights for smooth weighted round-robin (signed for proper subtraction)
    current_weights: Vec<AtomicI64>,
}

struct WeightedServiceEntry {
    name: String,
    weight: u32,
}

impl WeightedServiceRouter {
    pub fn new(config: &WeightedService) -> Self {
        let services: Vec<WeightedServiceEntry> = config
            .services
            .iter()
            .map(|s| WeightedServiceEntry {
                name: s.name.clone(),
                weight: s.weight,
            })
            .collect();

        let total_weight: i64 = services.iter().map(|s| s.weight as i64).sum();
        let current_weights: Vec<AtomicI64> = services
            .iter()
            .map(|_| AtomicI64::new(0))
            .collect();

        Self {
            services,
            total_weight,
            current_weights,
        }
    }

    /// Select the next service using smooth weighted round-robin
    /// Returns the service name to route to
    pub fn next_service(&self) -> Option<&str> {
        if self.services.is_empty() {
            return None;
        }

        if self.services.len() == 1 {
            return Some(&self.services[0].name);
        }

        // Smooth weighted round-robin algorithm
        // 1. Add each service's weight to its current weight
        // 2. Select the service with highest current weight
        // 3. Subtract total weight from the selected service's current weight

        let mut max_weight = i64::MIN;
        let mut selected_idx = 0;

        for (i, service) in self.services.iter().enumerate() {
            // Add the static weight
            let current = self.current_weights[i].fetch_add(service.weight as i64, Ordering::Relaxed)
                + service.weight as i64;

            if current > max_weight {
                max_weight = current;
                selected_idx = i;
            }
        }

        // Subtract total weight from selected
        self.current_weights[selected_idx].fetch_sub(self.total_weight, Ordering::Relaxed);

        Some(&self.services[selected_idx].name)
    }

    /// Select a service using random weighted selection
    /// Useful for one-off selections or when order doesn't matter
    pub fn random_service(&self) -> Option<&str> {
        if self.services.is_empty() {
            return None;
        }

        if self.services.len() == 1 {
            return Some(&self.services[0].name);
        }

        let target = (fast_random() as i64).abs() % self.total_weight;

        let mut cumulative = 0i64;
        for service in &self.services {
            cumulative += service.weight as i64;
            if target < cumulative {
                return Some(&service.name);
            }
        }

        // Fallback to last service
        self.services.last().map(|s| s.name.as_str())
    }

    /// Get all service names in the weighted group
    pub fn service_names(&self) -> Vec<&str> {
        self.services.iter().map(|s| s.name.as_str()).collect()
    }

    /// Get total weight
    pub fn total_weight(&self) -> i64 {
        self.total_weight
    }

    /// Check if router is empty
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

/// Fast xorshift random - no allocation, no syscall
#[inline]
fn fast_random() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u32> = Cell::new(0xDEADBEEF);
    }
    STATE.with(|state| {
        let mut x = state.get();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state.set(x);
        x
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WeightedServiceRef;
    use std::collections::HashMap;

    fn make_weighted_service(services: Vec<(&str, u32)>) -> WeightedService {
        WeightedService {
            services: services
                .into_iter()
                .map(|(name, weight)| WeightedServiceRef {
                    name: name.to_string(),
                    weight,
                })
                .collect(),
            sticky: None,
            health_check: None,
        }
    }

    #[test]
    fn test_weighted_router_single_service() {
        let config = make_weighted_service(vec![("service-a", 1)]);
        let router = WeightedServiceRouter::new(&config);

        for _ in 0..10 {
            assert_eq!(router.next_service(), Some("service-a"));
        }
    }

    #[test]
    fn test_weighted_router_equal_weights() {
        let config = make_weighted_service(vec![
            ("service-a", 1),
            ("service-b", 1),
        ]);
        let router = WeightedServiceRouter::new(&config);

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for _ in 0..100 {
            if let Some(name) = router.next_service() {
                *counts.entry(name).or_insert(0) += 1;
            }
        }

        // Should be roughly equal (50 each)
        let a = *counts.get("service-a").unwrap_or(&0);
        let b = *counts.get("service-b").unwrap_or(&0);
        assert_eq!(a, 50);
        assert_eq!(b, 50);
    }

    #[test]
    fn test_weighted_router_unequal_weights() {
        let config = make_weighted_service(vec![
            ("service-a", 9),  // 90%
            ("service-b", 1),  // 10%
        ]);
        let router = WeightedServiceRouter::new(&config);

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for _ in 0..100 {
            if let Some(name) = router.next_service() {
                *counts.entry(name).or_insert(0) += 1;
            }
        }

        // Should be 90-10 distribution
        let a = *counts.get("service-a").unwrap_or(&0);
        let b = *counts.get("service-b").unwrap_or(&0);
        assert_eq!(a, 90);
        assert_eq!(b, 10);
    }

    #[test]
    fn test_weighted_router_three_services() {
        let config = make_weighted_service(vec![
            ("service-a", 5),  // 50%
            ("service-b", 3),  // 30%
            ("service-c", 2),  // 20%
        ]);
        let router = WeightedServiceRouter::new(&config);

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for _ in 0..100 {
            if let Some(name) = router.next_service() {
                *counts.entry(name).or_insert(0) += 1;
            }
        }

        let a = *counts.get("service-a").unwrap_or(&0);
        let b = *counts.get("service-b").unwrap_or(&0);
        let c = *counts.get("service-c").unwrap_or(&0);

        // Smooth weighted should give exact distribution over 10 rounds
        assert_eq!(a, 50);
        assert_eq!(b, 30);
        assert_eq!(c, 20);
    }

    #[test]
    fn test_weighted_router_empty() {
        let config = make_weighted_service(vec![]);
        let router = WeightedServiceRouter::new(&config);

        assert!(router.is_empty());
        assert_eq!(router.next_service(), None);
    }

    #[test]
    fn test_random_service() {
        let config = make_weighted_service(vec![
            ("service-a", 9),
            ("service-b", 1),
        ]);
        let router = WeightedServiceRouter::new(&config);

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for _ in 0..1000 {
            if let Some(name) = router.random_service() {
                *counts.entry(name).or_insert(0) += 1;
            }
        }

        // Random selection should be approximately 90-10 (with some variance)
        let a = *counts.get("service-a").unwrap_or(&0);
        let b = *counts.get("service-b").unwrap_or(&0);

        // Allow 5% variance for random
        assert!(a > 850 && a < 950, "Expected ~900, got {}", a);
        assert!(b > 50 && b < 150, "Expected ~100, got {}", b);
    }
}
