use crate::config::MirroringService;

/// Fast xorshift random - no allocation, no syscall
#[inline]
fn fast_random() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u32> = Cell::new(0xCAFEBABE);
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

/// Mirroring service router for shadowing traffic to secondary services
/// The main service always receives the request, mirrors receive a copy
/// based on their configured percentage
pub struct MirroringServiceRouter {
    /// The main service that always receives the request
    main_service: String,
    /// Mirror services with their percentages (0-100)
    mirrors: Vec<MirrorEntry>,
    /// Maximum body size to buffer for mirroring (None = no limit)
    max_body_size: Option<i64>,
}

struct MirrorEntry {
    name: String,
    percent: u32,
}

impl MirroringServiceRouter {
    pub fn new(config: &MirroringService) -> Self {
        let mirrors: Vec<MirrorEntry> = config
            .mirrors
            .iter()
            .map(|m| MirrorEntry {
                name: m.name.clone(),
                percent: m.percent.min(100), // Cap at 100%
            })
            .collect();

        Self {
            main_service: config.service.clone(),
            mirrors,
            max_body_size: config.max_body_size,
        }
    }

    /// Get the main service name (always receives the request)
    pub fn main_service(&self) -> &str {
        &self.main_service
    }

    /// Get which mirrors should receive this request based on their percentages
    /// Returns a list of mirror service names that should receive a copy
    pub fn mirrors_for_request(&self) -> Vec<&str> {
        if self.mirrors.is_empty() {
            return Vec::new();
        }

        let mut selected = Vec::new();

        for mirror in &self.mirrors {
            // Each mirror independently decides based on its percentage
            let roll = fast_random() % 100;
            if roll < mirror.percent {
                selected.push(mirror.name.as_str());
            }
        }

        selected
    }

    /// Check if a body size is within the mirroring limit
    pub fn body_within_limit(&self, size: i64) -> bool {
        match self.max_body_size {
            Some(max) if max > 0 => size <= max,
            _ => true, // No limit or unlimited (0 or negative)
        }
    }

    /// Get max body size for mirroring
    pub fn max_body_size(&self) -> Option<i64> {
        self.max_body_size
    }

    /// Get all mirror service names
    pub fn all_mirrors(&self) -> Vec<&str> {
        self.mirrors.iter().map(|m| m.name.as_str()).collect()
    }

    /// Check if mirroring is configured
    pub fn has_mirrors(&self) -> bool {
        !self.mirrors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MirrorRef;

    fn make_mirroring_service(main: &str, mirrors: Vec<(&str, u32)>) -> MirroringService {
        MirroringService {
            service: main.to_string(),
            mirrors: mirrors
                .into_iter()
                .map(|(name, percent)| MirrorRef {
                    name: name.to_string(),
                    percent,
                })
                .collect(),
            max_body_size: None,
            mirror_body: true,
        }
    }

    #[test]
    fn test_mirroring_main_service() {
        let config = make_mirroring_service("main-api", vec![("shadow-api", 100)]);
        let router = MirroringServiceRouter::new(&config);

        assert_eq!(router.main_service(), "main-api");
    }

    #[test]
    fn test_mirroring_100_percent() {
        let config = make_mirroring_service("main-api", vec![("shadow-api", 100)]);
        let router = MirroringServiceRouter::new(&config);

        // 100% mirror should always be selected
        for _ in 0..100 {
            let mirrors = router.mirrors_for_request();
            assert_eq!(mirrors, vec!["shadow-api"]);
        }
    }

    #[test]
    fn test_mirroring_0_percent() {
        let config = make_mirroring_service("main-api", vec![("shadow-api", 0)]);
        let router = MirroringServiceRouter::new(&config);

        // 0% mirror should never be selected
        for _ in 0..100 {
            let mirrors = router.mirrors_for_request();
            assert!(mirrors.is_empty());
        }
    }

    #[test]
    fn test_mirroring_percentage() {
        let config = make_mirroring_service("main-api", vec![("shadow-api", 10)]);
        let router = MirroringServiceRouter::new(&config);

        let mut hit_count = 0;
        let iterations = 1000;

        for _ in 0..iterations {
            let mirrors = router.mirrors_for_request();
            if !mirrors.is_empty() {
                hit_count += 1;
            }
        }

        // Should be approximately 10% (allow 5% variance)
        let hit_rate = (hit_count as f64 / iterations as f64) * 100.0;
        assert!(
            hit_rate > 5.0 && hit_rate < 15.0,
            "Expected ~10% hit rate, got {}%",
            hit_rate
        );
    }

    #[test]
    fn test_mirroring_multiple_mirrors() {
        let config = make_mirroring_service(
            "main-api",
            vec![
                ("shadow-1", 100),  // Always
                ("shadow-2", 50),   // Half
                ("shadow-3", 0),    // Never
            ],
        );
        let router = MirroringServiceRouter::new(&config);

        let mut shadow1_count = 0;
        let mut shadow2_count = 0;
        let mut shadow3_count = 0;
        let iterations = 1000;

        for _ in 0..iterations {
            let mirrors = router.mirrors_for_request();
            if mirrors.contains(&"shadow-1") {
                shadow1_count += 1;
            }
            if mirrors.contains(&"shadow-2") {
                shadow2_count += 1;
            }
            if mirrors.contains(&"shadow-3") {
                shadow3_count += 1;
            }
        }

        assert_eq!(shadow1_count, iterations); // 100%
        assert_eq!(shadow3_count, 0);          // 0%

        // shadow-2 should be ~50% (allow variance)
        let rate2 = (shadow2_count as f64 / iterations as f64) * 100.0;
        assert!(
            rate2 > 45.0 && rate2 < 55.0,
            "Expected ~50% for shadow-2, got {}%",
            rate2
        );
    }

    #[test]
    fn test_mirroring_no_mirrors() {
        let config = make_mirroring_service("main-api", vec![]);
        let router = MirroringServiceRouter::new(&config);

        assert!(!router.has_mirrors());
        assert!(router.mirrors_for_request().is_empty());
    }

    #[test]
    fn test_mirroring_body_limit() {
        let mut config = make_mirroring_service("main-api", vec![("shadow", 100)]);
        config.max_body_size = Some(1024 * 1024); // 1MB

        let router = MirroringServiceRouter::new(&config);

        assert!(router.body_within_limit(512 * 1024)); // 512KB OK
        assert!(router.body_within_limit(1024 * 1024)); // 1MB OK
        assert!(!router.body_within_limit(2 * 1024 * 1024)); // 2MB NOT OK
    }

    #[test]
    fn test_mirroring_no_body_limit() {
        let config = make_mirroring_service("main-api", vec![("shadow", 100)]);
        let router = MirroringServiceRouter::new(&config);

        // No limit means any size is OK
        assert!(router.body_within_limit(i64::MAX));
    }
}
