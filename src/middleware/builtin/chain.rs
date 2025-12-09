use crate::config::ChainConfig;

/// Chain middleware composes multiple middlewares together
/// This is primarily a configuration-level concept - the actual chaining
/// happens in the middleware pipeline, but this struct holds the config
pub struct ChainMiddleware {
    /// List of middleware names to chain together (in order)
    pub middlewares: Vec<String>,
}

impl ChainMiddleware {
    pub fn new(config: ChainConfig) -> Self {
        Self {
            middlewares: config.middlewares,
        }
    }

    /// Get the list of middleware names in the chain
    pub fn middleware_names(&self) -> &[String] {
        &self.middlewares
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }

    /// Number of middlewares in the chain
    pub fn len(&self) -> usize {
        self.middlewares.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_middleware() {
        let config = ChainConfig {
            middlewares: vec![
                "rate-limit".to_string(),
                "auth".to_string(),
                "headers".to_string(),
            ],
        };

        let chain = ChainMiddleware::new(config);

        assert_eq!(chain.len(), 3);
        assert!(!chain.is_empty());
        assert_eq!(
            chain.middleware_names(),
            &["rate-limit", "auth", "headers"]
        );
    }

    #[test]
    fn test_empty_chain() {
        let config = ChainConfig {
            middlewares: vec![],
        };

        let chain = ChainMiddleware::new(config);

        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }
}
