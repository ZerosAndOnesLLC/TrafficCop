use super::Middleware;

/// Ordered collection of middleware instances to execute for a route.
pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl MiddlewareChain {
    /// Create an empty middleware chain.
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    /// Append a middleware to the end of the chain.
    pub fn add<M: Middleware + 'static>(&mut self, middleware: M) {
        self.middlewares.push(Box::new(middleware));
    }

    /// Returns the number of middleware in the chain.
    pub fn len(&self) -> usize {
        self.middlewares.len()
    }

    /// Returns true if the chain has no middleware.
    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}
