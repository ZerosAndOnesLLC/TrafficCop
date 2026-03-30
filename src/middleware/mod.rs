//! Middleware framework for the reverse proxy request/response pipeline.

pub mod builtin;
mod chain;
pub mod registry;

/// Core built-in middleware types re-exported for convenience.
pub use builtin::{
    AccessLogWriter, BasicAuthMiddleware, CorsMiddleware, HeadersMiddleware,
    IpAllowListMiddleware, IpDenyListMiddleware, RateLimitMiddleware,
    RedirectSchemeMiddleware,
};
/// Ordered chain of middleware to execute per request.
pub use chain::MiddlewareChain;
/// Registry for resolving middleware by name, and per-request context.
pub use registry::{MiddlewareRegistry, RequestContext};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, Request, Response};
use std::future::Future;
use std::pin::Pin;

/// A pinned, boxed, sendable future used throughout the middleware pipeline.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait that all middleware must implement to participate in the request pipeline.
pub trait Middleware: Send + Sync {
    /// Returns the middleware instance name (used for logging and registry lookup).
    fn name(&self) -> &str;

    /// Process a request, optionally delegating to `next` to continue the chain.
    fn handle<'a>(
        &'a self,
        req: Request<Incoming>,
        next: Next<'a>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>>;
}

/// Trait for the terminal endpoint in a middleware chain.
/// Unlike `Fn`, this correctly ties the returned future's lifetime to `&self`,
/// allowing the future to borrow data owned by the endpoint.
pub trait Endpoint: Send + Sync {
    /// Handle the request at the end of the middleware chain (e.g., proxy to backend).
    fn call(&self, req: Request<Incoming>) -> BoxFuture<'_, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>>;
}

/// Continuation handle passed to middleware; calling `run` invokes the next middleware or endpoint.
pub struct Next<'a> {
    pub(crate) middlewares: &'a [Box<dyn Middleware>],
    pub(crate) endpoint: &'a dyn Endpoint,
}

impl<'a> Next<'a> {
    /// Execute the remaining middleware chain and terminal endpoint.
    pub fn run(
        self,
        req: Request<Incoming>,
    ) -> BoxFuture<'a, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>> {
        if let Some((current, rest)) = self.middlewares.split_first() {
            let next = Next {
                middlewares: rest,
                endpoint: self.endpoint,
            };
            current.handle(req, next)
        } else {
            self.endpoint.call(req)
        }
    }
}
