pub mod builtin;
mod chain;
pub mod registry;

pub use builtin::{
    BasicAuthMiddleware, CorsMiddleware, HeadersMiddleware, IpAllowListMiddleware,
    IpDenyListMiddleware, RateLimitMiddleware, RedirectSchemeMiddleware,
};
pub use chain::MiddlewareChain;
pub use registry::{MiddlewareRegistry, RequestContext};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, Request, Response};
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Middleware: Send + Sync {
    fn name(&self) -> &str;

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
    fn call(&self, req: Request<Incoming>) -> BoxFuture<'_, Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>>;
}

pub struct Next<'a> {
    pub(crate) middlewares: &'a [Box<dyn Middleware>],
    pub(crate) endpoint: &'a dyn Endpoint,
}

impl<'a> Next<'a> {
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
