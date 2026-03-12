use crate::config::ParsedBackendUri;
use crate::router::Router;
use crate::service::ServiceManager;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_TYPE, HOST, TRANSFER_ENCODING, UPGRADE};
use hyper::{body::Incoming, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, error, warn};

use super::grpc;

fn hop_by_hop_headers() -> &'static [HeaderName] {
    static HEADERS: &[HeaderName] = &[
        CONNECTION,
        TRANSFER_ENCODING,
        UPGRADE,
    ];
    HEADERS
}

pub struct ProxyHandler {
    client: Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
}

impl ProxyHandler {
    pub fn new() -> Self {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_reuse_address(true);
        connector.enforce_http(false);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .pool_max_idle_per_host(256)
            .retry_canceled_requests(true)
            .set_host(true)
            .build(connector);

        Self { client }
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
        entrypoint: &str,
        router: &Router,
        services: &ServiceManager,
        is_tls: bool,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let start = Instant::now();

        // Detect if this is a gRPC request for proper error responses
        let is_grpc = grpc::is_grpc_request(&req) || grpc::is_grpc_web_request(&req);

        // Extract host - we need to clone only if we'll use it for X-Forwarded-Host
        // but for matching we can use a reference
        let host_header_value = req.headers().get(HOST).cloned();
        let host = host_header_value.as_ref()
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h));

        // Use references directly - no allocations
        let path = req.uri().path();
        let query = req.uri().query();
        let method = req.method();

        debug!(
            "Request: {} {} from {} (host: {:?}, grpc: {})",
            method, path, remote_addr, host, is_grpc
        );

        // Find matching route
        let route = match router.match_request(
            entrypoint,
            host,
            path,
            query,
            Some(method.as_str()),
            req.headers(),
        ) {
            Some(route) => route,
            None => {
                debug!(
                    "No route matched for {} {}",
                    host.unwrap_or("-"),
                    path
                );
                return Ok(Self::error_response_maybe_grpc(
                    StatusCode::NOT_FOUND,
                    "Not Found",
                    is_grpc,
                ));
            }
        };

        // Use references to avoid cloning - only clone service_name which is needed for lookup
        let route_name = &route.name;
        let service_name = &route.service;

        debug!(
            "Matched route '{}' -> service '{}'",
            route_name, service_name
        );

        // Get service and select backend
        // Get backend info - clone parsed_uri if available, otherwise clone URL
        let (backend_url, parsed_uri) = {
            let service = match services.get_service(service_name) {
                Some(s) => s,
                None => {
                    error!("Service '{}' not found", service_name);
                    return Ok(Self::error_response_maybe_grpc(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service Unavailable",
                        is_grpc,
                    ));
                }
            };

            match &service.balancer {
                Some(balancer) => match balancer.next_server() {
                    Some(s) => {
                        let url = s.url_arc.as_ref().map(Arc::clone).unwrap_or_else(|| Arc::from(s.url.as_str()));
                        (url, s.parsed_uri.clone())
                    }
                    None => {
                        error!("No healthy backends for service '{}'", service_name);
                        return Ok(Self::error_response_maybe_grpc(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "No Healthy Backends",
                            is_grpc,
                        ));
                    }
                },
                None => {
                    error!("Service '{}' has no load balancer configured", service_name);
                    return Ok(Self::error_response_maybe_grpc(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service Not Configured",
                        is_grpc,
                    ));
                }
            }
            // service guard is dropped here, releasing DashMap lock
        };

        debug!("Selected backend: {}", backend_url);

        // Check for WebSocket upgrade
        if super::websocket::is_websocket_upgrade(&req) {
            debug!("Handling WebSocket upgrade to {}", backend_url);
            return super::websocket::handle_websocket_upgrade(req, &backend_url, remote_addr).await;
        }

        // Build the proxied request - use pre-parsed URI if available
        let backend_uri = match Self::build_backend_uri_fast(&backend_url, req.uri(), parsed_uri.as_ref()) {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to build backend URI: {}", e);
                return Ok(Self::error_response_maybe_grpc(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    is_grpc,
                ));
            }
        };

        // Create the proxied request
        let proxied_req =
            match Self::build_proxied_request(req, backend_uri, remote_addr, host, is_tls, is_grpc)
            {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to build proxied request: {}", e);
                    return Ok(Self::error_response_maybe_grpc(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        is_grpc,
                    ));
                }
            };

        // Forward the request to the backend with timeout
        // Default request timeout of 30 seconds (can be configured via serversTransport)
        // For gRPC, use longer timeout as streaming calls may be long-lived
        let request_timeout = if is_grpc {
            Duration::from_secs(300) // 5 minutes for gRPC
        } else {
            Duration::from_secs(30)
        };
        let backend_future = self.client.request(proxied_req);

        match timeout(request_timeout, backend_future).await {
            Ok(Ok(response)) => {
                let status = response.status();
                let elapsed = start.elapsed();
                debug!(
                    "Backend response: {} in {:?} from {}",
                    status, elapsed, backend_url
                );

                let (parts, body) = response.into_parts();
                let mut response = Response::from_parts(parts, body.map_err(|e| e.into()).boxed());

                // Remove hop-by-hop headers from response (but not for gRPC trailers)
                if !is_grpc {
                    for header in hop_by_hop_headers() {
                        response.headers_mut().remove(header);
                    }
                }

                Ok(response)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed();
                error!(
                    "Backend request failed in {:?}: {} -> {}",
                    elapsed, backend_url, e
                );
                Ok(Self::error_response_maybe_grpc(
                    StatusCode::BAD_GATEWAY,
                    "Bad Gateway",
                    is_grpc,
                ))
            }
            Err(_) => {
                let elapsed = start.elapsed();
                warn!(
                    "Request timeout after {:?} (limit: {:?}): {}",
                    elapsed, request_timeout, backend_url
                );
                Ok(Self::error_response_maybe_grpc(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Gateway Timeout",
                    is_grpc,
                ))
            }
        }
    }

    #[inline]
    fn build_backend_uri(backend_url: &str, original_uri: &Uri) -> Result<Uri, String> {
        let backend_base: Uri = backend_url
            .parse()
            .map_err(|e| format!("Invalid backend URL: {}", e))?;

        let path_and_query = original_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let scheme = backend_base.scheme_str().unwrap_or("http");
        let authority = backend_base.authority().map(|a| a.as_str()).unwrap_or("");

        // Pre-calculate capacity to avoid reallocation
        let capacity = scheme.len() + 3 + authority.len() + path_and_query.len();
        let mut uri_string = String::with_capacity(capacity);
        uri_string.push_str(scheme);
        uri_string.push_str("://");
        uri_string.push_str(authority);
        uri_string.push_str(path_and_query);

        uri_string
            .parse()
            .map_err(|e| format!("Failed to build URI: {}", e))
    }

    /// Optimized URI builder that uses pre-parsed typed components when available.
    /// Uses Uri::builder with typed Scheme/Authority to avoid String allocation and re-parse.
    #[inline]
    fn build_backend_uri_fast(
        backend_url: &str,
        original_uri: &Uri,
        parsed: Option<&ParsedBackendUri>,
    ) -> Result<Uri, String> {
        let Some(parsed) = parsed else {
            return Self::build_backend_uri(backend_url, original_uri);
        };

        let path_and_query = original_uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| hyper::http::uri::PathAndQuery::from_static("/"));

        Uri::builder()
            .scheme(parsed.scheme.clone())
            .authority(parsed.authority.clone())
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| format!("Failed to build URI: {}", e))
    }

    fn build_proxied_request(
        req: Request<Incoming>,
        backend_uri: Uri,
        remote_addr: SocketAddr,
        original_host: Option<&str>,
        is_tls: bool,
        is_grpc: bool,
    ) -> Result<Request<BoxBody<Bytes, hyper::Error>>, String> {
        let (mut parts, body) = req.into_parts();

        parts.uri = backend_uri;

        // For gRPC, we need to be more careful about which headers we remove
        if !is_grpc {
            // Remove hop-by-hop headers
            for header in hop_by_hop_headers() {
                parts.headers.remove(header);
            }
            // Also remove these which aren't in the static list
            parts.headers.remove("keep-alive");
            parts.headers.remove("proxy-authenticate");
            parts.headers.remove("proxy-authorization");
            parts.headers.remove("te");
            parts.headers.remove("trailers");
        } else {
            // For gRPC, keep TE: trailers as it's required for trailer handling
            // Remove other hop-by-hop headers except trailers-related
            parts.headers.remove("keep-alive");
            parts.headers.remove("proxy-authenticate");
            parts.headers.remove("proxy-authorization");

            // Ensure TE: trailers is set (required for gRPC over HTTP/2)
            if !parts.headers.contains_key("te") {
                parts.headers.insert(
                    HeaderName::from_static("te"),
                    HeaderValue::from_static("trailers"),
                );
            }
        }

        // Add/append X-Forwarded-For - optimized to avoid format! macro
        {
            let ip_str = remote_addr.ip().to_string();
            let xff = match parts.headers.get("x-forwarded-for") {
                Some(existing) => {
                    if let Ok(existing_str) = existing.to_str() {
                        // Pre-allocate: existing + ", " + ip
                        let mut s = String::with_capacity(existing_str.len() + 2 + ip_str.len());
                        s.push_str(existing_str);
                        s.push_str(", ");
                        s.push_str(&ip_str);
                        s
                    } else {
                        ip_str
                    }
                }
                None => ip_str,
            };

            if let Ok(val) = HeaderValue::from_str(&xff) {
                parts
                    .headers
                    .insert(HeaderName::from_static("x-forwarded-for"), val);
            }
        }

        if let Some(host) = original_host {
            if let Ok(val) = HeaderValue::from_str(host) {
                parts
                    .headers
                    .insert(HeaderName::from_static("x-forwarded-host"), val);
            }
        }

        let proto = if is_tls { "https" } else { "http" };
        parts.headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(proto),
        );

        // Set the Host header to the backend host
        if let Some(authority) = parts.uri.authority() {
            if let Ok(host_value) = HeaderValue::from_str(authority.as_str()) {
                parts.headers.insert(HOST, host_value);
            }
        }

        let boxed_body = body.map_err(|e| e.into()).boxed();

        Ok(Request::from_parts(parts, boxed_body))
    }

    /// Return appropriate error response based on whether this is a gRPC request
    #[inline]
    fn error_response_maybe_grpc(
        status: StatusCode,
        message: &'static str,
        is_grpc: bool,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        if is_grpc {
            grpc::grpc_gateway_error(status, message)
        } else {
            Self::error_response(status, message)
        }
    }

    #[inline]
    fn error_response(
        status: StatusCode,
        message: &'static str,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Self::full_body(message))
            .unwrap()
    }

    #[inline]
    fn full_body<T: Into<Bytes>>(content: T) -> BoxBody<Bytes, hyper::Error> {
        Full::new(content.into())
            .map_err(|never| match never {})
            .boxed()
    }
}

impl Default for ProxyHandler {
    fn default() -> Self {
        Self::new()
    }
}
