use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

use crate::cluster::ClusterManager;
use crate::config::{Config, MiddlewareConfig};
use crate::health::HealthChecker;
use crate::router::Router;
use crate::service::ServiceManager;

/// Admin API handler for runtime inspection and cluster management
pub struct AdminApi {
    config: Arc<Config>,
    _router: Arc<Router>,
    _services: Arc<ServiceManager>,
    _health_checker: Option<Arc<HealthChecker>>,
    cluster_manager: Option<Arc<ClusterManager>>,
}

impl AdminApi {
    pub fn new(
        config: Arc<Config>,
        router: Arc<Router>,
        services: Arc<ServiceManager>,
    ) -> Self {
        Self {
            config,
            _router: router,
            _services: services,
            _health_checker: None,
            cluster_manager: None,
        }
    }

    pub fn with_health_checker(mut self, checker: Arc<HealthChecker>) -> Self {
        self._health_checker = Some(checker);
        self
    }

    /// Add cluster manager for HA operations
    pub fn with_cluster_manager(mut self, manager: Arc<ClusterManager>) -> Self {
        self.cluster_manager = Some(manager);
        self
    }

    /// Handle admin API request
    pub async fn handle(
        &self,
        req: Request<Incoming>,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let path = req.uri().path();
        let method = req.method();

        match (method.as_str(), path) {
            ("GET", "/api/overview") => self.overview().await,
            ("GET", "/api/entrypoints") => self.entrypoints().await,
            ("GET", "/api/routers") => self.routers().await,
            ("GET", "/api/services") => self.services_list().await,
            ("GET", "/api/middlewares") => self.middlewares().await,
            ("GET", path) if path.starts_with("/api/routers/") => {
                let name = &path["/api/routers/".len()..];
                self.router_detail(name).await
            }
            ("GET", path) if path.starts_with("/api/services/") => {
                let name = &path["/api/services/".len()..];
                self.service_detail(name).await
            }
            ("GET", "/api/health") => self.health_status().await,
            // Cluster/HA endpoints
            ("GET", "/api/cluster") => self.cluster_status().await,
            ("GET", "/api/cluster/nodes") => self.cluster_nodes().await,
            ("POST", "/api/cluster/drain") => self.start_drain().await,
            ("POST", "/api/cluster/undrain") => self.stop_drain().await,
            ("GET", path) if path.starts_with("/api/cluster/nodes/") => {
                let node_id = &path["/api/cluster/nodes/".len()..];
                if node_id.ends_with("/drain") {
                    let node_id = node_id.trim_end_matches("/drain");
                    self.drain_node(node_id).await
                } else {
                    self.node_detail(node_id).await
                }
            }
            ("POST", path) if path.starts_with("/api/cluster/nodes/") && path.ends_with("/drain") => {
                let node_id = path
                    .trim_start_matches("/api/cluster/nodes/")
                    .trim_end_matches("/drain");
                self.drain_node(node_id).await
            }
            ("GET", "/ping") => self.ping(),
            ("GET", "/") | ("GET", "/dashboard") => self.dashboard(),
            _ => self.not_found(),
        }
    }

    /// System overview
    async fn overview(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct Overview {
            version: &'static str,
            routers: usize,
            services: usize,
            middlewares: usize,
            entrypoints: usize,
        }

        let overview = Overview {
            version: env!("CARGO_PKG_VERSION"),
            routers: self.config.routers().len(),
            services: self.config.services().len(),
            middlewares: self.config.middlewares().len(),
            entrypoints: self.config.entry_points.len(),
        };

        self.json_response(&overview)
    }

    /// List entrypoints
    async fn entrypoints(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct Entrypoint {
            name: String,
            address: String,
        }

        let entrypoints: Vec<Entrypoint> = self
            .config
            .entry_points
            .iter()
            .map(|(name, ep)| Entrypoint {
                name: name.clone(),
                address: ep.address.clone(),
            })
            .collect();

        self.json_response(&entrypoints)
    }

    /// List routers
    async fn routers(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct RouterInfo {
            name: String,
            rule: String,
            service: String,
            entrypoints: Vec<String>,
            middlewares: Vec<String>,
            priority: i32,
        }

        let routers: Vec<RouterInfo> = self
            .config
            .routers()
            .iter()
            .map(|(name, r)| RouterInfo {
                name: name.clone(),
                rule: r.rule.clone(),
                service: r.service.clone(),
                entrypoints: r.entry_points.clone(),
                middlewares: r.middlewares.clone(),
                priority: r.priority,
            })
            .collect();

        self.json_response(&routers)
    }

    /// Router detail
    async fn router_detail(&self, name: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct RouterDetail {
            name: String,
            rule: String,
            service: String,
            entrypoints: Vec<String>,
            middlewares: Vec<String>,
            priority: i32,
            status: String,
        }

        if let Some(router) = self.config.routers().get(name) {
            let detail = RouterDetail {
                name: name.to_string(),
                rule: router.rule.clone(),
                service: router.service.clone(),
                entrypoints: router.entry_points.clone(),
                middlewares: router.middlewares.clone(),
                priority: router.priority,
                status: "enabled".to_string(),
            };
            self.json_response(&detail)
        } else {
            self.not_found()
        }
    }

    /// List services
    async fn services_list(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct ServiceInfo {
            name: String,
            servers: Vec<ServerInfo>,
            load_balancer: Option<String>,
        }

        #[derive(Serialize)]
        struct ServerInfo {
            url: String,
            weight: Option<i32>,
        }

        let services: Vec<ServiceInfo> = self
            .config
            .services()
            .iter()
            .map(|(name, s)| {
                let servers = if let Some(lb) = &s.load_balancer {
                    lb.servers
                        .iter()
                        .map(|server| ServerInfo {
                            url: server.url.clone(),
                            weight: Some(server.weight as i32),
                        })
                        .collect()
                } else {
                    Vec::new()
                };

                ServiceInfo {
                    name: name.clone(),
                    servers,
                    load_balancer: s.load_balancer.as_ref().map(|_| "roundRobin".to_string()),
                }
            })
            .collect();

        self.json_response(&services)
    }

    /// Service detail with health status
    async fn service_detail(&self, name: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct ServiceDetail {
            name: String,
            servers: Vec<ServerDetail>,
            load_balancer: Option<String>,
            status: String,
        }

        #[derive(Serialize)]
        struct ServerDetail {
            url: String,
            weight: Option<i32>,
            healthy: bool,
        }

        if let Some(service) = self.config.services().get(name) {
            let servers = if let Some(lb) = &service.load_balancer {
                lb.servers
                    .iter()
                    .map(|server| ServerDetail {
                        url: server.url.clone(),
                        weight: Some(server.weight as i32),
                        healthy: true, // TODO: get actual health status
                    })
                    .collect()
            } else {
                Vec::new()
            };

            let detail = ServiceDetail {
                name: name.to_string(),
                servers,
                load_balancer: service.load_balancer.as_ref().map(|_| "roundRobin".to_string()),
                status: "enabled".to_string(),
            };
            self.json_response(&detail)
        } else {
            self.not_found()
        }
    }

    /// List middlewares
    async fn middlewares(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct MiddlewareInfo {
            name: String,
            #[serde(rename = "type")]
            mw_type: String,
        }

        let middlewares: Vec<MiddlewareInfo> = self
            .config
            .middlewares()
            .iter()
            .map(|(name, mw)| MiddlewareInfo {
                name: name.clone(),
                mw_type: Self::middleware_type(mw),
            })
            .collect();

        self.json_response(&middlewares)
    }

    fn middleware_type(mw: &MiddlewareConfig) -> String {
        mw.middleware_type().to_string()
    }

    // =========================================================================
    // Cluster/HA Endpoints
    // =========================================================================

    /// Get cluster status
    async fn cluster_status(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        if let Some(cluster) = &self.cluster_manager {
            let stats = cluster.get_cluster_stats().await;
            self.json_response(&stats)
        } else {
            #[derive(Serialize)]
            struct NotEnabled {
                enabled: bool,
                message: &'static str,
            }
            self.json_response(&NotEnabled {
                enabled: false,
                message: "Cluster mode not enabled",
            })
        }
    }

    /// Get list of cluster nodes
    async fn cluster_nodes(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        if let Some(cluster) = &self.cluster_manager {
            match cluster.get_active_nodes().await {
                Ok(nodes) => self.json_response(&nodes),
                Err(e) => self.error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to get nodes: {}", e),
                ),
            }
        } else {
            self.json_response(&Vec::<()>::new())
        }
    }

    /// Get details for a specific node
    async fn node_detail(&self, node_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        if let Some(cluster) = &self.cluster_manager {
            match cluster.store().node_get(node_id).await {
                Ok(Some(node)) => self.json_response(&node),
                Ok(None) => self.not_found(),
                Err(e) => self.error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to get node: {}", e),
                ),
            }
        } else {
            self.not_found()
        }
    }

    /// Start draining this node
    async fn start_drain(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        if let Some(cluster) = &self.cluster_manager {
            match cluster.start_drain().await {
                Ok(()) => {
                    info!("Node drain started via API");
                    #[derive(Serialize)]
                    struct DrainResponse {
                        success: bool,
                        message: &'static str,
                        node_id: String,
                    }
                    self.json_response(&DrainResponse {
                        success: true,
                        message: "Drain started",
                        node_id: cluster.node_id().to_string(),
                    })
                }
                Err(e) => self.error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to start drain: {}", e),
                ),
            }
        } else {
            self.error_response(
                StatusCode::BAD_REQUEST,
                "Cluster mode not enabled",
            )
        }
    }

    /// Stop draining (re-enable this node)
    async fn stop_drain(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        // Note: In production, you'd want a way to cancel draining
        // For now, this just returns a message
        self.error_response(
            StatusCode::NOT_IMPLEMENTED,
            "Undrain not yet implemented. Restart the node to re-enable.",
        )
    }

    /// Drain a specific node (remote drain)
    async fn drain_node(&self, node_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        if let Some(cluster) = &self.cluster_manager {
            // Check if it's this node
            if cluster.node_id() == node_id {
                return self.start_drain().await;
            }

            // For remote nodes, we update their status in the store
            // The node will pick this up and start draining
            match cluster.store().node_set_status(node_id, crate::store::NodeStatus::Draining).await {
                Ok(()) => {
                    info!("Initiated drain for node {} via API", node_id);
                    #[derive(Serialize)]
                    struct DrainResponse {
                        success: bool,
                        message: String,
                        node_id: String,
                    }
                    self.json_response(&DrainResponse {
                        success: true,
                        message: format!("Drain initiated for node {}", node_id),
                        node_id: node_id.to_string(),
                    })
                }
                Err(e) => self.error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to drain node: {}", e),
                ),
            }
        } else {
            self.error_response(
                StatusCode::BAD_REQUEST,
                "Cluster mode not enabled",
            )
        }
    }

    // =========================================================================
    // Health Endpoints
    // =========================================================================

    /// Health status of backends
    async fn health_status(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct HealthStatus {
            status: String,
            services: Vec<ServiceHealth>,
        }

        #[derive(Serialize)]
        struct ServiceHealth {
            name: String,
            status: String,
            backends: Vec<BackendHealth>,
        }

        #[derive(Serialize)]
        struct BackendHealth {
            url: String,
            status: String,
        }

        let services: Vec<ServiceHealth> = self
            .config
            .services()
            .iter()
            .map(|(name, s)| {
                let backends = if let Some(lb) = &s.load_balancer {
                    lb.servers
                        .iter()
                        .map(|server| BackendHealth {
                            url: server.url.clone(),
                            status: "healthy".to_string(), // TODO: actual health
                        })
                        .collect()
                } else {
                    Vec::new()
                };

                ServiceHealth {
                    name: name.clone(),
                    status: "healthy".to_string(),
                    backends,
                }
            })
            .collect();

        let health = HealthStatus {
            status: "healthy".to_string(),
            services,
        };

        self.json_response(&health)
    }

    /// Simple ping endpoint
    fn ping(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Self::full_body("OK"))
            .unwrap()
    }

    /// Dashboard HTML
    fn dashboard(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>TrafficCop Dashboard</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; margin-bottom: 30px; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .card h2 { margin-top: 0; color: #00d4ff; font-size: 16px; }
        .stat { display: inline-block; margin-right: 40px; }
        .stat-value { font-size: 32px; font-weight: bold; color: #00ff88; }
        .stat-label { font-size: 12px; color: #888; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #333; }
        th { color: #888; font-weight: normal; }
        .status-ok { color: #00ff88; }
        .status-error { color: #ff4444; }
    </style>
</head>
<body>
    <h1>TrafficCop Dashboard</h1>
    <div class="card">
        <h2>Overview</h2>
        <div id="overview"></div>
    </div>
    <div class="card">
        <h2>Routers</h2>
        <div id="routers"></div>
    </div>
    <div class="card">
        <h2>Services</h2>
        <div id="services"></div>
    </div>
    <script>
        async function load() {
            const overview = await fetch('/api/overview').then(r => r.json());
            document.getElementById('overview').innerHTML = `
                <div class="stat"><div class="stat-value">${overview.routers}</div><div class="stat-label">Routers</div></div>
                <div class="stat"><div class="stat-value">${overview.services}</div><div class="stat-label">Services</div></div>
                <div class="stat"><div class="stat-value">${overview.middlewares}</div><div class="stat-label">Middlewares</div></div>
                <div class="stat"><div class="stat-value">${overview.entrypoints}</div><div class="stat-label">Entrypoints</div></div>
            `;

            const routers = await fetch('/api/routers').then(r => r.json());
            document.getElementById('routers').innerHTML = `<table>
                <tr><th>Name</th><th>Rule</th><th>Service</th><th>Entrypoints</th></tr>
                ${routers.map(r => `<tr><td>${r.name}</td><td>${r.rule}</td><td>${r.service}</td><td>${r.entrypoints.join(', ')}</td></tr>`).join('')}
            </table>`;

            const services = await fetch('/api/services').then(r => r.json());
            document.getElementById('services').innerHTML = `<table>
                <tr><th>Name</th><th>Servers</th><th>Load Balancer</th></tr>
                ${services.map(s => `<tr><td>${s.name}</td><td>${s.servers.length}</td><td>${s.load_balancer || '-'}</td></tr>`).join('')}
            </table>`;
        }
        load();
    </script>
</body>
</html>"#;

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Self::full_body(html))
            .unwrap()
    }

    fn not_found(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(Self::full_body(r#"{"error":"Not Found"}"#))
            .unwrap()
    }

    fn error_response(&self, status: StatusCode, message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        #[derive(Serialize)]
        struct ErrorResponse<'a> {
            error: &'a str,
        }
        let body = serde_json::to_string(&ErrorResponse { error: message })
            .unwrap_or_else(|_| format!(r#"{{"error":"{}"}}"#, message));
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Self::full_body(body))
            .unwrap()
    }

    fn json_response<T: Serialize>(&self, data: &T) -> Response<BoxBody<Bytes, hyper::Error>> {
        match serde_json::to_string(data) {
            Ok(json) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Self::full_body(json))
                .unwrap(),
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(Self::full_body(r#"{"error":"Serialization failed"}"#))
                .unwrap(),
        }
    }

    #[inline]
    fn full_body<T: Into<Bytes>>(content: T) -> BoxBody<Bytes, hyper::Error> {
        Full::new(content.into())
            .map_err(|never| match never {})
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_type_detection() {
        let mw = MiddlewareConfig {
            headers: Some(crate::config::HeadersConfig::default()),
            ..Default::default()
        };
        assert_eq!(AdminApi::middleware_type(&mw), "headers");
    }
}
