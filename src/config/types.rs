//! Configuration type definitions for TrafficCop.
//!
//! All structs use Traefik-compatible camelCase serde naming. The root type is [`Config`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::duration::Duration;

/// Root configuration - can be static config (traefik.yml) or combined
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Entry points configuration (static config)
    #[serde(default)]
    pub entry_points: HashMap<String, EntryPoint>,

    /// HTTP routing configuration (dynamic config)
    #[serde(default)]
    pub http: Option<HttpConfig>,

    /// TCP routing configuration (dynamic config)
    #[serde(default)]
    pub tcp: Option<TcpConfig>,

    /// UDP routing configuration (dynamic config)
    #[serde(default)]
    pub udp: Option<UdpConfig>,

    /// TLS configuration (dynamic config)
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Certificate resolvers (static config)
    #[serde(default)]
    pub certificates_resolvers: HashMap<String, CertificateResolver>,

    /// File provider configuration (static config)
    #[serde(default)]
    pub providers: Option<ProvidersConfig>,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    /// API configuration
    #[serde(default)]
    pub api: Option<ApiConfig>,

    /// Log configuration
    #[serde(default)]
    pub log: Option<LogConfig>,

    /// Access log configuration
    #[serde(default)]
    pub access_log: Option<AccessLogConfig>,

    /// Cluster/HA configuration
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
}

/// HTTP routing configuration: routers, services, middlewares, and transports.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpConfig {
    /// HTTP routers keyed by name.
    #[serde(default)]
    pub routers: HashMap<String, Router>,

    /// HTTP services keyed by name.
    #[serde(default)]
    pub services: HashMap<String, Service>,

    /// HTTP middlewares keyed by name.
    #[serde(default)]
    pub middlewares: HashMap<String, MiddlewareConfig>,

    /// Backend connection transports keyed by name.
    #[serde(default)]
    pub servers_transports: HashMap<String, ServersTransport>,
}

// =============================================================================
// TCP Configuration
// =============================================================================

/// TCP routing configuration (similar to Traefik's TCP config)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpConfig {
    /// TCP routers
    #[serde(default)]
    pub routers: HashMap<String, TcpRouter>,

    /// TCP services
    #[serde(default)]
    pub services: HashMap<String, TcpService>,

    /// TCP middlewares
    #[serde(default)]
    pub middlewares: HashMap<String, TcpMiddlewareConfig>,

    /// TCP servers transports
    #[serde(default)]
    pub servers_transports: HashMap<String, TcpServersTransport>,
}

/// TCP router configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpRouter {
    /// Entry points to listen on
    #[serde(default)]
    pub entry_points: Vec<String>,

    /// Routing rule (HostSNI for TLS, or catch-all `*`)
    pub rule: String,

    /// Rule syntax version (for forward compatibility)
    #[serde(default)]
    pub rule_syntax: Option<String>,

    /// Service to route to
    pub service: String,

    /// Middlewares to apply
    #[serde(default)]
    pub middlewares: Vec<String>,

    /// Priority for rule matching
    #[serde(default)]
    pub priority: i32,

    /// TLS configuration (enables TLS passthrough or termination)
    #[serde(default)]
    pub tls: Option<TcpRouterTls>,
}

/// TCP router TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpRouterTls {
    /// Enable TLS passthrough (proxy encrypted traffic without decryption)
    #[serde(default)]
    pub passthrough: bool,

    /// Certificate resolver for TLS termination
    #[serde(default)]
    pub cert_resolver: Option<String>,

    /// Domains for certificate generation
    #[serde(default)]
    pub domains: Vec<TlsDomain>,

    /// TLS options reference
    #[serde(default)]
    pub options: Option<String>,
}

/// TCP service configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpService {
    /// Load balancer service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<TcpLoadBalancer>,

    /// Weighted service (traffic splitting)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weighted: Option<TcpWeightedService>,
}

impl TcpService {
    /// Returns the active service variant name ("loadBalancer", "weighted", or "unknown").
    pub fn service_type(&self) -> &'static str {
        if self.load_balancer.is_some() {
            "loadBalancer"
        } else if self.weighted.is_some() {
            "weighted"
        } else {
            "unknown"
        }
    }
}

/// TCP load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpLoadBalancer {
    /// Backend servers
    pub servers: Vec<TcpServer>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<TcpHealthCheck>,

    /// Servers transport reference
    #[serde(default)]
    pub servers_transport: Option<String>,

    /// Proxy protocol version (1 or 2) to send to backends
    #[serde(default)]
    pub proxy_protocol: Option<u8>,

    /// Termination delay for graceful shutdown
    #[serde(default)]
    pub termination_delay: Option<Duration>,
}

/// TCP backend server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpServer {
    /// Server address (host:port)
    pub address: String,

    /// Server weight for load balancing
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Enable TLS to backend
    #[serde(default)]
    pub tls: bool,
}

/// TCP health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpHealthCheck {
    /// Health check interval
    #[serde(default = "default_tcp_health_interval")]
    pub interval: Duration,

    /// Health check timeout
    #[serde(default = "default_tcp_health_timeout")]
    pub timeout: Duration,
}

fn default_tcp_health_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_tcp_health_timeout() -> Duration {
    Duration::from_secs(5)
}

/// TCP weighted service for traffic splitting
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpWeightedService {
    /// Services with weights
    pub services: Vec<TcpWeightedServiceRef>,
}

/// Reference to a TCP service with weight
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpWeightedServiceRef {
    /// Service name
    pub name: String,

    /// Weight
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// TCP middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpMiddlewareConfig {
    /// IP allowlist middleware
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_allow_list: Option<TcpIpAllowList>,

    /// IP denylist middleware
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_deny_list: Option<TcpIpDenyList>,

    /// In-flight connection limit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_flight_conn: Option<TcpInFlightConn>,
}

impl TcpMiddlewareConfig {
    /// Returns the active middleware variant name.
    pub fn middleware_type(&self) -> &'static str {
        if self.ip_allow_list.is_some() {
            "ipAllowList"
        } else if self.ip_deny_list.is_some() {
            "ipDenyList"
        } else if self.in_flight_conn.is_some() {
            "inFlightConn"
        } else {
            "unknown"
        }
    }
}

/// TCP IP allowlist middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpIpAllowList {
    /// Allowed IP ranges (CIDR notation)
    pub source_range: Vec<String>,
}

/// TCP IP denylist middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpIpDenyList {
    /// Denied IP ranges (CIDR notation)
    pub source_range: Vec<String>,
}

/// TCP in-flight connection limit middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpInFlightConn {
    /// Maximum number of concurrent connections
    pub amount: i64,
}

/// TCP servers transport configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpServersTransport {
    /// TLS configuration for backend connections
    #[serde(default)]
    pub tls: Option<TcpTransportTls>,

    /// Dial timeout
    #[serde(default = "default_dial_timeout")]
    pub dial_timeout: Duration,

    /// Keep-alive settings
    #[serde(default)]
    pub dial_keep_alive: Option<Duration>,
}

/// TLS configuration for TCP backend connections
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TcpTransportTls {
    /// Server name for TLS verification
    #[serde(default)]
    pub server_name: Option<String>,

    /// Skip TLS verification (insecure)
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// Root CA certificates
    #[serde(default)]
    pub root_cas: Vec<String>,

    /// Client certificates
    #[serde(default)]
    pub certificates: Vec<TlsCertificate>,
}

// =============================================================================
// UDP Configuration
// =============================================================================

/// UDP routing configuration (similar to TCP config)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UdpConfig {
    /// UDP routers
    #[serde(default)]
    pub routers: HashMap<String, UdpRouter>,

    /// UDP services
    #[serde(default)]
    pub services: HashMap<String, UdpService>,

    /// UDP middlewares
    #[serde(default)]
    pub middlewares: HashMap<String, UdpMiddlewareConfig>,
}

/// UDP router configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpRouter {
    /// Entry points to listen on
    #[serde(default)]
    pub entry_points: Vec<String>,

    /// Routing rule (ClientIP or catch-all `*`)
    /// Note: UDP doesn't support SNI since there's no TLS handshake
    pub rule: String,

    /// Service to route to
    pub service: String,

    /// Middlewares to apply
    #[serde(default)]
    pub middlewares: Vec<String>,

    /// Priority for rule matching
    #[serde(default)]
    pub priority: i32,
}

/// UDP service configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UdpService {
    /// Load balancer service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<UdpLoadBalancer>,

    /// Weighted service (traffic splitting)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weighted: Option<UdpWeightedService>,
}

impl UdpService {
    /// Returns the active service variant name ("loadBalancer", "weighted", or "unknown").
    pub fn service_type(&self) -> &'static str {
        if self.load_balancer.is_some() {
            "loadBalancer"
        } else if self.weighted.is_some() {
            "weighted"
        } else {
            "unknown"
        }
    }
}

/// UDP load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpLoadBalancer {
    /// Backend servers
    pub servers: Vec<UdpServer>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<UdpHealthCheck>,
}

/// UDP backend server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpServer {
    /// Server address (host:port)
    pub address: String,

    /// Server weight for load balancing
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// UDP health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpHealthCheck {
    /// Health check interval
    #[serde(default = "default_udp_health_interval")]
    pub interval: Duration,

    /// Health check timeout
    #[serde(default = "default_udp_health_timeout")]
    pub timeout: Duration,

    /// Payload to send for health check (hex-encoded or plain text)
    #[serde(default)]
    pub payload: Option<String>,

    /// Expected response pattern (regex)
    #[serde(default)]
    pub expected_response: Option<String>,
}

fn default_udp_health_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_udp_health_timeout() -> Duration {
    Duration::from_secs(5)
}

/// UDP weighted service for traffic splitting
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpWeightedService {
    /// Services with weights
    pub services: Vec<UdpWeightedServiceRef>,
}

/// Reference to a UDP service with weight
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpWeightedServiceRef {
    /// Service name
    pub name: String,

    /// Weight
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// UDP middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UdpMiddlewareConfig {
    /// IP allowlist middleware
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_allow_list: Option<UdpIpAllowList>,

    /// IP denylist middleware
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_deny_list: Option<UdpIpDenyList>,

    /// Rate limiting middleware
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<UdpRateLimit>,
}

impl UdpMiddlewareConfig {
    /// Returns the active middleware variant name.
    pub fn middleware_type(&self) -> &'static str {
        if self.ip_allow_list.is_some() {
            "ipAllowList"
        } else if self.ip_deny_list.is_some() {
            "ipDenyList"
        } else if self.rate_limit.is_some() {
            "rateLimit"
        } else {
            "unknown"
        }
    }
}

/// UDP IP allowlist middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpIpAllowList {
    /// Allowed IP ranges (CIDR notation)
    pub source_range: Vec<String>,
}

/// UDP IP denylist middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpIpDenyList {
    /// Denied IP ranges (CIDR notation)
    pub source_range: Vec<String>,
}

/// UDP rate limit middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpRateLimit {
    /// Maximum packets per period per source IP
    pub average: u64,

    /// Burst allowance
    #[serde(default)]
    pub burst: u64,

    /// Rate limit period
    #[serde(default = "default_rate_period")]
    pub period: Duration,
}

/// Metrics export configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsConfig {
    /// Prometheus metrics configuration.
    #[serde(default)]
    pub prometheus: Option<PrometheusConfig>,
}

/// Prometheus metrics endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusConfig {
    /// Listen address for the metrics endpoint.
    #[serde(default = "default_metrics_address")]
    pub address: String,

    /// Add entry point labels to metrics.
    #[serde(default)]
    pub add_entry_points_labels: bool,

    /// Add service labels to metrics.
    #[serde(default)]
    pub add_services_labels: bool,

    /// Add router labels to metrics
    #[serde(default)]
    pub add_routers_labels: bool,

    /// Serve metrics on specific entry point (alternative to address)
    #[serde(default)]
    pub entry_point: Option<String>,

    /// Custom histogram buckets
    #[serde(default)]
    pub buckets: Vec<f64>,
}

fn default_metrics_address() -> String {
    ":9090".to_string()
}

/// Admin API and dashboard configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    /// Enable the dashboard UI.
    #[serde(default)]
    pub dashboard: bool,

    /// Allow insecure API access without TLS.
    #[serde(default)]
    pub insecure: bool,

    /// Enable debug mode for API
    #[serde(default)]
    pub debug: bool,

    /// Custom base path for API (default: "/api")
    #[serde(default)]
    pub base_path: Option<String>,

    /// Hide dashboard advertisement
    #[serde(default, rename = "disabledashboardad")]
    pub disable_dashboard_ad: bool,
}

/// Application logging configuration (level, format, output file).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    /// Log level (e.g., "debug", "info", "warn", "error").
    #[serde(default)]
    pub level: Option<String>,

    /// Log format (e.g., "json", "common").
    #[serde(default)]
    pub format: Option<String>,

    /// Path to log output file.
    #[serde(default)]
    pub file_path: Option<String>,
}

/// Access log configuration (per-request logging).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogConfig {
    /// Path to access log output file.
    #[serde(default)]
    pub file_path: Option<String>,

    /// Access log format (e.g., "json", "clf").
    #[serde(default)]
    pub format: Option<String>,

    /// Number of access log lines to buffer before flushing.
    #[serde(default)]
    pub bufferingsize: Option<u64>,
}

/// Dynamic configuration providers (file, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProvidersConfig {
    /// File-based dynamic configuration provider.
    #[serde(default)]
    pub file: Option<FileProviderConfig>,
}

/// File-based dynamic configuration provider.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileProviderConfig {
    /// Path to a single configuration file.
    #[serde(default)]
    pub filename: Option<String>,

    /// Directory containing configuration files.
    #[serde(default)]
    pub directory: Option<String>,

    /// Watch for file changes and reload automatically.
    #[serde(default = "default_watch")]
    pub watch: bool,
}

fn default_watch() -> bool {
    true
}

// =============================================================================
// Entry Points
// =============================================================================

/// Network entrypoint (listen address, TLS, proxy protocol, timeouts).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPoint {
    /// Listen address (e.g., ":80", ":443").
    pub address: String,

    /// Mark as default entry point for routers without explicit entry points.
    #[serde(default)]
    pub as_default: bool,

    /// HTTP-specific settings (redirections, TLS, middlewares).
    #[serde(default)]
    pub http: Option<EntryPointHttp>,

    /// Forwarded headers trust configuration.
    #[serde(default)]
    pub forwarded_headers: Option<ForwardedHeaders>,

    /// Transport-layer settings (timeouts, keep-alive).
    #[serde(default)]
    pub transport: Option<EntryPointTransport>,

    /// PROXY protocol configuration.
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocol>,
}

/// HTTP-specific entrypoint settings (redirections, TLS, default middlewares).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointHttp {
    /// HTTP redirection rules.
    #[serde(default)]
    pub redirections: Option<EntryPointRedirections>,

    /// TLS settings for this entry point.
    #[serde(default)]
    pub tls: Option<EntryPointTls>,

    /// Default middlewares applied to all routers on this entry point.
    #[serde(default)]
    pub middlewares: Vec<String>,
}

/// Entrypoint-level HTTP redirections (e.g., HTTP to HTTPS).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointRedirections {
    /// Redirect to another entry point.
    #[serde(default)]
    pub entry_point: Option<RedirectEntryPoint>,
}

/// Redirect to another entrypoint (target, scheme, permanent flag).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectEntryPoint {
    /// Target entry point name.
    pub to: String,

    /// Redirect scheme (default: "https").
    #[serde(default = "default_https_scheme")]
    pub scheme: String,

    /// Use permanent (301) redirect.
    #[serde(default = "default_true")]
    pub permanent: bool,

    /// Priority for the generated redirect router.
    #[serde(default)]
    pub priority: Option<i32>,
}

fn default_https_scheme() -> String {
    "https".to_string()
}

fn default_true() -> bool {
    true
}

/// TLS settings for an entrypoint (cert resolver, domains, options reference).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointTls {
    /// TLS options reference name.
    #[serde(default)]
    pub options: Option<String>,

    /// Certificate resolver to use.
    #[serde(default)]
    pub cert_resolver: Option<String>,

    /// Domains for certificate generation.
    #[serde(default)]
    pub domains: Vec<TlsDomain>,
}

/// Forwarded headers trust configuration (trusted IPs, hop-by-hop headers).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ForwardedHeaders {
    /// Trusted IP ranges for forwarded headers.
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    /// Trust all forwarded headers regardless of source.
    #[serde(default)]
    pub insecure: bool,

    /// Connection header handling - list of hop-by-hop headers to remove
    #[serde(default)]
    pub connection: Vec<String>,
}

/// Transport-layer settings for an entrypoint (timeouts, keep-alive limits).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointTransport {
    /// Request/response timeout settings.
    #[serde(default)]
    pub responding_timeouts: Option<RespondingTimeouts>,

    /// Graceful shutdown lifecycle settings.
    #[serde(default)]
    pub life_cycle: Option<LifeCycle>,

    /// Maximum number of requests per keep-alive connection (0 = unlimited)
    #[serde(default)]
    pub keep_alive_max_requests: Option<i64>,

    /// Maximum time a keep-alive connection can be used
    #[serde(default)]
    pub keep_alive_max_time: Option<Duration>,
}

/// Timeouts for reading requests, writing responses, and idle connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RespondingTimeouts {
    /// Maximum duration for reading the entire request.
    #[serde(default = "default_read_timeout")]
    pub read_timeout: Duration,

    /// Maximum duration for writing the response.
    #[serde(default)]
    pub write_timeout: Duration,

    /// Maximum duration an idle connection is kept open.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: Duration,
}

fn default_read_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(180)
}

impl Default for RespondingTimeouts {
    fn default() -> Self {
        Self {
            read_timeout: default_read_timeout(),
            write_timeout: Duration::ZERO,
            idle_timeout: default_idle_timeout(),
        }
    }
}

/// Graceful shutdown lifecycle timeouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifeCycle {
    /// Grace period before forcefully closing connections.
    #[serde(default = "default_grace_timeout")]
    pub grace_time_out: Duration,

    /// Grace period to keep accepting new requests during shutdown.
    #[serde(default)]
    pub request_accept_grace_timeout: Duration,
}

fn default_grace_timeout() -> Duration {
    Duration::from_secs(10)
}

impl Default for LifeCycle {
    fn default() -> Self {
        Self {
            grace_time_out: default_grace_timeout(),
            request_accept_grace_timeout: Duration::ZERO,
        }
    }
}

/// PROXY protocol configuration (trusted IPs for client address extraction).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProtocol {
    /// Trusted IP ranges for PROXY protocol headers.
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    /// Trust PROXY protocol from all sources.
    #[serde(default)]
    pub insecure: bool,
}

// =============================================================================
// Services
// =============================================================================

/// Service configuration - in Traefik format, exactly one of these should be set
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Load balancer service variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<LoadBalancerService>,

    /// Weighted traffic splitting service variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weighted: Option<WeightedService>,

    /// Traffic mirroring service variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirroring: Option<MirroringService>,

    /// Failover service variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<FailoverService>,
}

impl Service {
    /// Get the service type for matching
    pub fn service_type(&self) -> &'static str {
        if self.load_balancer.is_some() {
            "loadBalancer"
        } else if self.weighted.is_some() {
            "weighted"
        } else if self.mirroring.is_some() {
            "mirroring"
        } else if self.failover.is_some() {
            "failover"
        } else {
            "unknown"
        }
    }
}

/// Load balancer service with backend servers, stickiness, and health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancerService {
    /// Backend servers to load balance across.
    pub servers: Vec<Server>,

    /// Forward the original Host header to backends.
    #[serde(default = "default_true")]
    pub pass_host_header: bool,

    /// Session stickiness configuration.
    #[serde(default)]
    pub sticky: Option<Sticky>,

    /// Active health check configuration.
    #[serde(default)]
    pub health_check: Option<HealthCheck>,

    /// Named servers transport for backend connections.
    #[serde(default)]
    pub servers_transport: Option<String>,

    /// Response forwarding settings.
    #[serde(default)]
    pub response_forwarding: Option<ResponseForwarding>,
}

/// HTTP backend server (URL, weight, and pre-parsed URI for hot-path performance).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /// Backend server URL.
    pub url: String,

    /// Server weight for load balancing.
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Preserve the original request path when forwarding.
    #[serde(default)]
    pub preserve_path: bool,

    /// Pre-parsed URI for performance - populated after deserialization
    #[serde(skip)]
    pub parsed_uri: Option<ParsedBackendUri>,

    /// Arc-wrapped URL for cheap cloning in hot path (~1ns vs ~50-200ns for String)
    #[serde(skip)]
    pub url_arc: Option<std::sync::Arc<str>>,
}

/// Pre-parsed backend URI components using typed parts to avoid string
/// re-construction and re-parsing on every request
#[derive(Debug, Clone)]
pub struct ParsedBackendUri {
    /// URI scheme (http or https).
    pub scheme: hyper::http::uri::Scheme,
    /// URI authority (host and optional port).
    pub authority: hyper::http::uri::Authority,
}

fn default_weight() -> u32 {
    1
}

/// Session stickiness configuration (cookie-based affinity).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sticky {
    /// Cookie-based sticky session configuration.
    #[serde(default)]
    pub cookie: Option<StickyCookie>,
}

/// Sticky session cookie parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StickyCookie {
    /// Cookie name.
    pub name: String,

    /// Set the Secure flag on the cookie.
    #[serde(default)]
    pub secure: bool,

    /// Set the HttpOnly flag on the cookie.
    #[serde(default)]
    pub http_only: bool,

    /// SameSite attribute (e.g., "none", "lax", "strict").
    #[serde(default)]
    pub same_site: Option<String>,

    /// Max-Age attribute in seconds.
    #[serde(default)]
    pub max_age: Option<i64>,

    /// Cookie path scope.
    #[serde(default)]
    pub path: Option<String>,
}

/// Active health check configuration for backend servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    /// Health check request path.
    #[serde(default = "default_health_path")]
    pub path: String,

    /// Interval between health checks.
    #[serde(default = "default_health_interval")]
    pub interval: Duration,

    /// Timeout for each health check request.
    #[serde(default = "default_health_timeout")]
    pub timeout: Duration,

    /// Scheme to use for health checks (e.g., "http", "https").
    #[serde(default)]
    pub scheme: Option<String>,

    /// Health check mode: "http" (default) or "grpc"
    #[serde(default)]
    pub mode: Option<String>,

    /// HTTP method for health check requests.
    #[serde(default)]
    pub method: Option<String>,

    /// Expected HTTP status code for a healthy response.
    #[serde(default)]
    pub status: Option<u16>,

    /// Override port for health check (uses server port by default)
    #[serde(default)]
    pub port: Option<u16>,

    /// Hostname for the health check Host header.
    #[serde(default)]
    pub hostname: Option<String>,

    /// Custom headers to include in health check requests.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Whether to follow HTTP redirects in health checks
    #[serde(default)]
    pub follow_redirects: bool,
}

fn default_health_path() -> String {
    "/".to_string()
}

fn default_health_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Response forwarding settings (flush interval for streaming).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResponseForwarding {
    /// Interval between response flushes for streaming.
    #[serde(default)]
    pub flush_interval: Option<Duration>,
}

/// Weighted service for traffic splitting across multiple backend services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedService {
    /// Services with their respective weights.
    pub services: Vec<WeightedServiceRef>,

    /// Session stickiness configuration.
    #[serde(default)]
    pub sticky: Option<Sticky>,

    /// Health check configuration.
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

/// Reference to a named service with a weight for traffic splitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedServiceRef {
    /// Service name.
    pub name: String,

    /// Traffic weight.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// Traffic mirroring service (sends copies of requests to additional backends).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirroringService {
    /// Primary service to route requests to.
    pub service: String,

    /// Mirror targets receiving copies of requests.
    #[serde(default)]
    pub mirrors: Vec<MirrorRef>,

    /// Maximum body size to mirror (in bytes).
    #[serde(default)]
    pub max_body_size: Option<i64>,

    /// Whether to mirror the request body (default: true)
    #[serde(default = "default_true")]
    pub mirror_body: bool,
}

/// Failover service - automatic failover to backup service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailoverService {
    /// Primary service name
    pub service: String,

    /// Fallback service name (used when primary fails)
    pub fallback: String,

    /// Health check configuration for failover detection
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

/// Reference to a mirror target service with a sampling percentage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorRef {
    /// Mirror target service name.
    pub name: String,

    /// Percentage of requests to mirror (0-100).
    #[serde(default = "default_mirror_percent")]
    pub percent: u32,
}

fn default_mirror_percent() -> u32 {
    100
}

/// Backend connection transport settings (TLS, connection pooling, timeouts).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServersTransport {
    /// Server name for TLS verification.
    #[serde(default)]
    pub server_name: Option<String>,

    /// Skip TLS certificate verification (insecure).
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// Root CA certificate files for backend TLS.
    #[serde(default)]
    pub root_cas: Vec<String>,

    /// Client certificates for mutual TLS with backends.
    #[serde(default)]
    pub certificates: Vec<TlsCertificate>,

    /// Maximum idle connections per host.
    #[serde(default = "default_max_idle_conns")]
    pub max_idle_conns_per_host: i32,

    /// Backend connection timeout settings.
    #[serde(default)]
    pub forwarding_timeouts: Option<ForwardingTimeouts>,

    /// Disable HTTP/2 for backend connections.
    #[serde(default)]
    pub disable_http2: bool,

    /// URI to match in the backend peer certificate.
    #[serde(default)]
    pub peer_cert_uri: Option<String>,
}

fn default_max_idle_conns() -> i32 {
    200
}

/// Timeouts for backend connections (dial, response header, idle).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardingTimeouts {
    /// Timeout for establishing a connection to the backend.
    #[serde(default = "default_dial_timeout")]
    pub dial_timeout: Duration,

    /// Timeout waiting for the backend response headers.
    #[serde(default)]
    pub response_header_timeout: Duration,

    /// Timeout for idle connections in the pool.
    #[serde(default = "default_idle_conn_timeout")]
    pub idle_conn_timeout: Duration,

    /// Timeout for idle reads on a connection.
    #[serde(default)]
    pub read_idle_timeout: Duration,

    /// Timeout for HTTP/2 ping responses.
    #[serde(default)]
    pub ping_timeout: Duration,
}

fn default_dial_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_idle_conn_timeout() -> Duration {
    Duration::from_secs(90)
}

impl Default for ForwardingTimeouts {
    fn default() -> Self {
        Self {
            dial_timeout: default_dial_timeout(),
            response_header_timeout: Duration::ZERO,
            idle_conn_timeout: default_idle_conn_timeout(),
            read_idle_timeout: Duration::ZERO,
            ping_timeout: Duration::ZERO,
        }
    }
}

// =============================================================================
// Routers
// =============================================================================

/// HTTP router: matches requests by rule and routes to a service through middlewares.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Router {
    /// Entry points this router listens on.
    #[serde(default)]
    pub entry_points: Vec<String>,

    /// Routing rule expression.
    pub rule: String,

    /// Rule syntax version (for forward compatibility)
    #[serde(default)]
    pub rule_syntax: Option<String>,

    /// Service to route matched requests to.
    pub service: String,

    /// Middlewares to apply in order.
    #[serde(default)]
    pub middlewares: Vec<String>,

    /// Priority for rule matching.
    #[serde(default)]
    pub priority: i32,

    /// TLS settings for this router.
    #[serde(default)]
    pub tls: Option<RouterTls>,

    /// Observability toggles for this router.
    #[serde(default)]
    pub observability: Option<RouterObservability>,
}

/// TLS settings for an HTTP router (cert resolver, domains, options).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouterTls {
    /// Certificate resolver to use.
    #[serde(default)]
    pub cert_resolver: Option<String>,

    /// Domains for certificate generation.
    #[serde(default)]
    pub domains: Vec<TlsDomain>,

    /// TLS options reference name.
    #[serde(default)]
    pub options: Option<String>,
}

/// TLS domain with a main domain and optional Subject Alternative Names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsDomain {
    /// Primary domain name.
    pub main: String,

    /// Subject Alternative Names.
    #[serde(default)]
    pub sans: Vec<String>,
}

/// Per-router observability toggles (access logs, tracing, metrics).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouterObservability {
    /// Enable access logging for this router.
    #[serde(default = "default_true")]
    pub access_logs: bool,

    /// Enable tracing for this router.
    #[serde(default = "default_true")]
    pub tracing: bool,

    /// Enable metrics for this router.
    #[serde(default = "default_true")]
    pub metrics: bool,
}

// =============================================================================
// Middlewares
// =============================================================================

/// Middleware configuration - in Traefik format, exactly one of these should be set
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MiddlewareConfig {
    /// Rate limiting middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    /// IP allowlist middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_allow_list: Option<IpAllowListConfig>,

    /// IP denylist middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_deny_list: Option<IpDenyListConfig>,

    /// Headers modification middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeadersConfig>,

    /// HTTP Basic authentication middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthConfig>,

    /// HTTP Digest authentication middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_auth: Option<DigestAuthConfig>,

    /// Forward authentication middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<ForwardAuthConfig>,

    /// Response compression middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<CompressConfig>,

    /// Automatic retry middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,

    /// Circuit breaker middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Scheme redirect middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_scheme: Option<RedirectSchemeConfig>,

    /// Regex-based redirect middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_regex: Option<RedirectRegexConfig>,

    /// Strip path prefix middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_prefix: Option<StripPrefixConfig>,

    /// Regex-based strip prefix middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_prefix_regex: Option<StripPrefixRegexConfig>,

    /// Add path prefix middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_prefix: Option<AddPrefixConfig>,

    /// Replace path middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_path: Option<ReplacePathConfig>,

    /// Regex-based replace path middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_path_regex: Option<ReplacePathRegexConfig>,

    /// Middleware chain (composes multiple middlewares).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainConfig>,

    /// Request/response buffering middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffering: Option<BufferingConfig>,

    /// In-flight request limiter middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_flight_req: Option<InFlightReqConfig>,

    /// Pass TLS client certificate middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_tls_client_cert: Option<PassTlsClientCertConfig>,

    /// Content-Type auto-detection middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<ContentTypeConfig>,

    /// gRPC-Web protocol bridge middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_web: Option<GrpcWebConfig>,

    /// JWT validation middleware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtConfig>,

    /// Errors middleware - custom error pages
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<ErrorsConfig>,

    /// Deprecated alias for ipAllowList (for backwards compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipWhiteList")]
    pub ip_white_list: Option<IpAllowListConfig>,
}

impl MiddlewareConfig {
    /// Get the middleware type name
    pub fn middleware_type(&self) -> &'static str {
        if self.rate_limit.is_some() { "rateLimit" }
        else if self.ip_allow_list.is_some() { "ipAllowList" }
        else if self.ip_white_list.is_some() { "ipWhiteList" }
        else if self.ip_deny_list.is_some() { "ipDenyList" }
        else if self.headers.is_some() { "headers" }
        else if self.basic_auth.is_some() { "basicAuth" }
        else if self.digest_auth.is_some() { "digestAuth" }
        else if self.forward_auth.is_some() { "forwardAuth" }
        else if self.compress.is_some() { "compress" }
        else if self.retry.is_some() { "retry" }
        else if self.circuit_breaker.is_some() { "circuitBreaker" }
        else if self.redirect_scheme.is_some() { "redirectScheme" }
        else if self.redirect_regex.is_some() { "redirectRegex" }
        else if self.strip_prefix.is_some() { "stripPrefix" }
        else if self.strip_prefix_regex.is_some() { "stripPrefixRegex" }
        else if self.add_prefix.is_some() { "addPrefix" }
        else if self.replace_path.is_some() { "replacePath" }
        else if self.replace_path_regex.is_some() { "replacePathRegex" }
        else if self.chain.is_some() { "chain" }
        else if self.buffering.is_some() { "buffering" }
        else if self.in_flight_req.is_some() { "inFlightReq" }
        else if self.pass_tls_client_cert.is_some() { "passTLSClientCert" }
        else if self.content_type.is_some() { "contentType" }
        else if self.grpc_web.is_some() { "grpcWeb" }
        else if self.jwt.is_some() { "jwt" }
        else if self.errors.is_some() { "errors" }
        else { "unknown" }
    }

    /// Get the effective IP allow list config (supports deprecated ipWhiteList)
    pub fn get_ip_allow_list(&self) -> Option<&IpAllowListConfig> {
        self.ip_allow_list.as_ref().or(self.ip_white_list.as_ref())
    }
}

/// Rate limiting middleware configuration (token bucket per source).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    /// Average requests allowed per period.
    pub average: u64,

    /// Maximum burst above the average rate.
    #[serde(default)]
    pub burst: u64,

    /// Time period for the rate calculation.
    #[serde(default = "default_rate_period")]
    pub period: Duration,

    /// Criterion for identifying the rate-limit source.
    #[serde(default)]
    pub source_criterion: Option<SourceCriterion>,
}

fn default_rate_period() -> Duration {
    Duration::from_secs(1)
}

/// Criterion for identifying the rate-limit source (IP, header, or host).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceCriterion {
    /// IP-based source identification strategy.
    #[serde(default)]
    pub ip_strategy: Option<IpStrategy>,

    /// Header name to use as the rate-limit key.
    #[serde(default)]
    pub request_header_name: Option<String>,

    /// Use the request Host as the rate-limit key.
    #[serde(default)]
    pub request_host: bool,
}

/// Strategy for extracting client IP from X-Forwarded-For headers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IpStrategy {
    /// Depth in X-Forwarded-For to extract the client IP.
    #[serde(default)]
    pub depth: u32,

    /// IPs to exclude when extracting client IP.
    #[serde(default)]
    pub excluded_ips: Vec<String>,

    /// IPv6 subnet mask size for grouping clients.
    #[serde(default)]
    pub ipv6_subnet: Option<u32>,
}

/// IP allowlist middleware (permit only listed CIDR ranges).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAllowListConfig {
    /// Allowed IP ranges (CIDR notation).
    pub source_range: Vec<String>,

    /// Strategy for extracting client IP.
    #[serde(default)]
    pub ip_strategy: Option<IpStrategy>,

    /// HTTP status code to return for rejected requests.
    #[serde(default)]
    pub reject_status_code: Option<u16>,
}

/// IP denylist middleware (block listed CIDR ranges).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpDenyListConfig {
    /// Denied IP ranges (CIDR notation).
    pub source_range: Vec<String>,

    /// Strategy for extracting client IP.
    #[serde(default)]
    pub ip_strategy: Option<IpStrategy>,
}

/// Headers middleware (custom headers, CORS, security headers, HSTS).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HeadersConfig {
    /// Custom headers to add to requests.
    #[serde(default)]
    pub custom_request_headers: HashMap<String, String>,

    /// Custom headers to add to responses.
    #[serde(default)]
    pub custom_response_headers: HashMap<String, String>,

    /// CORS: allow credentials.
    #[serde(default)]
    pub access_control_allow_credentials: bool,

    /// CORS: allowed request headers.
    #[serde(default)]
    pub access_control_allow_headers: Vec<String>,

    /// CORS: allowed HTTP methods.
    #[serde(default)]
    pub access_control_allow_methods: Vec<String>,

    /// CORS: allowed origins.
    #[serde(default)]
    pub access_control_allow_origin_list: Vec<String>,

    /// CORS: allowed origins as regex patterns.
    #[serde(default)]
    pub access_control_allow_origin_list_regex: Vec<String>,

    /// CORS: headers exposed to the browser.
    #[serde(default)]
    pub access_control_expose_headers: Vec<String>,

    /// CORS: max age for preflight cache in seconds.
    #[serde(default)]
    pub access_control_max_age: Option<i64>,

    /// Add Vary header for CORS.
    #[serde(default)]
    pub add_vary_header: bool,

    /// Set X-Frame-Options to DENY.
    #[serde(default)]
    pub frame_deny: bool,

    /// Custom X-Frame-Options value.
    #[serde(default)]
    pub custom_frame_options_value: Option<String>,

    /// Set X-Content-Type-Options to nosniff.
    #[serde(default)]
    pub content_type_nosniff: bool,

    /// Enable X-XSS-Protection header.
    #[serde(default)]
    pub browser_xss_filter: bool,

    /// Custom X-XSS-Protection value.
    #[serde(default)]
    pub custom_browser_xss_value: Option<String>,

    /// Content-Security-Policy header value.
    #[serde(default)]
    pub content_security_policy: Option<String>,

    /// Content-Security-Policy-Report-Only header value.
    #[serde(default)]
    pub content_security_policy_report_only: Option<String>,

    /// Public-Key-Pins header value.
    #[serde(default)]
    pub public_key: Option<String>,

    /// Referrer-Policy header value.
    #[serde(default)]
    pub referrer_policy: Option<String>,

    /// Permissions-Policy header value.
    #[serde(default)]
    pub permissions_policy: Option<String>,

    /// HSTS: max-age in seconds.
    #[serde(default)]
    pub sts_seconds: i64,

    /// HSTS: include subdomains.
    #[serde(default)]
    pub sts_include_subdomains: bool,

    /// HSTS: enable preloading.
    #[serde(default)]
    pub sts_preload: bool,

    /// Force STS header even on HTTP.
    #[serde(default)]
    pub force_sts_header: bool,

    /// Allowed hosts for host checking.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Headers used to determine the host for proxy.
    #[serde(default)]
    pub hosts_proxy_headers: Vec<String>,

    /// Redirect HTTP to HTTPS.
    #[serde(default)]
    pub ssl_redirect: bool,

    /// Use temporary (302) SSL redirect.
    #[serde(default)]
    pub ssl_temporary_redirect: bool,

    /// Host to redirect SSL requests to.
    #[serde(default)]
    pub ssl_host: Option<String>,

    /// Headers indicating SSL termination by proxy.
    #[serde(default)]
    pub ssl_proxy_headers: HashMap<String, String>,

    /// Force SSL host even if already HTTPS.
    #[serde(default)]
    pub ssl_force_host: bool,

    /// Relax security headers for development.
    #[serde(default)]
    pub is_development: bool,
}

/// HTTP Basic authentication middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthConfig {
    /// Inline user credentials (htpasswd format).
    #[serde(default)]
    pub users: Vec<String>,

    /// Path to htpasswd-format users file.
    #[serde(default)]
    pub users_file: Option<String>,

    /// Authentication realm name.
    #[serde(default)]
    pub realm: Option<String>,

    /// Header to forward the authenticated user to backends.
    #[serde(default)]
    pub header_field: Option<String>,

    /// Remove the Authorization header after successful auth.
    #[serde(default)]
    pub remove_header: bool,
}

/// HTTP Digest authentication middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DigestAuthConfig {
    /// Inline user credentials.
    #[serde(default)]
    pub users: Vec<String>,

    /// Path to users file.
    #[serde(default)]
    pub users_file: Option<String>,

    /// Authentication realm name.
    #[serde(default)]
    pub realm: Option<String>,

    /// Header to forward the authenticated user to backends.
    #[serde(default)]
    pub header_field: Option<String>,

    /// Remove the Authorization header after successful auth.
    #[serde(default)]
    pub remove_header: bool,
}

/// Forward authentication middleware (delegates auth to an external service).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAuthConfig {
    /// URL of the authentication service.
    pub address: String,

    /// Trust existing X-Forwarded-* headers.
    #[serde(default)]
    pub trust_forward_header: bool,

    /// Headers to copy from the auth response to the request.
    #[serde(default)]
    pub auth_response_headers: Vec<String>,

    /// Regex to match auth response headers to copy.
    #[serde(default)]
    pub auth_response_headers_regex: Option<String>,

    /// Headers from the original request to forward to the auth service.
    #[serde(default)]
    pub auth_request_headers: Vec<String>,

    /// TLS settings for the auth service connection.
    #[serde(default)]
    pub tls: Option<ForwardAuthTls>,

    /// Cookies from the auth response to add to the client response.
    #[serde(default)]
    pub add_auth_cookies_to_response: Vec<String>,
}

/// TLS settings for the forward auth upstream connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAuthTls {
    /// CA certificate for verifying the auth service.
    #[serde(default)]
    pub ca: Option<String>,

    /// Client certificate for mutual TLS.
    #[serde(default)]
    pub cert: Option<String>,

    /// Client private key for mutual TLS.
    #[serde(default)]
    pub key: Option<String>,

    /// Skip TLS certificate verification.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// JWT validation middleware (HMAC/RSA/EC, header/cookie/query extraction).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtConfig {
    /// Secret key for HMAC algorithms (HS256, HS384, HS512)
    #[serde(default)]
    pub secret: Option<String>,

    /// Path to public key file for RSA/EC algorithms (RS256, ES256, etc.)
    #[serde(default)]
    pub public_key: Option<String>,

    /// Algorithm to use for validation (default: HS256)
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,

    /// Issuer claim to validate (optional)
    #[serde(default)]
    pub issuer: Option<String>,

    /// Audience claim to validate (optional)
    #[serde(default)]
    pub audience: Option<String>,

    /// Header name to extract JWT from (default: Authorization)
    #[serde(default = "default_jwt_header")]
    pub header_name: String,

    /// Prefix before token in header (default: Bearer)
    #[serde(default = "default_jwt_prefix")]
    pub header_prefix: String,

    /// Query parameter name for JWT (optional, alternative to header)
    #[serde(default)]
    pub query_param: Option<String>,

    /// Cookie name for JWT (optional, alternative to header)
    #[serde(default)]
    pub cookie_name: Option<String>,

    /// Claims to forward as headers to backend (claim_name -> header_name)
    #[serde(default)]
    pub forward_claims: HashMap<String, String>,

    /// Whether to remove the Authorization header after validation
    #[serde(default)]
    pub strip_authorization_header: bool,
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_jwt_header() -> String {
    "Authorization".to_string()
}

fn default_jwt_prefix() -> String {
    "Bearer ".to_string()
}

/// Response compression middleware (gzip, brotli, zstd).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CompressConfig {
    /// Content types to exclude from compression.
    #[serde(default)]
    pub excluded_content_types: Vec<String>,

    /// Content types to include for compression.
    #[serde(default)]
    pub included_content_types: Vec<String>,

    /// Minimum response size in bytes to trigger compression.
    #[serde(default = "default_compress_min_size")]
    pub min_response_body_bytes: u64,

    /// Default encoding when client has no preference.
    #[serde(default)]
    pub default_encoding: Option<String>,

    /// Supported compression encodings in priority order.
    #[serde(default = "default_encodings")]
    pub encodings: Vec<String>,
}

fn default_compress_min_size() -> u64 {
    1024
}

fn default_encodings() -> Vec<String> {
    vec!["zstd".to_string(), "br".to_string(), "gzip".to_string()]
}

/// Automatic retry middleware with exponential backoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,

    /// Initial interval before the first retry.
    #[serde(default = "default_retry_initial_interval")]
    pub initial_interval: Duration,
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_initial_interval() -> Duration {
    Duration::from_millis(100)
}

/// Circuit breaker middleware (trips on error threshold, auto-recovers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerConfig {
    /// Trigger expression (e.g., "NetworkErrorRatio() > 0.5").
    pub expression: String,

    /// Interval for evaluating the trigger expression.
    #[serde(default = "default_cb_check_period")]
    pub check_period: Duration,

    /// Duration to stay in open (tripped) state.
    #[serde(default = "default_cb_fallback_duration")]
    pub fallback_duration: Duration,

    /// Duration of the half-open recovery state.
    #[serde(default = "default_cb_recovery_duration")]
    pub recovery_duration: Duration,

    /// HTTP status code returned when the circuit is open.
    #[serde(default = "default_cb_response_code")]
    pub response_code: u16,
}

fn default_cb_check_period() -> Duration {
    Duration::from_millis(100)
}

fn default_cb_fallback_duration() -> Duration {
    Duration::from_secs(10)
}

fn default_cb_recovery_duration() -> Duration {
    Duration::from_secs(10)
}

fn default_cb_response_code() -> u16 {
    503
}

/// Scheme redirect middleware (e.g., HTTP to HTTPS).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectSchemeConfig {
    /// Target scheme (e.g., "https").
    #[serde(default = "default_https_scheme")]
    pub scheme: String,

    /// Use permanent (301) redirect.
    #[serde(default)]
    pub permanent: bool,

    /// Override target port.
    #[serde(default)]
    pub port: Option<String>,
}

/// Regex-based URL redirect middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectRegexConfig {
    /// Regex pattern to match request URLs.
    pub regex: String,

    /// Replacement URL template (supports capture groups).
    pub replacement: String,

    /// Use permanent (301) redirect.
    #[serde(default)]
    pub permanent: bool,
}

/// Strip path prefix middleware (removes prefix before forwarding).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StripPrefixConfig {
    /// Prefixes to strip from the request path.
    pub prefixes: Vec<String>,

    /// Ensure resulting path starts with a slash.
    #[serde(default)]
    pub force_slash: bool,
}

/// Regex-based path prefix stripping middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StripPrefixRegexConfig {
    /// Regex patterns for prefixes to strip.
    pub regex: Vec<String>,
}

/// Add path prefix middleware (prepends prefix before forwarding).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPrefixConfig {
    /// Prefix to prepend to the request path.
    pub prefix: String,
}

/// Replace entire request path middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacePathConfig {
    /// Replacement path for the request.
    pub path: String,
}

/// Regex-based path replacement middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacePathRegexConfig {
    /// Regex pattern to match the request path.
    pub regex: String,

    /// Replacement path template (supports capture groups).
    pub replacement: String,
}

/// Middleware chain (composes multiple middlewares into one).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainConfig {
    /// Ordered list of middleware names to compose.
    pub middlewares: Vec<String>,
}

/// Request/response buffering middleware (memory and disk limits).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BufferingConfig {
    /// Maximum request body size in bytes.
    #[serde(default)]
    pub max_request_body_bytes: i64,

    /// Maximum request body size to buffer in memory.
    #[serde(default)]
    pub mem_request_body_bytes: i64,

    /// Maximum response body size in bytes.
    #[serde(default)]
    pub max_response_body_bytes: i64,

    /// Maximum response body size to buffer in memory.
    #[serde(default)]
    pub mem_response_body_bytes: i64,

    /// Expression to decide whether to retry based on response.
    #[serde(default)]
    pub retry_expression: Option<String>,
}

/// In-flight request limiter middleware (concurrent request cap).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InFlightReqConfig {
    /// Maximum number of concurrent in-flight requests.
    pub amount: i64,

    /// Criterion for identifying the request source.
    #[serde(default)]
    pub source_criterion: Option<SourceCriterion>,
}

/// Pass TLS client certificate info to backend via headers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PassTlsClientCertConfig {
    /// Forward the full PEM certificate to backends.
    #[serde(default)]
    pub pem: bool,

    /// Certificate fields to extract and forward.
    #[serde(default)]
    pub info: Option<TlsClientCertInfo>,
}

/// Which TLS client certificate fields to forward as headers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientCertInfo {
    /// Include certificate Not After date.
    #[serde(default)]
    pub not_after: bool,

    /// Include certificate Not Before date.
    #[serde(default)]
    pub not_before: bool,

    /// Include Subject Alternative Names.
    #[serde(default)]
    pub sans: bool,

    /// Include certificate serial number.
    #[serde(default)]
    pub serial_number: bool,

    /// Subject fields to extract.
    #[serde(default)]
    pub subject: Option<TlsClientCertSubject>,

    /// Issuer fields to extract.
    #[serde(default)]
    pub issuer: Option<TlsClientCertIssuer>,
}

/// TLS client certificate subject fields to extract.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientCertSubject {
    /// Include country (C).
    #[serde(default)]
    pub country: bool,

    /// Include state/province (ST).
    #[serde(default)]
    pub province: bool,

    /// Include locality (L).
    #[serde(default)]
    pub locality: bool,

    /// Include organization (O).
    #[serde(default)]
    pub organization: bool,

    /// Include organizational unit (OU).
    #[serde(default)]
    pub organizational_unit: bool,

    /// Include common name (CN).
    #[serde(default)]
    pub common_name: bool,

    /// Include serial number.
    #[serde(default)]
    pub serial_number: bool,

    /// Include domain component (DC).
    #[serde(default)]
    pub domain_component: bool,
}

/// TLS client certificate issuer fields to extract.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientCertIssuer {
    /// Include country (C).
    #[serde(default)]
    pub country: bool,

    /// Include state/province (ST).
    #[serde(default)]
    pub province: bool,

    /// Include locality (L).
    #[serde(default)]
    pub locality: bool,

    /// Include organization (O).
    #[serde(default)]
    pub organization: bool,

    /// Include common name (CN).
    #[serde(default)]
    pub common_name: bool,

    /// Include serial number.
    #[serde(default)]
    pub serial_number: bool,

    /// Include domain component (DC).
    #[serde(default)]
    pub domain_component: bool,
}

/// Content-Type auto-detection middleware.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContentTypeConfig {
    /// Enable automatic Content-Type detection.
    #[serde(default)]
    pub auto_detect: bool,
}

/// gRPC-Web protocol bridge middleware.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GrpcWebConfig {
    /// Allowed origins for gRPC-Web CORS.
    #[serde(default)]
    pub allow_origins: Vec<String>,
}

/// Errors middleware configuration - custom error pages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorsConfig {
    /// Status code ranges to intercept (e.g., "500-599", "404")
    pub status: Vec<String>,

    /// Service to handle error responses
    pub service: String,

    /// Query path for error page (supports {status} placeholder)
    pub query: String,
}

// =============================================================================
// TLS Configuration
// =============================================================================

/// Global TLS configuration (certificates, options, stores).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    /// TLS certificate and key pairs.
    #[serde(default)]
    pub certificates: Vec<TlsCertificate>,

    /// Named TLS protocol options.
    #[serde(default)]
    pub options: HashMap<String, TlsOptions>,

    /// Named TLS certificate stores.
    #[serde(default)]
    pub stores: HashMap<String, TlsStore>,
}

/// TLS certificate and key file pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsCertificate {
    /// Path to the certificate file.
    pub cert_file: String,

    /// Path to the private key file.
    pub key_file: String,

    /// Certificate stores this certificate belongs to.
    #[serde(default)]
    pub stores: Vec<String>,
}

/// TLS protocol options (versions, ciphers, client auth, ALPN).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsOptions {
    /// Minimum TLS version (e.g., "VersionTLS12").
    #[serde(default)]
    pub min_version: Option<String>,

    /// Maximum TLS version (e.g., "VersionTLS13").
    #[serde(default)]
    pub max_version: Option<String>,

    /// Allowed cipher suites.
    #[serde(default)]
    pub cipher_suites: Vec<String>,

    /// Preferred elliptic curves.
    #[serde(default)]
    pub curve_preferences: Vec<String>,

    /// Client certificate authentication settings.
    #[serde(default)]
    pub client_auth: Option<ClientAuth>,

    /// Require SNI to match a known certificate.
    #[serde(default)]
    pub sni_strict: bool,

    /// ALPN protocols to advertise.
    #[serde(default)]
    pub alpn_protocols: Vec<String>,

    /// Prefer server cipher suites over client preferences
    #[serde(default)]
    pub prefer_server_cipher_suites: bool,
}

/// Mutual TLS client authentication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAuth {
    /// CA certificate files for verifying client certificates.
    #[serde(default)]
    pub ca_files: Vec<String>,

    /// Client auth policy (e.g., "RequireAndVerifyClientCert").
    #[serde(default)]
    pub client_auth_type: Option<String>,
}

/// Named TLS certificate store with default certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsStore {
    /// Default certificate for this store.
    #[serde(default)]
    pub default_certificate: Option<TlsCertificate>,

    /// Auto-generated default certificate configuration.
    #[serde(default)]
    pub default_generated_cert: Option<DefaultGeneratedCert>,
}

/// Auto-generated default certificate using a cert resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultGeneratedCert {
    /// Certificate resolver name.
    pub resolver: String,

    /// Domain for the generated certificate.
    #[serde(default)]
    pub domain: Option<TlsDomain>,
}

// =============================================================================
// Certificate Resolvers (ACME)
// =============================================================================

/// Certificate resolver (currently supports ACME/Let's Encrypt).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateResolver {
    /// ACME (Let's Encrypt) configuration.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

/// ACME (Let's Encrypt) automatic certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeConfig {
    /// Contact email for the ACME account.
    pub email: String,

    /// Path to the ACME certificate storage file.
    #[serde(default = "default_acme_storage")]
    pub storage: String,

    /// ACME CA server URL (defaults to Let's Encrypt production).
    #[serde(default)]
    pub ca_server: Option<String>,

    /// Key type for generated certificates (e.g., "RSA4096", "EC256").
    #[serde(default)]
    pub key_type: Option<String>,

    /// External Account Binding credentials.
    #[serde(default)]
    pub eab: Option<ExternalAccountBinding>,

    /// Requested certificate duration.
    #[serde(default)]
    pub certificate_duration: Option<Duration>,

    /// Preferred certificate chain.
    #[serde(default)]
    pub preferred_chain: Option<String>,

    /// HTTP-01 challenge configuration.
    #[serde(default)]
    pub http_challenge: Option<HttpChallenge>,

    /// TLS-ALPN-01 challenge configuration.
    #[serde(default)]
    pub tls_challenge: Option<TlsChallenge>,

    /// DNS-01 challenge configuration.
    #[serde(default)]
    pub dns_challenge: Option<DnsChallenge>,
}

fn default_acme_storage() -> String {
    "acme.json".to_string()
}

/// ACME External Account Binding (EAB) credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccountBinding {
    /// Key identifier for EAB.
    pub kid: String,

    /// Base64-encoded HMAC key for EAB.
    pub hmac_encoded: String,
}

/// ACME HTTP-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpChallenge {
    /// Entry point to serve HTTP-01 challenges on.
    pub entry_point: String,
}

/// ACME TLS-ALPN-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsChallenge {}

/// ACME DNS-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsChallenge {
    /// DNS provider name.
    pub provider: String,

    /// Delay before checking DNS propagation.
    #[serde(default)]
    pub delay_before_check: Option<Duration>,

    /// Custom DNS resolvers for propagation checks.
    #[serde(default)]
    pub resolvers: Vec<String>,

    /// Skip DNS propagation verification.
    #[serde(default)]
    pub disable_propagation_check: bool,
}

// =============================================================================
// Cluster/HA Configuration
// =============================================================================

/// Cluster configuration for high availability
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterConfig {
    /// Enable cluster mode
    #[serde(default)]
    pub enabled: bool,

    /// Unique node identifier (auto-generated if not provided)
    #[serde(default)]
    pub node_id: Option<String>,

    /// Node advertise address (for cluster communication)
    #[serde(default)]
    pub advertise_address: Option<String>,

    /// Store configuration (Redis/Valkey)
    #[serde(default)]
    pub store: Option<StoreConfig>,

    /// Heartbeat interval for cluster membership
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: Duration,

    /// Node timeout (considered dead if no heartbeat)
    #[serde(default = "default_node_timeout")]
    pub node_timeout: Duration,

    /// Drain timeout for graceful shutdown
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: Duration,

    /// Health check leader election TTL
    #[serde(default = "default_leader_ttl")]
    pub leader_ttl: Duration,

    /// Remote configuration providers
    #[serde(default)]
    pub config_providers: Vec<ConfigProviderConfig>,
}

fn default_heartbeat_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_node_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_drain_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_leader_ttl() -> Duration {
    Duration::from_secs(15)
}

/// Store configuration (Traefik redis provider compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[derive(Default)]
pub enum StoreConfig {
    /// Local in-memory store (single node only)
    #[serde(rename = "local")]
    #[default]
    Local,

    /// Redis/Valkey distributed store
    #[serde(rename = "redis")]
    Redis(Box<RedisStoreConfig>),
}


/// Redis/Valkey store configuration
/// Compatible with Traefik's redis provider format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisStoreConfig {
    /// Redis endpoints (supports cluster and sentinel)
    /// Format: "redis://host:port" or "rediss://host:port" for TLS
    pub endpoints: Vec<String>,

    /// Password for authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Username for authentication (Redis 6+ ACL)
    #[serde(default)]
    pub username: Option<String>,

    /// Database number (default 0)
    #[serde(default)]
    pub db: i64,

    /// Key prefix for all keys
    #[serde(default = "default_key_prefix")]
    pub root_key: String,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<RedisTlsConfig>,

    /// Sentinel configuration (optional)
    #[serde(default)]
    pub sentinel: Option<RedisSentinelConfig>,

    /// Connection timeout
    #[serde(default = "default_redis_timeout")]
    pub timeout: Duration,
}

fn default_key_prefix() -> String {
    "trafficcop".to_string()
}

fn default_redis_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Redis TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RedisTlsConfig {
    /// CA certificate file path
    #[serde(default)]
    pub ca: Option<String>,

    /// Client certificate file path
    #[serde(default)]
    pub cert: Option<String>,

    /// Client key file path
    #[serde(default)]
    pub key: Option<String>,

    /// Skip TLS verification (not recommended for production)
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// Redis Sentinel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisSentinelConfig {
    /// Sentinel master name
    pub master_name: String,

    /// Sentinel password (optional)
    #[serde(default)]
    pub password: Option<String>,
}

/// Remote configuration provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ConfigProviderConfig {
    /// HTTP/HTTPS endpoint
    #[serde(rename = "http")]
    Http(HttpProviderConfig),

    /// AWS S3
    #[serde(rename = "s3")]
    S3(S3ProviderConfig),

    /// Consul KV
    #[serde(rename = "consul")]
    Consul(ConsulProviderConfig),
}

/// HTTP configuration provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpProviderConfig {
    /// URL to fetch configuration from
    pub endpoint: String,

    /// Poll interval for changes
    #[serde(default = "default_poll_interval")]
    pub poll_interval: Duration,

    /// HTTP timeout
    #[serde(default = "default_http_timeout")]
    pub timeout: Duration,

    /// HTTP headers to include
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<HttpProviderTls>,

    /// Basic auth credentials
    #[serde(default)]
    pub basic_auth: Option<BasicAuthCredentials>,
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_http_timeout() -> Duration {
    Duration::from_secs(10)
}

/// TLS settings for the HTTP configuration provider connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpProviderTls {
    /// CA certificate file path.
    #[serde(default)]
    pub ca: Option<String>,

    /// Client certificate file path.
    #[serde(default)]
    pub cert: Option<String>,

    /// Client private key file path.
    #[serde(default)]
    pub key: Option<String>,

    /// Skip TLS certificate verification.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// Basic auth credentials for HTTP provider authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthCredentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

/// S3 configuration provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3ProviderConfig {
    /// S3 bucket name
    pub bucket: String,

    /// Object key (path to config file)
    pub key: String,

    /// AWS region
    pub region: String,

    /// Poll interval for changes
    #[serde(default = "default_poll_interval")]
    pub poll_interval: Duration,

    /// Custom endpoint (for S3-compatible services)
    #[serde(default)]
    pub endpoint: Option<String>,

    /// AWS credentials (optional, uses default chain if not provided)
    #[serde(default)]
    pub credentials: Option<AwsCredentials>,
}

/// AWS credentials for S3 configuration provider access.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCredentials {
    /// AWS access key ID.
    pub access_key_id: String,
    /// AWS secret access key.
    pub secret_access_key: String,
    /// Temporary session token (for assumed roles).
    #[serde(default)]
    pub session_token: Option<String>,
}

/// Consul configuration provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsulProviderConfig {
    /// Consul endpoint
    pub endpoint: String,

    /// KV key path
    pub key: String,

    /// Consul token
    #[serde(default)]
    pub token: Option<String>,

    /// Datacenter
    #[serde(default)]
    pub datacenter: Option<String>,

    /// Use long polling (blocking queries)
    #[serde(default = "default_true")]
    pub watch: bool,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<HttpProviderTls>,
}
