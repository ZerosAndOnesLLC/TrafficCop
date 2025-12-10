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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpConfig {
    #[serde(default)]
    pub routers: HashMap<String, Router>,

    #[serde(default)]
    pub services: HashMap<String, Service>,

    #[serde(default)]
    pub middlewares: HashMap<String, MiddlewareConfig>,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsConfig {
    #[serde(default)]
    pub prometheus: Option<PrometheusConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusConfig {
    #[serde(default = "default_metrics_address")]
    pub address: String,

    #[serde(default)]
    pub add_entry_points_labels: bool,

    #[serde(default)]
    pub add_services_labels: bool,
}

fn default_metrics_address() -> String {
    ":9090".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    #[serde(default)]
    pub dashboard: bool,

    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    #[serde(default)]
    pub level: Option<String>,

    #[serde(default)]
    pub format: Option<String>,

    #[serde(default)]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogConfig {
    #[serde(default)]
    pub file_path: Option<String>,

    #[serde(default)]
    pub format: Option<String>,

    #[serde(default)]
    pub bufferingsize: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProvidersConfig {
    #[serde(default)]
    pub file: Option<FileProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileProviderConfig {
    #[serde(default)]
    pub filename: Option<String>,

    #[serde(default)]
    pub directory: Option<String>,

    #[serde(default = "default_watch")]
    pub watch: bool,
}

fn default_watch() -> bool {
    true
}

// =============================================================================
// Entry Points
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryPoint {
    pub address: String,

    #[serde(default)]
    pub as_default: bool,

    #[serde(default)]
    pub http: Option<EntryPointHttp>,

    #[serde(default)]
    pub forwarded_headers: Option<ForwardedHeaders>,

    #[serde(default)]
    pub transport: Option<EntryPointTransport>,

    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointHttp {
    #[serde(default)]
    pub redirections: Option<EntryPointRedirections>,

    #[serde(default)]
    pub tls: Option<EntryPointTls>,

    #[serde(default)]
    pub middlewares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointRedirections {
    #[serde(default)]
    pub entry_point: Option<RedirectEntryPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectEntryPoint {
    pub to: String,

    #[serde(default = "default_https_scheme")]
    pub scheme: String,

    #[serde(default = "default_true")]
    pub permanent: bool,

    #[serde(default)]
    pub priority: Option<i32>,
}

fn default_https_scheme() -> String {
    "https".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointTls {
    #[serde(default)]
    pub options: Option<String>,

    #[serde(default)]
    pub cert_resolver: Option<String>,

    #[serde(default)]
    pub domains: Vec<TlsDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ForwardedHeaders {
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPointTransport {
    #[serde(default)]
    pub responding_timeouts: Option<RespondingTimeouts>,

    #[serde(default)]
    pub life_cycle: Option<LifeCycle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RespondingTimeouts {
    #[serde(default = "default_read_timeout")]
    pub read_timeout: Duration,

    #[serde(default)]
    pub write_timeout: Duration,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifeCycle {
    #[serde(default = "default_grace_timeout")]
    pub grace_time_out: Duration,

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProtocol {
    #[serde(default)]
    pub trusted_ips: Vec<String>,

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<LoadBalancerService>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weighted: Option<WeightedService>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirroring: Option<MirroringService>,
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
        } else {
            "unknown"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancerService {
    pub servers: Vec<Server>,

    #[serde(default = "default_true")]
    pub pass_host_header: bool,

    #[serde(default)]
    pub sticky: Option<Sticky>,

    #[serde(default)]
    pub health_check: Option<HealthCheck>,

    #[serde(default)]
    pub servers_transport: Option<String>,

    #[serde(default)]
    pub response_forwarding: Option<ResponseForwarding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub url: String,

    #[serde(default = "default_weight")]
    pub weight: u32,

    #[serde(default)]
    pub preserve_path: bool,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sticky {
    #[serde(default)]
    pub cookie: Option<StickyCookie>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StickyCookie {
    pub name: String,

    #[serde(default)]
    pub secure: bool,

    #[serde(default)]
    pub http_only: bool,

    #[serde(default)]
    pub same_site: Option<String>,

    #[serde(default)]
    pub max_age: Option<i64>,

    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    #[serde(default = "default_health_path")]
    pub path: String,

    #[serde(default = "default_health_interval")]
    pub interval: Duration,

    #[serde(default = "default_health_timeout")]
    pub timeout: Duration,

    #[serde(default)]
    pub scheme: Option<String>,

    #[serde(default)]
    pub method: Option<String>,

    #[serde(default)]
    pub status: Option<u16>,

    #[serde(default)]
    pub hostname: Option<String>,

    #[serde(default)]
    pub headers: HashMap<String, String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResponseForwarding {
    #[serde(default)]
    pub flush_interval: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedService {
    pub services: Vec<WeightedServiceRef>,

    #[serde(default)]
    pub sticky: Option<Sticky>,

    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedServiceRef {
    pub name: String,

    #[serde(default = "default_weight")]
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirroringService {
    pub service: String,

    #[serde(default)]
    pub mirrors: Vec<MirrorRef>,

    #[serde(default)]
    pub max_body_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorRef {
    pub name: String,

    #[serde(default = "default_mirror_percent")]
    pub percent: u32,
}

fn default_mirror_percent() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServersTransport {
    #[serde(default)]
    pub server_name: Option<String>,

    #[serde(default)]
    pub insecure_skip_verify: bool,

    #[serde(default)]
    pub root_cas: Vec<String>,

    #[serde(default)]
    pub certificates: Vec<TlsCertificate>,

    #[serde(default = "default_max_idle_conns")]
    pub max_idle_conns_per_host: i32,

    #[serde(default)]
    pub forwarding_timeouts: Option<ForwardingTimeouts>,

    #[serde(default)]
    pub disable_http2: bool,

    #[serde(default)]
    pub peer_cert_uri: Option<String>,
}

fn default_max_idle_conns() -> i32 {
    200
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardingTimeouts {
    #[serde(default = "default_dial_timeout")]
    pub dial_timeout: Duration,

    #[serde(default)]
    pub response_header_timeout: Duration,

    #[serde(default = "default_idle_conn_timeout")]
    pub idle_conn_timeout: Duration,

    #[serde(default)]
    pub read_idle_timeout: Duration,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Router {
    #[serde(default)]
    pub entry_points: Vec<String>,

    pub rule: String,

    pub service: String,

    #[serde(default)]
    pub middlewares: Vec<String>,

    #[serde(default)]
    pub priority: i32,

    #[serde(default)]
    pub tls: Option<RouterTls>,

    #[serde(default)]
    pub observability: Option<RouterObservability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouterTls {
    #[serde(default)]
    pub cert_resolver: Option<String>,

    #[serde(default)]
    pub domains: Vec<TlsDomain>,

    #[serde(default)]
    pub options: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsDomain {
    pub main: String,

    #[serde(default)]
    pub sans: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouterObservability {
    #[serde(default = "default_true")]
    pub access_logs: bool,

    #[serde(default = "default_true")]
    pub tracing: bool,

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_allow_list: Option<IpAllowListConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_deny_list: Option<IpDenyListConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeadersConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_auth: Option<DigestAuthConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<ForwardAuthConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<CompressConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_scheme: Option<RedirectSchemeConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_regex: Option<RedirectRegexConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_prefix: Option<StripPrefixConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_prefix_regex: Option<StripPrefixRegexConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_prefix: Option<AddPrefixConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_path: Option<ReplacePathConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_path_regex: Option<ReplacePathRegexConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffering: Option<BufferingConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_flight_req: Option<InFlightReqConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_tls_client_cert: Option<PassTlsClientCertConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<ContentTypeConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_web: Option<GrpcWebConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtConfig>,
}

impl MiddlewareConfig {
    /// Get the middleware type name
    pub fn middleware_type(&self) -> &'static str {
        if self.rate_limit.is_some() { "rateLimit" }
        else if self.ip_allow_list.is_some() { "ipAllowList" }
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
        else { "unknown" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    pub average: u64,

    #[serde(default)]
    pub burst: u64,

    #[serde(default = "default_rate_period")]
    pub period: Duration,

    #[serde(default)]
    pub source_criterion: Option<SourceCriterion>,
}

fn default_rate_period() -> Duration {
    Duration::from_secs(1)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceCriterion {
    #[serde(default)]
    pub ip_strategy: Option<IpStrategy>,

    #[serde(default)]
    pub request_header_name: Option<String>,

    #[serde(default)]
    pub request_host: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IpStrategy {
    #[serde(default)]
    pub depth: u32,

    #[serde(default)]
    pub excluded_ips: Vec<String>,

    #[serde(default)]
    pub ipv6_subnet: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAllowListConfig {
    pub source_range: Vec<String>,

    #[serde(default)]
    pub ip_strategy: Option<IpStrategy>,

    #[serde(default)]
    pub reject_status_code: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpDenyListConfig {
    pub source_range: Vec<String>,

    #[serde(default)]
    pub ip_strategy: Option<IpStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HeadersConfig {
    // Custom headers
    #[serde(default)]
    pub custom_request_headers: HashMap<String, String>,

    #[serde(default)]
    pub custom_response_headers: HashMap<String, String>,

    // CORS
    #[serde(default)]
    pub access_control_allow_credentials: bool,

    #[serde(default)]
    pub access_control_allow_headers: Vec<String>,

    #[serde(default)]
    pub access_control_allow_methods: Vec<String>,

    #[serde(default)]
    pub access_control_allow_origin_list: Vec<String>,

    #[serde(default)]
    pub access_control_allow_origin_list_regex: Vec<String>,

    #[serde(default)]
    pub access_control_expose_headers: Vec<String>,

    #[serde(default)]
    pub access_control_max_age: Option<i64>,

    #[serde(default)]
    pub add_vary_header: bool,

    // Security headers
    #[serde(default)]
    pub frame_deny: bool,

    #[serde(default)]
    pub custom_frame_options_value: Option<String>,

    #[serde(default)]
    pub content_type_nosniff: bool,

    #[serde(default)]
    pub browser_xss_filter: bool,

    #[serde(default)]
    pub custom_browser_xss_value: Option<String>,

    #[serde(default)]
    pub content_security_policy: Option<String>,

    #[serde(default)]
    pub content_security_policy_report_only: Option<String>,

    #[serde(default)]
    pub public_key: Option<String>,

    #[serde(default)]
    pub referrer_policy: Option<String>,

    #[serde(default)]
    pub permissions_policy: Option<String>,

    // HSTS
    #[serde(default)]
    pub sts_seconds: i64,

    #[serde(default)]
    pub sts_include_subdomains: bool,

    #[serde(default)]
    pub sts_preload: bool,

    #[serde(default)]
    pub force_sts_header: bool,

    // Host
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    #[serde(default)]
    pub hosts_proxy_headers: Vec<String>,

    #[serde(default)]
    pub ssl_redirect: bool,

    #[serde(default)]
    pub ssl_temporary_redirect: bool,

    #[serde(default)]
    pub ssl_host: Option<String>,

    #[serde(default)]
    pub ssl_proxy_headers: HashMap<String, String>,

    #[serde(default)]
    pub ssl_force_host: bool,

    #[serde(default)]
    pub is_development: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthConfig {
    #[serde(default)]
    pub users: Vec<String>,

    #[serde(default)]
    pub users_file: Option<String>,

    #[serde(default)]
    pub realm: Option<String>,

    #[serde(default)]
    pub header_field: Option<String>,

    #[serde(default)]
    pub remove_header: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DigestAuthConfig {
    #[serde(default)]
    pub users: Vec<String>,

    #[serde(default)]
    pub users_file: Option<String>,

    #[serde(default)]
    pub realm: Option<String>,

    #[serde(default)]
    pub header_field: Option<String>,

    #[serde(default)]
    pub remove_header: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAuthConfig {
    pub address: String,

    #[serde(default)]
    pub trust_forward_header: bool,

    #[serde(default)]
    pub auth_response_headers: Vec<String>,

    #[serde(default)]
    pub auth_response_headers_regex: Option<String>,

    #[serde(default)]
    pub auth_request_headers: Vec<String>,

    #[serde(default)]
    pub tls: Option<ForwardAuthTls>,

    #[serde(default)]
    pub add_auth_cookies_to_response: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAuthTls {
    #[serde(default)]
    pub ca: Option<String>,

    #[serde(default)]
    pub cert: Option<String>,

    #[serde(default)]
    pub key: Option<String>,

    #[serde(default)]
    pub insecure_skip_verify: bool,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CompressConfig {
    #[serde(default)]
    pub excluded_content_types: Vec<String>,

    #[serde(default)]
    pub included_content_types: Vec<String>,

    #[serde(default = "default_compress_min_size")]
    pub min_response_body_bytes: u64,

    #[serde(default)]
    pub default_encoding: Option<String>,

    #[serde(default = "default_encodings")]
    pub encodings: Vec<String>,
}

fn default_compress_min_size() -> u64 {
    1024
}

fn default_encodings() -> Vec<String> {
    vec!["zstd".to_string(), "br".to_string(), "gzip".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryConfig {
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,

    #[serde(default = "default_retry_initial_interval")]
    pub initial_interval: Duration,
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_initial_interval() -> Duration {
    Duration::from_millis(100)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerConfig {
    pub expression: String,

    #[serde(default = "default_cb_check_period")]
    pub check_period: Duration,

    #[serde(default = "default_cb_fallback_duration")]
    pub fallback_duration: Duration,

    #[serde(default = "default_cb_recovery_duration")]
    pub recovery_duration: Duration,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectSchemeConfig {
    #[serde(default = "default_https_scheme")]
    pub scheme: String,

    #[serde(default)]
    pub permanent: bool,

    #[serde(default)]
    pub port: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectRegexConfig {
    pub regex: String,

    pub replacement: String,

    #[serde(default)]
    pub permanent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StripPrefixConfig {
    pub prefixes: Vec<String>,

    #[serde(default)]
    pub force_slash: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StripPrefixRegexConfig {
    pub regex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPrefixConfig {
    pub prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacePathConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacePathRegexConfig {
    pub regex: String,

    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainConfig {
    pub middlewares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BufferingConfig {
    #[serde(default)]
    pub max_request_body_bytes: i64,

    #[serde(default)]
    pub mem_request_body_bytes: i64,

    #[serde(default)]
    pub max_response_body_bytes: i64,

    #[serde(default)]
    pub mem_response_body_bytes: i64,

    #[serde(default)]
    pub retry_expression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InFlightReqConfig {
    pub amount: i64,

    #[serde(default)]
    pub source_criterion: Option<SourceCriterion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PassTlsClientCertConfig {
    #[serde(default)]
    pub pem: bool,

    #[serde(default)]
    pub info: Option<TlsClientCertInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientCertInfo {
    #[serde(default)]
    pub not_after: bool,

    #[serde(default)]
    pub not_before: bool,

    #[serde(default)]
    pub sans: bool,

    #[serde(default)]
    pub serial_number: bool,

    #[serde(default)]
    pub subject: Option<TlsClientCertSubject>,

    #[serde(default)]
    pub issuer: Option<TlsClientCertIssuer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientCertSubject {
    #[serde(default)]
    pub country: bool,

    #[serde(default)]
    pub province: bool,

    #[serde(default)]
    pub locality: bool,

    #[serde(default)]
    pub organization: bool,

    #[serde(default)]
    pub organizational_unit: bool,

    #[serde(default)]
    pub common_name: bool,

    #[serde(default)]
    pub serial_number: bool,

    #[serde(default)]
    pub domain_component: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientCertIssuer {
    #[serde(default)]
    pub country: bool,

    #[serde(default)]
    pub province: bool,

    #[serde(default)]
    pub locality: bool,

    #[serde(default)]
    pub organization: bool,

    #[serde(default)]
    pub common_name: bool,

    #[serde(default)]
    pub serial_number: bool,

    #[serde(default)]
    pub domain_component: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContentTypeConfig {
    #[serde(default)]
    pub auto_detect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GrpcWebConfig {
    #[serde(default)]
    pub allow_origins: Vec<String>,
}

// =============================================================================
// TLS Configuration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    #[serde(default)]
    pub certificates: Vec<TlsCertificate>,

    #[serde(default)]
    pub options: HashMap<String, TlsOptions>,

    #[serde(default)]
    pub stores: HashMap<String, TlsStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsCertificate {
    pub cert_file: String,

    pub key_file: String,

    #[serde(default)]
    pub stores: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsOptions {
    #[serde(default)]
    pub min_version: Option<String>,

    #[serde(default)]
    pub max_version: Option<String>,

    #[serde(default)]
    pub cipher_suites: Vec<String>,

    #[serde(default)]
    pub curve_preferences: Vec<String>,

    #[serde(default)]
    pub client_auth: Option<ClientAuth>,

    #[serde(default)]
    pub sni_strict: bool,

    #[serde(default)]
    pub alpn_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAuth {
    #[serde(default)]
    pub ca_files: Vec<String>,

    #[serde(default)]
    pub client_auth_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsStore {
    #[serde(default)]
    pub default_certificate: Option<TlsCertificate>,

    #[serde(default)]
    pub default_generated_cert: Option<DefaultGeneratedCert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultGeneratedCert {
    pub resolver: String,

    #[serde(default)]
    pub domain: Option<TlsDomain>,
}

// =============================================================================
// Certificate Resolvers (ACME)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateResolver {
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeConfig {
    pub email: String,

    #[serde(default = "default_acme_storage")]
    pub storage: String,

    #[serde(default)]
    pub ca_server: Option<String>,

    #[serde(default)]
    pub key_type: Option<String>,

    #[serde(default)]
    pub eab: Option<ExternalAccountBinding>,

    #[serde(default)]
    pub certificate_duration: Option<Duration>,

    #[serde(default)]
    pub preferred_chain: Option<String>,

    // Challenge types - only one should be set
    #[serde(default)]
    pub http_challenge: Option<HttpChallenge>,

    #[serde(default)]
    pub tls_challenge: Option<TlsChallenge>,

    #[serde(default)]
    pub dns_challenge: Option<DnsChallenge>,
}

fn default_acme_storage() -> String {
    "acme.json".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccountBinding {
    pub kid: String,

    pub hmac_encoded: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpChallenge {
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TlsChallenge {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsChallenge {
    pub provider: String,

    #[serde(default)]
    pub delay_before_check: Option<Duration>,

    #[serde(default)]
    pub resolvers: Vec<String>,

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
pub enum StoreConfig {
    /// Local in-memory store (single node only)
    #[serde(rename = "local")]
    Local,

    /// Redis/Valkey distributed store
    #[serde(rename = "redis")]
    Redis(RedisStoreConfig),
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig::Local
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpProviderTls {
    #[serde(default)]
    pub ca: Option<String>,

    #[serde(default)]
    pub cert: Option<String>,

    #[serde(default)]
    pub key: Option<String>,

    #[serde(default)]
    pub insecure_skip_verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthCredentials {
    pub username: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
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
