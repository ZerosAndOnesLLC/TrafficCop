use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub entrypoints: HashMap<String, Entrypoint>,

    #[serde(default)]
    pub services: HashMap<String, Service>,

    #[serde(default)]
    pub routers: HashMap<String, Router>,

    #[serde(default)]
    pub middlewares: HashMap<String, MiddlewareConfig>,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_address")]
    pub address: String,
}

fn default_metrics_address() -> String {
    "0.0.0.0:9090".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoint {
    pub address: String,

    #[serde(default)]
    pub tls: Option<EntrypointTls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrypointTls {
    #[serde(default)]
    pub cert_resolver: Option<String>,

    #[serde(default)]
    pub cert_file: Option<String>,

    #[serde(default)]
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    #[serde(default)]
    pub load_balancer: LoadBalancerConfig,

    pub servers: Vec<ServerConfig>,

    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    #[serde(default)]
    pub timeouts: TimeoutConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Connection timeout in milliseconds
    #[serde(default = "default_connect_timeout")]
    pub connect_ms: u64,

    /// Request timeout in milliseconds (total time for request)
    #[serde(default = "default_request_timeout")]
    pub request_ms: u64,

    /// Idle timeout for connection pool in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_seconds: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_ms: default_connect_timeout(),
            request_ms: default_request_timeout(),
            idle_seconds: default_idle_timeout(),
        }
    }
}

fn default_connect_timeout() -> u64 {
    5000 // 5 seconds
}

fn default_request_timeout() -> u64 {
    30000 // 30 seconds
}

fn default_idle_timeout() -> u64 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoadBalancerConfig {
    #[serde(default)]
    pub strategy: LoadBalancerStrategy,

    #[serde(default)]
    pub sticky: Option<StickyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerStrategy {
    #[default]
    RoundRobin,
    Weighted,
    LeastConn,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickyConfig {
    pub cookie_name: String,

    #[serde(default = "default_cookie_ttl")]
    pub ttl_seconds: u64,
}

fn default_cookie_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,

    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_health_path")]
    pub path: String,

    #[serde(default = "default_health_interval")]
    pub interval_seconds: u64,

    #[serde(default = "default_health_timeout")]
    pub timeout_seconds: u64,

    #[serde(default = "default_health_threshold")]
    pub healthy_threshold: u32,

    #[serde(default = "default_health_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_timeout() -> u64 {
    5
}

fn default_health_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Router {
    #[serde(default)]
    pub entrypoints: Vec<String>,

    pub rule: String,

    pub service: String,

    #[serde(default)]
    pub middlewares: Vec<String>,

    #[serde(default)]
    pub priority: i32,

    #[serde(default)]
    pub tls: Option<RouterTls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterTls {
    #[serde(default)]
    pub cert_resolver: Option<String>,

    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MiddlewareConfig {
    RateLimit(RateLimitConfig),
    Headers(HeadersConfig),
    BasicAuth(BasicAuthConfig),
    ForwardAuth(ForwardAuthConfig),
    Compress(CompressConfig),
    Retry(RetryConfig),
    CircuitBreaker(CircuitBreakerConfig),
    IpFilter(IpFilterConfig),
    Cors(CorsConfig),
    RedirectScheme(RedirectSchemeConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub average: u64,

    #[serde(default)]
    pub burst: u64,

    #[serde(default = "default_rate_period")]
    pub period_seconds: u64,
}

fn default_rate_period() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersConfig {
    #[serde(default)]
    pub request_headers: HashMap<String, String>,

    #[serde(default)]
    pub response_headers: HashMap<String, String>,

    #[serde(default)]
    pub remove_request_headers: Vec<String>,

    #[serde(default)]
    pub remove_response_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub users: Vec<String>, // format: "user:password_hash"

    #[serde(default)]
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardAuthConfig {
    pub address: String,

    #[serde(default)]
    pub auth_response_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressConfig {
    #[serde(default = "default_compress_min_size")]
    pub min_response_body_bytes: u64,
}

fn default_compress_min_size() -> u64 {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_retry_attempts")]
    pub attempts: u32,

    #[serde(default = "default_retry_initial_interval")]
    pub initial_interval_ms: u64,
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_initial_interval() -> u64 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_cb_threshold")]
    pub failure_threshold: u32,

    #[serde(default = "default_cb_timeout")]
    pub recovery_timeout_seconds: u64,
}

fn default_cb_threshold() -> u32 {
    5
}

fn default_cb_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,

    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub email: String,

    #[serde(default = "default_acme_storage")]
    pub storage: String,

    #[serde(default)]
    pub ca_server: Option<String>,
}

fn default_acme_storage() -> String {
    "acme.json".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterConfig {
    /// IP addresses or CIDR ranges to allow (processed first)
    #[serde(default)]
    pub allow: Vec<String>,

    /// IP addresses or CIDR ranges to deny
    #[serde(default)]
    pub deny: Vec<String>,

    /// Default action when no rules match: "allow" or "deny"
    #[serde(default = "default_ip_filter_default")]
    pub default_action: String,
}

fn default_ip_filter_default() -> String {
    "allow".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins (use "*" for all, or specific origins)
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed headers
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,

    /// Headers to expose to the browser
    #[serde(default)]
    pub exposed_headers: Vec<String>,

    /// Allow credentials (cookies, authorization headers)
    #[serde(default)]
    pub allow_credentials: bool,

    /// Max age for preflight cache in seconds
    #[serde(default = "default_cors_max_age")]
    pub max_age_seconds: u64,
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
        "OPTIONS".to_string(),
    ]
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "Content-Type".to_string(),
        "Authorization".to_string(),
        "X-Requested-With".to_string(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectSchemeConfig {
    /// Target scheme ("https" or "http")
    #[serde(default = "default_redirect_scheme")]
    pub scheme: String,

    /// Use permanent redirect (301) or temporary (302)
    #[serde(default = "default_redirect_permanent")]
    pub permanent: bool,

    /// Port to redirect to (omit to use default port for scheme)
    #[serde(default)]
    pub port: Option<u16>,
}

fn default_redirect_scheme() -> String {
    "https".to_string()
}

fn default_redirect_permanent() -> bool {
    true
}
