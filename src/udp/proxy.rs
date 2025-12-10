use crate::udp::{UdpRouter, UdpServiceManager};
use dashmap::DashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Maximum datagram size (64KB - typical max UDP payload)
const MAX_DATAGRAM_SIZE: usize = 65535;

/// Default session timeout (how long to keep session mappings)
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// How often to clean up expired sessions
const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// UDP proxy handler
pub struct UdpProxy {
    router: Arc<UdpRouter>,
    services: Arc<UdpServiceManager>,
    /// Session tracking: maps client addr -> backend info
    sessions: Arc<DashMap<SocketAddr, UdpSession>>,
    /// Session timeout
    session_timeout: Duration,
    /// Metrics
    packets_received: AtomicU64,
    packets_sent: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
}

/// A UDP session tracking entry
struct UdpSession {
    /// Backend server address
    backend_addr: SocketAddr,
    /// Service name for this session (for metrics/logging)
    #[allow(dead_code)]
    service_name: String,
    /// Last activity time
    last_activity: Instant,
    /// Socket bound to ephemeral port for this session (for receiving responses)
    backend_socket: Arc<UdpSocket>,
}

impl UdpProxy {
    /// Create a new UDP proxy
    pub fn new(router: Arc<UdpRouter>, services: Arc<UdpServiceManager>) -> Self {
        Self {
            router,
            services,
            sessions: Arc::new(DashMap::new()),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    /// Create with custom session timeout
    pub fn with_session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Run the UDP proxy for an entrypoint
    pub async fn run(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        entrypoint: &str,
        mut shutdown: mpsc::Receiver<()>,
    ) {
        let entrypoint = entrypoint.to_string();
        let local_addr = socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

        info!(
            "UDP proxy started on {} (entrypoint: {})",
            local_addr, entrypoint
        );

        // Start session cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let session_timeout = self.session_timeout;
        let cleanup_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(SESSION_CLEANUP_INTERVAL).await;
                Self::cleanup_expired_sessions(&sessions_cleanup, session_timeout);
            }
        });

        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, client_addr)) => {
                            self.packets_received.fetch_add(1, Ordering::Relaxed);
                            self.bytes_received.fetch_add(len as u64, Ordering::Relaxed);

                            let data = buf[..len].to_vec();
                            let proxy = Arc::clone(&self);
                            let socket = Arc::clone(&socket);
                            let ep = entrypoint.clone();

                            // Handle each datagram in a separate task
                            tokio::spawn(async move {
                                if let Err(e) = proxy.handle_datagram(
                                    &socket,
                                    client_addr,
                                    data,
                                    &ep,
                                ).await {
                                    debug!("UDP: Error handling datagram from {}: {}", client_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("UDP: Error receiving datagram: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("UDP proxy shutting down (entrypoint: {})", entrypoint);
                    break;
                }
            }
        }

        cleanup_handle.abort();
    }

    /// Handle an incoming UDP datagram
    async fn handle_datagram(
        &self,
        _client_socket: &UdpSocket,
        client_addr: SocketAddr,
        data: Vec<u8>,
        entrypoint: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check for existing session
        if let Some(mut session) = self.sessions.get_mut(&client_addr) {
            // Update last activity
            session.last_activity = Instant::now();

            // Forward to existing backend
            let backend_socket = Arc::clone(&session.backend_socket);
            let backend_addr = session.backend_addr;
            drop(session); // Release lock

            self.forward_to_backend(
                client_addr,
                &backend_socket,
                backend_addr,
                &data,
            )
            .await?;

            return Ok(());
        }

        // No existing session - route the datagram
        let route = match self.router.match_datagram(entrypoint, Some(client_addr)) {
            Some(r) => r,
            None => {
                warn!(
                    "UDP: No route found for datagram from {} on entrypoint '{}'",
                    client_addr, entrypoint
                );
                return Ok(());
            }
        };

        // Get the backend service
        let service = match self.services.get_service(&route.service) {
            Some(s) => s,
            None => {
                error!("UDP: Service '{}' not found", route.service);
                return Ok(());
            }
        };

        // Use consistent hashing based on client IP for session affinity
        let hash = Self::hash_addr(&client_addr);
        let backend = match service.get_server_by_hash(hash) {
            Some(b) => b,
            None => {
                error!("UDP: No healthy backends for service '{}'", route.service);
                return Ok(());
            }
        };

        // Parse backend address
        let backend_addr: SocketAddr = match backend.address.parse() {
            Ok(addr) => addr,
            Err(e) => {
                error!("UDP: Invalid backend address '{}': {}", backend.address, e);
                return Ok(());
            }
        };

        debug!(
            "UDP: Routing {} -> {} (route: {}, service: {})",
            client_addr, backend_addr, route.name, route.service
        );

        // Create a new socket for this session (to receive responses)
        let backend_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        // Store session
        let session = UdpSession {
            backend_addr,
            service_name: route.service.clone(),
            last_activity: Instant::now(),
            backend_socket: Arc::clone(&backend_socket),
        };
        self.sessions.insert(client_addr, session);

        // Forward the datagram and start listening for response
        self.forward_to_backend(
            client_addr,
            &backend_socket,
            backend_addr,
            &data,
        )
        .await?;

        // Spawn task to listen for backend responses
        let proxy_metrics = self.clone_metrics();
        let sessions = Arc::clone(&self.sessions);
        let session_timeout = self.session_timeout;

        tokio::spawn(async move {
            Self::listen_for_responses(
                backend_socket,
                client_addr,
                sessions,
                session_timeout,
                proxy_metrics,
            )
            .await;
        });

        Ok(())
    }

    /// Forward a datagram to the backend
    async fn forward_to_backend(
        &self,
        client_addr: SocketAddr,
        backend_socket: &UdpSocket,
        backend_addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Send to backend
        backend_socket.send_to(data, backend_addr).await?;
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);

        debug!(
            "UDP: Forwarded {} bytes from {} to {}",
            data.len(),
            client_addr,
            backend_addr
        );

        Ok(())
    }

    /// Listen for responses from the backend and forward to client
    async fn listen_for_responses(
        backend_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        sessions: Arc<DashMap<SocketAddr, UdpSession>>,
        session_timeout: Duration,
        proxy: UdpProxyMetrics,
    ) {
        // Bind a socket to send responses back to client
        let response_socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                error!("UDP: Failed to bind response socket: {}", e);
                return;
            }
        };

        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            // Check if session still exists
            if !sessions.contains_key(&client_addr) {
                debug!("UDP: Session for {} no longer exists, stopping listener", client_addr);
                break;
            }

            // Wait for response with timeout
            let result = tokio::time::timeout(
                session_timeout,
                backend_socket.recv_from(&mut buf),
            )
            .await;

            match result {
                Ok(Ok((len, from_addr))) => {
                    proxy.packets_received.fetch_add(1, Ordering::Relaxed);
                    proxy.bytes_received.fetch_add(len as u64, Ordering::Relaxed);

                    // Update session activity
                    if let Some(mut session) = sessions.get_mut(&client_addr) {
                        session.last_activity = Instant::now();
                    }

                    // Send response back to client
                    match response_socket.send_to(&buf[..len], client_addr).await {
                        Ok(_) => {
                            proxy.packets_sent.fetch_add(1, Ordering::Relaxed);
                            proxy.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);

                            debug!(
                                "UDP: Forwarded {} bytes response from {} to {}",
                                len, from_addr, client_addr
                            );
                        }
                        Err(e) => {
                            debug!("UDP: Failed to send response to {}: {}", client_addr, e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug!("UDP: Error receiving from backend for {}: {}", client_addr, e);
                    break;
                }
                Err(_) => {
                    // Timeout - session may have expired
                    debug!("UDP: Response timeout for session {}", client_addr);
                    break;
                }
            }
        }

        // Clean up session
        sessions.remove(&client_addr);
        debug!("UDP: Cleaned up session for {}", client_addr);
    }

    /// Clean up expired sessions
    fn cleanup_expired_sessions(
        sessions: &DashMap<SocketAddr, UdpSession>,
        timeout: Duration,
    ) {
        let now = Instant::now();
        let mut expired = Vec::new();

        for entry in sessions.iter() {
            if now.duration_since(entry.last_activity) > timeout {
                expired.push(*entry.key());
            }
        }

        for addr in expired {
            sessions.remove(&addr);
            debug!("UDP: Expired session for {}", addr);
        }
    }

    /// Hash a socket address for consistent routing
    fn hash_addr(addr: &SocketAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        addr.ip().hash(&mut hasher);
        hasher.finish() as usize
    }

    /// Clone just the metrics counters for the response listener
    fn clone_metrics(&self) -> UdpProxyMetrics {
        UdpProxyMetrics {
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    /// Get metrics
    pub fn metrics(&self) -> UdpProxyStats {
        UdpProxyStats {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            active_sessions: self.sessions.len(),
        }
    }
}

/// Metrics counters for spawned tasks
struct UdpProxyMetrics {
    packets_received: AtomicU64,
    packets_sent: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
}

/// UDP proxy statistics
#[derive(Debug, Clone)]
pub struct UdpProxyStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub active_sessions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_addr_consistency() {
        let addr1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.1:54321".parse().unwrap();
        let addr3: SocketAddr = "192.168.1.2:12345".parse().unwrap();

        // Same IP should hash the same (we hash by IP only for session affinity)
        assert_eq!(UdpProxy::hash_addr(&addr1), UdpProxy::hash_addr(&addr2));

        // Different IPs should (probably) hash differently
        assert_ne!(UdpProxy::hash_addr(&addr1), UdpProxy::hash_addr(&addr3));
    }
}
