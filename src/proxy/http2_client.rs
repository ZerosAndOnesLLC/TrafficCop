use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

/// HTTP/2 connection pool for upstream connections
/// Maintains persistent HTTP/2 connections with multiplexing support
pub struct Http2ConnectionPool {
    /// Map of host -> connection
    connections: RwLock<HashMap<String, Arc<Http2Connection>>>,
}

struct Http2Connection {
    sender: Mutex<Option<SendRequest<BoxBody<Bytes, hyper::Error>>>>,
}

impl Http2ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Send a request using HTTP/2
    pub async fn send_request(
        &self,
        host: &str,
        port: u16,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<Response<hyper::body::Incoming>, Http2Error> {
        // Get or create connection first, before consuming the request
        let conn = self.get_or_create_connection(host, port).await?;

        match conn.send(req).await {
            Ok(response) => Ok(response),
            Err(Http2Error::ConnectionClosed) => {
                // Connection closed, remove it so next request creates a new one
                self.remove_connection(host, port).await;
                Err(Http2Error::ConnectionClosed)
            }
            Err(e) => Err(e),
        }
    }

    /// Get existing connection or create a new one
    async fn get_or_create_connection(&self, host: &str, port: u16) -> Result<Arc<Http2Connection>, Http2Error> {
        let key = format!("{}:{}", host, port);

        // Check for existing connection
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&key) {
                if conn.is_ready().await {
                    return Ok(Arc::clone(conn));
                }
            }
        }

        // Create new connection
        let conn = self.create_connection(host, port).await?;

        // Store connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(key, Arc::clone(&conn));
        }

        Ok(conn)
    }

    /// Create a new HTTP/2 connection
    async fn create_connection(&self, host: &str, port: u16) -> Result<Arc<Http2Connection>, Http2Error> {
        let addr = format!("{}:{}", host, port);

        debug!("Creating new HTTP/2 connection to {}", addr);

        let stream = TcpStream::connect(&addr).await.map_err(Http2Error::Connect)?;

        // Set TCP options
        stream.set_nodelay(true).ok();

        let io = TokioIo::new(stream);

        // Perform HTTP/2 handshake
        let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(Http2Error::Handshake)?;

        // Spawn connection driver
        let addr_clone = addr.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP/2 connection to {} closed: {}", addr_clone, e);
            }
        });

        Ok(Arc::new(Http2Connection {
            sender: Mutex::new(Some(sender)),
        }))
    }

    /// Remove a connection from the pool
    pub async fn remove_connection(&self, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        let mut connections = self.connections.write().await;
        connections.remove(&key);
    }

    /// Get pool statistics
    pub async fn stats(&self) -> Http2PoolStats {
        let connections = self.connections.read().await;
        Http2PoolStats {
            connection_count: connections.len(),
        }
    }
}

impl Default for Http2ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Connection {
    /// Check if the connection is ready to send requests
    async fn is_ready(&self) -> bool {
        let sender_guard = self.sender.lock().await;
        if let Some(ref sender) = *sender_guard {
            sender.is_ready()
        } else {
            false
        }
    }

    /// Send request (must have valid sender)
    async fn send(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<Response<hyper::body::Incoming>, Http2Error> {
        let mut sender_guard = self.sender.lock().await;

        if let Some(ref mut sender) = *sender_guard {
            sender.ready().await.map_err(Http2Error::Ready)?;
            sender.send_request(req).await.map_err(Http2Error::Request)
        } else {
            Err(Http2Error::ConnectionClosed)
        }
    }
}

/// HTTP/2 pool statistics
pub struct Http2PoolStats {
    pub connection_count: usize,
}

/// HTTP/2 connection errors
#[derive(Debug)]
pub enum Http2Error {
    Connect(std::io::Error),
    Handshake(hyper::Error),
    Ready(hyper::Error),
    Request(hyper::Error),
    ConnectionClosed,
}

impl std::fmt::Display for Http2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Http2Error::Connect(e) => write!(f, "Connection failed: {}", e),
            Http2Error::Handshake(e) => write!(f, "HTTP/2 handshake failed: {}", e),
            Http2Error::Ready(e) => write!(f, "Connection not ready: {}", e),
            Http2Error::Request(e) => write!(f, "Request failed: {}", e),
            Http2Error::ConnectionClosed => write!(f, "Connection closed"),
        }
    }
}

impl std::error::Error for Http2Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = Http2ConnectionPool::new();
        assert!(pool.connections.try_read().is_ok());
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let pool = Http2ConnectionPool::new();
        let stats = pool.stats().await;
        assert_eq!(stats.connection_count, 0);
    }
}
