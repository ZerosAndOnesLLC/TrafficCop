use crate::tcp::{TcpRouter, TcpServiceManager};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Buffer size for TCP proxying
const BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Timeout for initial connection to backend
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading SNI from TLS ClientHello (if needed)
const SNI_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP proxy handler
pub struct TcpProxy {
    router: Arc<TcpRouter>,
    services: Arc<TcpServiceManager>,
}

impl TcpProxy {
    /// Create a new TCP proxy
    pub fn new(router: Arc<TcpRouter>, services: Arc<TcpServiceManager>) -> Self {
        Self { router, services }
    }

    /// Handle an incoming TCP connection
    pub async fn handle_connection(
        &self,
        mut client: TcpStream,
        client_addr: SocketAddr,
        entrypoint: &str,
    ) {
        // Try to extract SNI from TLS ClientHello if this looks like TLS
        let (sni, initial_data) = match self.peek_tls_sni(&mut client).await {
            Ok((sni, data)) => (sni, data),
            Err(e) => {
                debug!("TCP: Failed to peek TLS SNI: {}", e);
                (None, Vec::new())
            }
        };

        debug!(
            "TCP: Connection from {} (entrypoint: {}, SNI: {:?})",
            client_addr, entrypoint, sni
        );

        // Find matching route
        let route = match self.router.match_connection(entrypoint, sni.as_deref(), Some(client_addr)) {
            Some(r) => r,
            None => {
                warn!(
                    "TCP: No route found for connection from {} (SNI: {:?})",
                    client_addr, sni
                );
                return;
            }
        };

        // Get the backend service
        let service = match self.services.get_service(&route.service) {
            Some(s) => s,
            None => {
                error!("TCP: Service '{}' not found", route.service);
                return;
            }
        };

        // Get a backend server
        let backend = match service.next_server() {
            Some(b) => b,
            None => {
                error!("TCP: No healthy backends for service '{}'", route.service);
                return;
            }
        };

        debug!(
            "TCP: Routing {} -> {} (route: {}, service: {})",
            client_addr, backend.address, route.name, route.service
        );

        // Connect to backend
        let backend_stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&backend.address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!("TCP: Failed to connect to backend {}: {}", backend.address, e);
                return;
            }
            Err(_) => {
                error!(
                    "TCP: Connection timeout to backend {} ({}s)",
                    backend.address,
                    CONNECT_TIMEOUT.as_secs()
                );
                return;
            }
        };

        // Set TCP nodelay for lower latency
        let _ = client.set_nodelay(true);
        let _ = backend_stream.set_nodelay(true);

        // If we have initial data (from SNI peeking), we need to write it first
        // This is handled by the proxy function

        // Start bidirectional proxy
        if let Err(e) = self.proxy_bidirectional(client, backend_stream, initial_data).await {
            debug!("TCP: Proxy ended for {}: {}", client_addr, e);
        }

        debug!("TCP: Connection closed for {}", client_addr);
    }

    /// Peek at the TLS ClientHello to extract SNI
    /// Returns (Option<SNI>, initial_data)
    async fn peek_tls_sni(&self, stream: &mut TcpStream) -> std::io::Result<(Option<String>, Vec<u8>)> {
        // Read initial bytes to check for TLS
        let mut buf = vec![0u8; 1024];

        // Use timeout for reading
        let n = match timeout(SNI_READ_TIMEOUT, stream.peek(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Timeout - not TLS or slow client
                return Ok((None, Vec::new()));
            }
        };

        if n < 5 {
            return Ok((None, Vec::new()));
        }

        // Check if this looks like TLS
        if buf[0] != 0x16 {
            // Not a TLS handshake
            return Ok((None, Vec::new()));
        }

        // Parse TLS record header
        let content_type = buf[0];
        let _version_major = buf[1];
        let _version_minor = buf[2];
        let record_length = ((buf[3] as usize) << 8) | (buf[4] as usize);

        if content_type != 0x16 {
            // Not a handshake record
            return Ok((None, Vec::new()));
        }

        // Read full ClientHello if needed
        let total_needed = 5 + record_length;
        if total_needed > buf.len() {
            buf.resize(total_needed.min(16384), 0);
        }

        let n = match timeout(SNI_READ_TIMEOUT, stream.peek(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok((None, Vec::new())),
        };

        if n < total_needed.min(buf.len()) {
            return Ok((None, Vec::new()));
        }

        // Parse ClientHello for SNI
        let sni = self.parse_sni(&buf[5..]);

        Ok((sni, Vec::new())) // No initial data since we used peek()
    }

    /// Parse SNI from TLS ClientHello
    fn parse_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 38 {
            return None;
        }

        // Handshake type (should be ClientHello = 1)
        if data[0] != 0x01 {
            return None;
        }

        // Skip: handshake type (1), length (3), version (2), random (32)
        let mut offset = 1 + 3 + 2 + 32;

        if offset >= data.len() {
            return None;
        }

        // Session ID length
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > data.len() {
            return None;
        }

        // Cipher suites length
        let cipher_suites_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2 + cipher_suites_len;

        if offset + 1 > data.len() {
            return None;
        }

        // Compression methods length
        let compression_len = data[offset] as usize;
        offset += 1 + compression_len;

        if offset + 2 > data.len() {
            return None;
        }

        // Extensions length
        let extensions_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2;

        let extensions_end = offset + extensions_len;
        if extensions_end > data.len() {
            return None;
        }

        // Parse extensions looking for SNI (type 0x0000)
        while offset + 4 <= extensions_end {
            let ext_type = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
            let ext_len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
            offset += 4;

            if ext_type == 0x0000 {
                // SNI extension
                return self.parse_sni_extension(&data[offset..offset + ext_len]);
            }

            offset += ext_len;
        }

        None
    }

    /// Parse SNI extension data
    fn parse_sni_extension(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // SNI list length
        let _list_len = ((data[0] as usize) << 8) | (data[1] as usize);

        // First entry
        let name_type = data[2];
        if name_type != 0 {
            // Not a hostname
            return None;
        }

        let name_len = ((data[3] as usize) << 8) | (data[4] as usize);
        if 5 + name_len > data.len() {
            return None;
        }

        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    }

    /// Bidirectional proxy between client and backend
    async fn proxy_bidirectional(
        &self,
        client: TcpStream,
        backend: TcpStream,
        initial_data: Vec<u8>,
    ) -> std::io::Result<()> {
        let (client_read, client_write) = client.into_split();
        let (backend_read, backend_write) = backend.into_split();

        // If we have initial data, prepend it
        let client_to_backend = if initial_data.is_empty() {
            tokio::spawn(copy_stream(client_read, backend_write))
        } else {
            tokio::spawn(copy_stream_with_initial(client_read, backend_write, initial_data))
        };

        let backend_to_client = tokio::spawn(copy_stream(backend_read, client_write));

        // Wait for either direction to finish
        tokio::select! {
            result = client_to_backend => {
                match result {
                    Ok(Ok(bytes)) => debug!("TCP: Client->Backend finished, {} bytes", bytes),
                    Ok(Err(e)) => debug!("TCP: Client->Backend error: {}", e),
                    Err(e) => debug!("TCP: Client->Backend task error: {}", e),
                }
            }
            result = backend_to_client => {
                match result {
                    Ok(Ok(bytes)) => debug!("TCP: Backend->Client finished, {} bytes", bytes),
                    Ok(Err(e)) => debug!("TCP: Backend->Client error: {}", e),
                    Err(e) => debug!("TCP: Backend->Client task error: {}", e),
                }
            }
        }

        Ok(())
    }
}

/// Copy data from reader to writer
async fn copy_stream<R, W>(mut reader: R, mut writer: W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }

    let _ = writer.shutdown().await;
    Ok(total)
}

/// Copy data from reader to writer, sending initial data first
async fn copy_stream_with_initial<R, W>(
    mut reader: R,
    mut writer: W,
    initial_data: Vec<u8>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;

    // Write initial data first
    if !initial_data.is_empty() {
        writer.write_all(&initial_data).await?;
        total += initial_data.len() as u64;
    }

    // Then copy the rest
    let mut buf = vec![0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }

    let _ = writer.shutdown().await;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni_from_clienthello() {
        // A minimal TLS ClientHello with SNI for "example.com"
        // This is a simplified test - real parsing would need a complete ClientHello
        let proxy = TcpProxy::new(
            Arc::new(TcpRouter::from_config(&crate::config::Config::default())),
            Arc::new(TcpServiceManager::new(&crate::config::Config::default())),
        );

        // SNI extension data for "example.com"
        let sni_ext = vec![
            0x00, 0x0e, // list length = 14
            0x00, // name type = hostname
            0x00, 0x0b, // name length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];

        let result = proxy.parse_sni_extension(&sni_ext);
        assert_eq!(result, Some("example.com".to_string()));
    }
}
