use super::middleware::TcpMiddlewares;
use super::rule::ConnInfo;
use crate::tcp::{TcpRouter, TcpServiceManager};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Timeout for initial connection to backend
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for reading SNI from TLS ClientHello (if needed)
const SNI_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds-checked big-endian reader for TLS parsing.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// TCP proxy handler
pub struct TcpProxy {
    router: Arc<TcpRouter>,
    services: Arc<TcpServiceManager>,
    middlewares: Arc<TcpMiddlewares>,
}

impl TcpProxy {
    /// Create a new TCP proxy
    pub fn new(
        router: Arc<TcpRouter>,
        services: Arc<TcpServiceManager>,
        middlewares: Arc<TcpMiddlewares>,
    ) -> Self {
        Self {
            router,
            services,
            middlewares,
        }
    }

    /// Handle an incoming TCP connection
    pub async fn handle_connection(
        &self,
        mut client: TcpStream,
        client_addr: SocketAddr,
        entrypoint: &str,
    ) {
        // Try to extract SNI from TLS ClientHello if this looks like TLS
        let (sni, alpn) = match self.peek_tls_sni(&mut client).await {
            Ok(v) => v,
            Err(e) => {
                debug!("TCP: Failed to peek TLS SNI: {}", e);
                (None, Vec::new())
            }
        };
        let initial_data: Vec<u8> = Vec::new();

        debug!(
            "TCP: Connection from {} (entrypoint: {}, SNI: {:?})",
            client_addr, entrypoint, sni
        );

        // Find matching route
        let conn = ConnInfo {
            sni: sni.as_deref(),
            alpn: &alpn,
            client_ip: Some(client_addr.ip()),
        };
        let Some(route) = self.router.match_connection(entrypoint, &conn) else {
            warn!(
                "TCP: No route found for connection from {} (SNI: {:?})",
                client_addr, sni
            );
            return;
        };

        // Middlewares (ipAllowList / ipDenyList / inFlightConn). Guards are
        // held until the connection ends.
        let _guards = match self.middlewares.admit(&route.middlewares, client_addr.ip()) {
            Ok(g) => g,
            Err(reason) => {
                debug!("TCP: Rejecting {}: {}", client_addr, reason);
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
        let backend_stream =
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(&backend.address)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    error!(
                        "TCP: Failed to connect to backend {}: {}",
                        backend.address, e
                    );
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
        if let Err(e) = self
            .proxy_bidirectional(client, backend_stream, initial_data)
            .await
        {
            debug!("TCP: Proxy ended for {}: {}", client_addr, e);
        }

        debug!("TCP: Connection closed for {}", client_addr);
    }

    /// Peek at the TLS ClientHello to extract SNI
    /// Returns (Option<SNI>, initial_data)
    async fn peek_tls_sni(
        &self,
        stream: &mut TcpStream,
    ) -> std::io::Result<(Option<String>, Vec<String>)> {
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
        // peek() leaves the bytes in the socket; nothing to replay.
        Ok(Self::parse_client_hello(&buf[5..n.min(buf.len())]))
    }

    /// Parse SNI and ALPN from a TLS ClientHello handshake message
    /// (record header already stripped). Every length is bounds-checked:
    /// a malformed hello yields `(None, [])`, never a panic.
    fn parse_client_hello(data: &[u8]) -> (Option<String>, Vec<String>) {
        Self::try_parse_client_hello(data).unwrap_or((None, Vec::new()))
    }

    fn try_parse_client_hello(data: &[u8]) -> Option<(Option<String>, Vec<String>)> {
        let mut r = Reader { data, pos: 0 };
        if r.u8()? != 0x01 {
            return None; // not a ClientHello
        }
        r.skip(3 + 2 + 32)?; // length, legacy_version, random
        let sid = r.u8()? as usize;
        r.skip(sid)?;
        let suites = r.u16()? as usize;
        r.skip(suites)?;
        let comp = r.u8()? as usize;
        r.skip(comp)?;
        let ext_total = r.u16()? as usize;
        let mut exts = Reader {
            data: r.take(ext_total)?,
            pos: 0,
        };

        let (mut sni, mut alpn) = (None, Vec::new());
        while exts.remaining() >= 4 {
            let ty = exts.u16()?;
            let len = exts.u16()? as usize;
            let mut body = Reader {
                data: exts.take(len)?,
                pos: 0,
            };
            match ty {
                0x0000 => {
                    let mut list = Reader {
                        data: {
                            let n = body.u16()? as usize;
                            body.take(n)?
                        },
                        pos: 0,
                    };
                    while list.remaining() >= 3 {
                        let kind = list.u8()?;
                        let n = list.u16()? as usize;
                        let name = list.take(n)?;
                        if kind == 0 {
                            sni = std::str::from_utf8(name).ok().map(str::to_string);
                            break;
                        }
                    }
                }
                0x0010 => {
                    let mut list = Reader {
                        data: {
                            let n = body.u16()? as usize;
                            body.take(n)?
                        },
                        pos: 0,
                    };
                    while list.remaining() >= 1 {
                        let n = list.u8()? as usize;
                        let p = list.take(n)?;
                        if let Ok(p) = std::str::from_utf8(p) {
                            alpn.push(p.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        Some((sni, alpn))
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
            tokio::spawn(copy_stream_with_initial(
                client_read,
                backend_write,
                initial_data,
            ))
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

/// Copy data from reader to writer using tokio's optimized internal buffer
async fn copy_stream<R, W>(mut reader: R, mut writer: W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let bytes = tokio::io::copy(&mut reader, &mut writer).await?;
    let _ = writer.shutdown().await;
    Ok(bytes)
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
    if !initial_data.is_empty() {
        writer.write_all(&initial_data).await?;
        total += initial_data.len() as u64;
    }
    total += tokio::io::copy(&mut reader, &mut writer).await?;
    let _ = writer.shutdown().await;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ClientHello handshake message with SNI and ALPN extensions.
    fn hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
        let mut exts = Vec::new();
        let name = sni.as_bytes();
        let mut sni_body = vec![0x00];
        sni_body.extend((name.len() as u16).to_be_bytes());
        sni_body.extend(name);
        let mut sni_ext = (sni_body.len() as u16).to_be_bytes().to_vec();
        sni_ext.extend(sni_body);
        exts.extend([0x00, 0x00]);
        exts.extend((sni_ext.len() as u16).to_be_bytes());
        exts.extend(sni_ext);
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend(p.as_bytes());
        }
        let mut alpn_ext = (list.len() as u16).to_be_bytes().to_vec();
        alpn_ext.extend(list);
        exts.extend([0x00, 0x10]);
        exts.extend((alpn_ext.len() as u16).to_be_bytes());
        exts.extend(alpn_ext);

        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]);
        body.push(0); // session id
        body.extend([0x00, 0x02, 0x13, 0x01]); // one suite
        body.extend([0x01, 0x00]); // compression
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut msg = vec![0x01];
        msg.extend(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend(body);
        msg
    }

    #[test]
    fn parses_sni_and_alpn() {
        let (sni, alpn) =
            TcpProxy::parse_client_hello(&hello("db.example.com", &["h2", "postgresql"]));
        assert_eq!(sni.as_deref(), Some("db.example.com"));
        assert_eq!(alpn, vec!["h2", "postgresql"]);
    }

    #[test]
    fn truncated_or_malformed_hello_never_panics() {
        let h = hello("example.com", &["h2"]);
        for n in 0..h.len() {
            let _ = TcpProxy::parse_client_hello(&h[..n]);
        }
        let mut bad = h.clone();
        // inflate the extensions length well past the buffer
        let ext_len_pos = 1 + 3 + 2 + 32 + 1 + 4 + 2;
        bad[ext_len_pos] = 0xff;
        bad[ext_len_pos + 1] = 0xff;
        assert_eq!(TcpProxy::parse_client_hello(&bad), (None, vec![]));
        assert_eq!(
            TcpProxy::parse_client_hello(&[0x01, 0xff, 0xff, 0xff]),
            (None, vec![])
        );
    }
}
