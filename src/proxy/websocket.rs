use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::header::{HeaderValue, CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error};

/// Check if request is a WebSocket upgrade request
#[inline]
pub fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let dominated = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("websocket"))
        .unwrap_or(false);

    let connection = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);

    dominated && connection
}

/// Handle WebSocket upgrade and proxy the connection
pub async fn handle_websocket_upgrade(
    req: Request<Incoming>,
    backend_addr: &str,
    _remote_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Parse backend address
    let backend_url: url::Url = match backend_addr.parse() {
        Ok(url) => url,
        Err(e) => {
            error!("Invalid backend URL for WebSocket: {}", e);
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    };

    let host = backend_url.host_str().unwrap_or("localhost");
    let port = backend_url.port().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    // Connect to backend
    let backend_stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to backend for WebSocket: {}", e);
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    };

    backend_stream.set_nodelay(true).ok();

    debug!("WebSocket: Connected to backend {}", addr);

    // Build the WebSocket upgrade request to send to backend
    let ws_key = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static(""));

    let path = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&addr);

    // Send HTTP upgrade request manually
    let upgrade_request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        path,
        host_header,
        ws_key.to_str().unwrap_or("")
    );

    // Write upgrade request to backend
    let mut backend_stream = backend_stream;
    if let Err(e) = backend_stream.write_all(upgrade_request.as_bytes()).await {
        error!("Failed to send WebSocket upgrade to backend: {}", e);
        return Ok(error_response(StatusCode::BAD_GATEWAY));
    }

    // Read response from backend using a buffer we own
    let mut buf = vec![0u8; 4096];
    let mut total_read = 0usize;

    // Read until we find \r\n\r\n (end of headers)
    loop {
        use tokio::io::AsyncReadExt;
        let n = match backend_stream.read(&mut buf[total_read..]).await {
            Ok(0) => {
                error!("Backend closed connection during WebSocket handshake");
                return Ok(error_response(StatusCode::BAD_GATEWAY));
            }
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read WebSocket response from backend: {}", e);
                return Ok(error_response(StatusCode::BAD_GATEWAY));
            }
        };
        total_read += n;

        // Check for end of headers
        if let Some(pos) = find_header_end(&buf[..total_read]) {
            // Parse the response
            let response_text = String::from_utf8_lossy(&buf[..pos]);
            if !response_text.contains("101") {
                error!("Backend rejected WebSocket upgrade: {}", response_text.lines().next().unwrap_or(""));
                return Ok(error_response(StatusCode::BAD_GATEWAY));
            }
            break;
        }

        if total_read >= buf.len() {
            error!("WebSocket handshake response too large");
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    }

    debug!("WebSocket: Backend accepted upgrade");

    // Build 101 response for client
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", compute_accept_key(ws_key.to_str().unwrap_or("")))
        .body(empty_body())
        .unwrap();

    // Schedule the upgrade handler - this runs after we return the 101 response
    let req_upgrade = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match req_upgrade.await {
            Ok(upgraded) => {
                let client_stream = TokioIo::new(upgraded);
                if let Err(e) = proxy_streams(client_stream, backend_stream).await {
                    debug!("WebSocket proxy ended: {}", e);
                }
            }
            Err(e) => {
                error!("WebSocket upgrade failed: {}", e);
            }
        }
    });

    Ok(response)
}

/// Find the end of HTTP headers (\r\n\r\n)
fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Compute Sec-WebSocket-Accept value
fn compute_accept_key(key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    let hash = hasher.digest().bytes();

    base64_encode(&hash)
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Proxy data bidirectionally between two streams
async fn proxy_streams<C, B>(client: C, backend: B) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);

    let client_to_backend = tokio::io::copy(&mut client_read, &mut backend_write);
    let backend_to_client = tokio::io::copy(&mut backend_read, &mut client_write);

    tokio::select! {
        result = client_to_backend => {
            debug!("WebSocket client->backend closed: {:?}", result);
        }
        result = backend_to_client => {
            debug!("WebSocket backend->client closed: {:?}", result);
        }
    }

    Ok(())
}

fn error_response(status: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap()
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
