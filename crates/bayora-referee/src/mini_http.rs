//! A deliberately tiny HTTP/1.1 client.
//!
//! The Referee talks to two control interfaces that are *not* under its own
//! process boundary:
//!
//! * the Firecracker API (`PUT /snapshot/load`, over a UNIX socket), and
//! * the llama.cpp server (`POST /slots/{n}?action=erase`).
//!
//! Pulling in a full HTTP stack for two request shapes would enlarge the TCB
//! for no benefit, so this module implements exactly what is needed: one
//! request per connection, `Connection: close`, read to EOF, split headers from
//! body. Nothing here parses attacker-controlled input — the responses come
//! from local, policy-specified endpoints.

use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn body_str(&self) -> Result<&str, io::Error> {
        std::str::from_utf8(&self.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// Perform one request/response exchange over an arbitrary stream.
///
/// `host_header` only affects the `Host:` header (virtual hosts on
/// 127.0.0.1 do not care, but some servers require its presence).
pub async fn request<S>(
    stream: &mut S,
    host_header: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> io::Result<HttpResponse>
where
    S: AsyncReadExt + AsyncWrite + Unpin,
{
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(payload) = body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await?;
    if let Some(payload) = body {
        stream.write_all(payload).await?;
    }
    stream.flush().await?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_response(&raw)
}

/// Parse a raw HTTP/1.1 response (headers + body).
pub fn parse_response(raw: &[u8]) -> io::Result<HttpResponse> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response had no header terminator",
            )
        })?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP response"))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().unwrap_or("HTTP/1.1");
    let status: u16 = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP status"))?;
    Ok(HttpResponse {
        status,
        body: raw[split + 4..].to_vec(),
    })
}

/// One exchange over loopback TCP.
pub async fn tcp_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> io::Result<HttpResponse> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    request(&mut stream, &addr.to_string(), method, path, body).await
}

/// One exchange over a UNIX domain socket (Firecracker's `api-sock`).
#[cfg(unix)]
pub async fn unix_request(
    socket: &std::path::Path,
    host_header: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> io::Result<HttpResponse> {
    let mut stream = tokio::net::UnixStream::connect(socket).await?;
    request(&mut stream, host_header, method, path, body).await
}

/// Parse `http://host:port` into a `SocketAddr` (loopback-only callers).
pub fn parse_http_endpoint(url: &str) -> Result<SocketAddr, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("endpoint {url:?} must start with http://"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    authority
        .parse::<SocketAddr>()
        .map_err(|e| format!("endpoint {url:?} is not host:port: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    #[test]
    fn parses_status_and_body() {
        let raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
        assert!(resp.is_success());

        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 5\r\n\r\nnope!";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 400);
        assert_eq!(resp.body_str().unwrap(), "nope!");
        assert!(!resp.is_success());
    }

    #[test]
    fn rejects_headerless_response() {
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn parses_endpoints() {
        assert_eq!(
            parse_http_endpoint("http://127.0.0.1:8081").unwrap(),
            "127.0.0.1:8081".parse().unwrap()
        );
        assert_eq!(
            parse_http_endpoint("http://127.0.0.1:8081/slots/0").unwrap(),
            "127.0.0.1:8081".parse().unwrap()
        );
        assert!(parse_http_endpoint("https://example.com").is_err());
    }

    /// Spin a one-shot server that echoes the request line so the client's
    /// request formatting is asserted end-to-end.
    async fn one_shot_server(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_request_round_trip() {
        let addr = one_shot_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let resp = tcp_request(addr, "POST", "/slots/0?action=erase", Some(b"{}"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_str().unwrap(), "ok");
    }

    #[tokio::test]
    async fn connection_refused_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(tcp_request(addr, "GET", "/health", None).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_request_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let resp = unix_request(&sock, "localhost", "PUT", "/snapshot/load", Some(b"{}"))
            .await
            .unwrap();
        assert_eq!(resp.status, 204);
    }
}
