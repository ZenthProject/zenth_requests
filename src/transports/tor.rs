use crate::{
    request::Request,
    response::Response,
    errors::errors::ReqError,
};
use super::Transport;
use async_trait::async_trait;
use bytes::Bytes;
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use tokio::sync::OnceCell;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

/// Embedded Tor transport using Arti, no external Tor binary needed.
pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl TorTransport {
    pub async fn new() -> Result<Self, ReqError> {
        static TOR_CLIENT: OnceCell<Arc<TorClient<PreferredRuntime>>> = OnceCell::const_new();

        let client = TOR_CLIENT
            .get_or_try_init(|| async {
                let config = TorClientConfig::default();
                let client = TorClient::create_bootstrapped(config)
                    .await
                    .map_err(|e| {
                        ReqError::transport(format!("Failed to bootstrap Tor client: {}", e))
                    })?;
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                Ok::<_, ReqError>(Arc::new(client))
            })
            .await?;
        Ok(Self { client: client.clone() })
    }
}

#[async_trait]
impl Transport for TorTransport {
    async fn send(&self, req: Request) -> Result<Response, ReqError> {
        let url = Url::parse(&req.url)
            .map_err(|e| ReqError::transport(format!("Invalid URL: {}", e)))?;

        let host = url.host_str()
            .ok_or_else(|| ReqError::transport(String::from("Missing hostname in URL")))?;
        let port = url.port_or_known_default()
            .ok_or_else(|| ReqError::transport(String::from("Missing port and no default")))?;

        let stream = match self.client.connect((host, port)).await {
            Ok(s) => {
                s
            },
            Err(e) => {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;                
                self.client.connect((host, port)).await
                    .map_err(|e| {
                        ReqError::transport(format!("Tor connect failed: {}", e))
                    })?
            }
        };

        let path = if url.path().is_empty() { "/" } else { url.path() };
        let mut raw = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", req.method, path, host);
        
        for (k, v) in &req.headers {
            raw.push_str(&format!("{}: {}\r\n", k, v));
        }
        raw.push_str("\r\n");
        
        if let Some(body) = &req.body {
            raw.push_str(&String::from_utf8_lossy(body));
        }

        if url.scheme() == "https" {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| ReqError::transport(format!("Invalid server name: {}", e)))?;

            let mut tls_stream = connector.connect(server_name, stream).await
                .map_err(|e| ReqError::transport(format!("TLS handshake failed: {}", e)))?;

            tls_stream.write_all(raw.as_bytes()).await
                .map_err(|e| ReqError::transport(format!("TLS write failed: {}", e)))?;
            
            tls_stream.flush().await
                .map_err(|e| ReqError::transport(format!("TLS flush failed: {}", e)))?;

            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let mut total_read = 0;
            let mut headers_complete = false;
            let mut content_length: Option<usize> = None;
            
            let read_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(30),
                async {
                    loop {
                        match tls_stream.read(&mut tmp).await {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&tmp[..n]);
                                total_read += n;
                                
                                if !headers_complete {
                                    if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                        headers_complete = true;
                                        
                                        let headers_part = String::from_utf8_lossy(&buf[..header_end]);
                                        for line in headers_part.lines() {
                                            if line.to_lowercase().starts_with("content-length:") {
                                                if let Some(len_str) = line.split(':').nth(1) {
                                                    content_length = len_str.trim().parse().ok();
                                                }
                                            }
                                        }
                                        
                                        if let Some(expected_len) = content_length {
                                            let body_start = header_end + 4;
                                            let current_body_len = buf.len() - body_start;
                                            if current_body_len >= expected_len {
                                                break;
                                            }
                                        }
                                    }
                                } else if let Some(expected_len) = content_length {
                                    if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                        let body_start = header_end + 4;
                                        let current_body_len = buf.len() - body_start;
                                        if current_body_len >= expected_len {
                                            break; // On a tout reçu
                                        }
                                    }
                                }
                                
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(())
                }
            ).await;
            
            match read_result {
                Ok(Ok(())) => println!("[TorTransport] Response received ({} bytes)", total_read),
                Ok(Err(e)) => return Err(ReqError::transport(format!("TLS read failed: {}", e))),
                Err(_) => return Err(ReqError::transport("Request timeout".to_string())),
            }
            
            parse_http_response(&buf)
            
        } else {
            let mut stream = stream;
            stream.write_all(raw.as_bytes()).await
                .map_err(|e| ReqError::transport(format!("Tor write failed: {}", e)))?;
            
            stream.flush().await
                .map_err(|e| ReqError::transport(format!("Tor flush failed: {}", e)))?;

            let mut buf = Vec::new();
            
            let read_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(30),
                stream.read_to_end(&mut buf)
            ).await;
            
            match read_result {
                Ok(Ok(n)) => println!("[TorTransport] Response received ({} bytes)", n),
                Ok(Err(e)) => return Err(ReqError::transport(format!("Read failed: {}", e))),
                Err(_) => return Err(ReqError::transport("Request timeout".to_string())),
            }

            parse_http_response(&buf)
        }
    }
    
    async fn recv(&self) -> Result<Response, ReqError> {
        Err(ReqError::other("recv() not implemented for TorTransport"))
    }
}

fn parse_http_response(buf: &[u8]) -> Result<Response, ReqError> {
    let response_text = String::from_utf8_lossy(buf);
    let (header_block, body_block) = response_text.split_once("\r\n\r\n")
        .ok_or_else(|| ReqError::transport("Malformed HTTP response".to_string()))?;

    let status = header_block
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let headers_map = header_block
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(": ").map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();

    Ok(Response {
        status,
        headers: headers_map,
        body: Bytes::from(body_block.as_bytes().to_vec()),
    })
}