use crate::{
    request::Request,
    response::Response,
    errors::errors::ReqError
};
use crate::transports::Transport;
use async_trait::async_trait;
use reqwest::Client as ReqwestClient;

/// HTTP/HTTPS transport with TLS 1.3 support
/// Automatically accepts self-signed certificates for localhost (development)
pub struct HttpTransport {
    client_secure: ReqwestClient,      // For production (validates certs)
    client_localhost: ReqwestClient,   // For localhost (accepts self-signed)
}

impl HttpTransport {
    pub fn new() -> Result<Self, ReqError> {
        // Production client: TLS 1.3 with full certificate validation
        let client_secure = ReqwestClient::builder()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .build()
            .map_err(|e| ReqError::Transport(format!("Failed to build secure client: {}", e)))?;

        // Localhost client: TLS 1.3 but accepts self-signed certs
        // This is safe because localhost connections never leave the machine
        let client_localhost = ReqwestClient::builder()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| ReqError::Transport(format!("Failed to build localhost client: {}", e)))?;

        Ok(HttpTransport { client_secure, client_localhost })
    }

    /// Check if URL is localhost
    fn is_localhost(url: &str) -> bool {
        url.contains("://localhost") ||
        url.contains("://127.0.0.1") ||
        url.contains("://[::1]")
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send(&self, req: Request) -> Result<Response, ReqError> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| ReqError::transport(format!("Invalid HTTP method: {}", e)))?;

        // Use localhost client (accepts self-signed) or secure client based on URL
        let client = if Self::is_localhost(&req.url) {
            &self.client_localhost
        } else {
            &self.client_secure
        };

        let mut builder = client.request(method, &req.url);

        for (key, value) in req.headers.iter() {
            builder = builder.header(key, value);
        }

        if let Some(body) = req.body {
            builder = builder.body(body.to_vec());
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| ReqError::transport(format!("HTTP request failed: {}", e)))?;

        let status = resp.status().as_u16();

        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = resp
            .bytes()
            .await
            .map_err(|e| ReqError::transport(format!("Failed to read response body: {}", e)))?;

        Ok(Response { status, headers, body: body.into() })
    }

    async fn recv(&self) -> Result<Response, ReqError> {
        Err(ReqError::other("recv not implemented for HttpTransport"))
    }
}
