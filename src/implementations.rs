use crate::{
    errors::errors::ReqError,
    transports::{Transport, http::HttpTransport, tor::TorTransport},
};

pub struct RequestsNetwork;

impl RequestsNetwork {
    pub async fn new(type_request: &str) -> Result<Box<dyn Transport + Send + Sync>, ReqError> {
        let transport: Box<dyn Transport + Send + Sync> = match type_request.to_lowercase().as_str() {
            "tor" | "Tor" | "TOR" | "socks5" | "SOCKS5" | "Socks5" => Box::new(TorTransport::new().await?),
            "http" | "Http" | "HTTP" | "https" | "Https" | "HTTPS" => Box::new(HttpTransport::new()?),
            //TODO: Re-add I2P support later
            //"i2p" | "I2P" | "I2p" => Box::new(I2PTransport::new(None).await?),
            "lokinet" | "Lokinet" | "LOKINET" | "loki" | "Loki" | "LOKI" => Box::new(HttpTransport::new()?),
            _ => return Err(ReqError::transport("Transport not found!".to_string())),
        };
        Ok(transport)
    }
}
