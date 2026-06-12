use std::fmt;
use std::io;
use thiserror::Error;

/// Erreur principale pour la crate `requests`
#[derive(Error, Debug)]
pub enum ReqError {
    /// Erreurs liées au transport (HTTP, WebSocket, Tor, I2P, etc.)
    #[error("Transport error: {0}")]
    Transport(String),

    /// Timeout expiré
    #[error("Timeout expired: {0}")]
    Timeout(String),

    /// Erreur de parsing (JSON, bytes, etc.)
    #[error("Parsing error: {0}")]
    Parsing(String),

    /// Erreur IO générique
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Erreur provenant de Reqwest (HTTP client)
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Erreur JSON (serde)
    #[error("Serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    /// Erreur générique (fallback)
    #[error("Unknown error: {0}")]
    Other(String),
}

impl ReqError {
    /// Crée une erreur Transport simple
    pub fn transport(msg: impl Into<String>) -> Self {
        ReqError::Transport(msg.into())
    }

    /// Crée une erreur Timeout simple
    pub fn timeout(msg: impl Into<String>) -> Self {
        ReqError::Timeout(msg.into())
    }

    /// Crée une erreur Parsing simple
    pub fn parsing(msg: impl Into<String>) -> Self {
        ReqError::Parsing(msg.into())
    }

    /// Crée une erreur générique
    pub fn other(msg: impl Into<String>) -> Self {
        ReqError::Other(msg.into())
    }
}
