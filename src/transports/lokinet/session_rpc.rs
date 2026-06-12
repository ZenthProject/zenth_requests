//! Format des requêtes RPC Session
//!
//! Implémente le format JSON-RPC 2.0 utilisé par les snodes Session.

use serde::{Deserialize, Serialize};

/// Requête JSON-RPC 2.0 pour les snodes Session
#[derive(Debug, Clone, Serialize)]
pub struct SessionRpcRequest {
    pub jsonrpc: &'static str,
    pub method: String,
    pub params: serde_json::Value,
}

impl SessionRpcRequest {
    /// Crée une nouvelle requête RPC
    pub fn new(method: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        }
    }

    /// Crée une requête batch avec plusieurs sous-requêtes
    pub fn batch(requests: Vec<SubRequest>) -> Self {
        Self::new("batch", serde_json::json!({
            "requests": requests
        }))
    }

    /// Crée une requête sequence (s'arrête à la première erreur)
    pub fn sequence(requests: Vec<SubRequest>) -> Self {
        Self::new("sequence", serde_json::json!({
            "requests": requests
        }))
    }

    /// Sérialise en JSON
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Sous-requête pour batch/sequence
///
/// Format Session Desktop: {"method": "...", "params": {...}}
/// Le champ `params` est TOUJOURS présent (même si vide)
#[derive(Debug, Clone, Serialize)]
pub struct SubRequest {
    pub method: String,
    pub params: serde_json::Value,
}

impl SubRequest {
    /// Crée une sous-requête info
    pub fn info() -> Self {
        Self {
            method: "info".to_string(),
            params: serde_json::json!({}),
        }
    }

    /// Crée une sous-requête oxend_request
    pub fn oxend_request(endpoint: &str, params: serde_json::Value) -> Self {
        Self {
            method: "oxend_request".to_string(),
            params: serde_json::json!({
                "endpoint": endpoint,
                "params": params
            }),
        }
    }

    /// Crée une sous-requête get_swarm
    pub fn get_swarm(pubkey: &str) -> Self {
        Self {
            method: "get_swarm".to_string(),
            params: serde_json::json!({
                "pubKey": pubkey
            }),
        }
    }

    /// Crée une sous-requête retrieve
    pub fn retrieve(pubkey: &str, namespace: i32, last_hash: Option<&str>) -> Self {
        let mut params = serde_json::json!({
            "pubkey": pubkey,
            "namespace": namespace
        });

        if let Some(hash) = last_hash {
            params["last_hash"] = serde_json::Value::String(hash.to_string());
        }

        Self {
            method: "retrieve".to_string(),
            params,
        }
    }

    /// Crée une sous-requête store
    pub fn store(
        pubkey: &str,
        namespace: i32,
        data: &str,
        ttl: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            method: "store".to_string(),
            params: serde_json::json!({
                "pubkey": pubkey,
                "namespace": namespace,
                "data": data,
                "ttl": ttl,
                "timestamp": timestamp
            }),
        }
    }
}

/// Réponse d'une requête batch
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    pub results: Vec<BatchResultEntry>,
}

/// Entrée dans la réponse batch
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResultEntry {
    pub code: u16,
    pub body: serde_json::Value,
}

/// Réponse info d'un snode
#[derive(Debug, Clone, Deserialize)]
pub struct InfoResponse {
    pub version: Option<Vec<u32>>,
    pub timestamp: Option<u64>,
    pub t: Option<u64>,
    pub hf: Option<Vec<u32>>,
}

/// Réponse get_swarm
#[derive(Debug, Clone, Deserialize)]
pub struct SwarmResponse {
    pub snodes: Vec<SwarmSnode>,
    pub swarm: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SwarmSnode {
    pub ip: String,
    pub port: String,
    pub pubkey_x25519: String,
    pub pubkey_ed25519: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_request_format() {
        let req = SessionRpcRequest::batch(vec![
            SubRequest::info(),
        ]);

        let json = String::from_utf8(req.to_json()).unwrap();
        assert!(json.contains("jsonrpc"));
        assert!(json.contains("2.0"));
        assert!(json.contains("batch"));
        assert!(json.contains("requests"));
    }

    #[test]
    fn test_get_swarm_request() {
        let sub = SubRequest::get_swarm("05abcdef");
        let json = serde_json::to_string(&sub).unwrap();
        assert!(json.contains("get_swarm"));
        assert!(json.contains("pubKey"));
    }
}
