//! Transport wrapper pour le réseau Session/Lokinet
//!
//! Fournit un transport onion-routed via les Service Nodes Session.
//!
//! **Important:** Le réseau Session est conçu pour la messagerie, pas comme un proxy HTTP généraliste.
//! Ce transport permet:
//! - Requêtes vers les snodes (storage RPC, swarm queries, etc.)
//! - Requêtes vers d'autres services Session
//!
//! Pour un proxy HTTP généraliste, utilisez Tor.

use crate::{
    request::Request,
    response::Response,
    errors::errors::ReqError,
};
use crate::transports::Transport;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::RwLock;
use std::sync::Arc;
use std::collections::HashMap;
use url::Url;
use rand::seq::SliceRandom;
use rand::SeedableRng;

use super::snode::{Snode, fetch_snodes_from_seeds};
use super::crypto::{decrypt_from_snode, encrypt_for_snode, encode_plaintext_plus_json};
use super::payload::{build_onion_payload, build_onion_payload_with_dest, decode_v4_response, RelayDestination, Protocol};
use super::session_rpc::{SessionRpcRequest, SubRequest, BatchResponse};

/// Nombre de snodes dans le chemin onion (guard, middle, exit)
const PATH_LENGTH: usize = 3;

/// Durée de vie du cache des snodes (en secondes)
const SNODE_CACHE_TTL: u64 = 3600; // 1 heure

/// Transport onion via le réseau Session/Lokinet
///
/// Utilise 3 hops (guard → middle → exit) pour anonymiser les requêtes.
/// Compatible avec les Service Nodes du réseau Oxen/Session.
///
/// # Modes d'utilisation
///
/// 1. **Direct snode** - Requêtes RPC vers un snode destination (storage, swarm)
/// 2. **Onion routing** - Requêtes via chaîne de snodes vers un snode final
pub struct LokinetTransport {
    /// Client HTTP pour les requêtes vers les guard nodes
    client: reqwest::Client,
    /// Cache des snodes disponibles
    snodes: Arc<RwLock<Vec<Snode>>>,
    /// Chemin actuel (3 snodes)
    current_path: Arc<RwLock<Option<Vec<Snode>>>>,
    /// Timestamp du dernier refresh des snodes
    last_refresh: Arc<RwLock<std::time::Instant>>,
}

impl LokinetTransport {
    /// Crée un nouveau transport Lokinet
    ///
    /// Bootstrap automatiquement depuis les seed nodes officiels Session.
    pub async fn new() -> Result<Self, ReqError> {
        // Client HTTP qui accepte les certs self-signed (snodes utilisent leurs propres certs)
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ReqError::transport(format!("Failed to create HTTP client: {}", e)))?;

        let transport = Self {
            client,
            snodes: Arc::new(RwLock::new(Vec::new())),
            current_path: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(std::time::Instant::now())),
        };

        // Bootstrap initial
        transport.refresh_snodes().await?;
        transport.rotate_path().await?;

        Ok(transport)
    }

    /// Rafraîchit la liste des snodes depuis les seeds
    pub async fn refresh_snodes(&self) -> Result<(), ReqError> {
        let snodes = fetch_snodes_from_seeds().await?;

        if snodes.len() < PATH_LENGTH {
            return Err(ReqError::transport(format!(
                "Not enough snodes available: {} (need at least {})",
                snodes.len(),
                PATH_LENGTH
            )));
        }

        let mut snodes_lock = self.snodes.write().await;
        *snodes_lock = snodes;

        let mut refresh_lock = self.last_refresh.write().await;
        *refresh_lock = std::time::Instant::now();

        Ok(())
    }

    /// Sélectionne un nouveau chemin aléatoire de 3 snodes
    pub async fn rotate_path(&self) -> Result<(), ReqError> {
        // Lecture des snodes disponibles
        let snodes_lock = self.snodes.read().await;

        if snodes_lock.len() < PATH_LENGTH {
            return Err(ReqError::transport("Not enough snodes for path"));
        }

        // Sélection aléatoire avec un RNG thread-safe
        let mut rng = rand::rngs::StdRng::from_entropy();
        let path: Vec<Snode> = snodes_lock
            .choose_multiple(&mut rng, PATH_LENGTH)
            .cloned()
            .collect();

        drop(snodes_lock);

        let mut path_lock = self.current_path.write().await;
        *path_lock = Some(path);

        Ok(())
    }

    /// Récupère le chemin actuel ou en crée un nouveau
    async fn get_path(&self) -> Result<Vec<Snode>, ReqError> {
        // Vérifie si on doit refresh les snodes
        {
            let refresh_lock = self.last_refresh.read().await;
            if refresh_lock.elapsed().as_secs() > SNODE_CACHE_TTL {
                drop(refresh_lock);
                self.refresh_snodes().await?;
                self.rotate_path().await?;
            }
        }

        let path_lock = self.current_path.read().await;
        path_lock.clone().ok_or_else(|| ReqError::transport("No path available"))
    }

    /// Envoie une requête via le chemin onion
    async fn send_onion_request(
        &self,
        path: &[Snode],
        destination: &RelayDestination,
        v4_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<[u8; 32]>), ReqError> {
        // Construit le payload onion multi-couche
        let onion = build_onion_payload(path, v4_payload, Some(destination))?;

        // Envoie au guard node
        // Le payload contient déjà la clé éphémère dans le JSON
        let guard = &path[0];
        let guard_url = guard.onion_url();

        let response = self.client
            .post(&guard_url)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "WhatsApp")
            .header("Accept-Language", "en-us")
            .body(onion.data)
            .send()
            .await
            .map_err(|e| ReqError::transport(format!("Guard node request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ReqError::transport(format!(
                "Guard node returned status: {}",
                response.status()
            )));
        }

        let encrypted_response = response.bytes().await
            .map_err(|e| ReqError::transport(format!("Failed to read guard response: {}", e)))?;

        Ok((encrypted_response.to_vec(), onion.symmetric_keys))
    }

    /// Déchiffre la réponse onion
    ///
    /// La réponse du réseau Session est en base64 et chiffrée avec la clé
    /// symétrique de la destination finale.
    fn decrypt_onion_response(
        &self,
        encrypted: &[u8],
        symmetric_keys: &[[u8; 32]],
    ) -> Result<Vec<u8>, ReqError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        if symmetric_keys.is_empty() {
            return Err(ReqError::transport("No symmetric keys available"));
        }

        // La réponse est encodée en base64
        let encrypted_str = std::str::from_utf8(encrypted)
            .map_err(|e| ReqError::parsing(format!("Response is not valid UTF-8: {}", e)))?;

        let ciphertext = STANDARD.decode(encrypted_str.trim())
            .map_err(|e| ReqError::parsing(format!("Failed to decode base64: {}", e)))?;

        // La réponse est chiffrée avec la clé de la destination finale
        let final_key = symmetric_keys.last().unwrap();
        decrypt_from_snode(final_key, &ciphertext)
    }

    /// Envoie une requête RPC via onion routing vers un snode destination
    ///
    /// Session utilise un chemin de 3 snodes (guard, middle, exit) qui relayent
    /// vers un **quatrième** snode destination.
    ///
    /// Format Session Desktop pour snode destination:
    /// Le payload chiffré contient: [len][JSON-RPC body][{"body": null}]
    pub async fn send_to_snode(
        &self,
        rpc_body: &[u8],
    ) -> Result<Vec<u8>, ReqError> {

        let path = self.get_path().await?;

        // Sélectionne un snode destination (différent du chemin)
        let destination_snode = self.get_random_snode_excluding(&path).await?;

        // Format Session Desktop: le body RPC + metadata avec body: null, headers: {}
        // Comme dans onions.ts ligne 1055-1069:
        // encodeCiphertextPlusJson(bodyEncoded, {body: null, headers: {}})
        let metadata = serde_json::json!({
            "body": serde_json::Value::Null,
            "headers": {}
        });
        let encoded_payload = encode_plaintext_plus_json(rpc_body, &metadata);

        // Chiffre ce payload pour le snode destination
        let dest_ctx = encrypt_for_snode(&destination_snode.pubkey_x25519, &encoded_payload)?;
        let final_symmetric_key = dest_ctx.symmetric_key;

        // Construit le payload onion avec le ciphertext destination
        let onion = build_onion_payload_with_dest(&path, &dest_ctx, &destination_snode)?;

        let guard = &path[0];
        let guard_url = guard.onion_url();

        let response = self.client
            .post(&guard_url)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "WhatsApp")
            .header("Accept-Language", "en-us")
            .body(onion.data)
            .send()
            .await
            .map_err(|e| ReqError::transport(format!("Guard node request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ReqError::transport(format!(
                "Guard node returned status: {}",
                response.status()
            )));
        }

        let encrypted_response = response.bytes().await
            .map_err(|e| ReqError::transport(format!("Failed to read response: {}", e)))?;

        // Déchiffre la réponse avec la clé de la destination
        self.decrypt_single_layer(&encrypted_response, &final_symmetric_key)
    }

    /// Sélectionne un snode aléatoire qui n'est pas dans le chemin
    async fn get_random_snode_excluding(&self, path: &[Snode]) -> Result<Snode, ReqError> {
        let snodes = self.snodes.read().await;
        let path_pubkeys: std::collections::HashSet<_> = path.iter()
            .map(|s| s.pubkey_ed25519)
            .collect();

        let available: Vec<_> = snodes.iter()
            .filter(|s| !path_pubkeys.contains(&s.pubkey_ed25519))
            .cloned()
            .collect();

        if available.is_empty() {
            return Err(ReqError::transport("No snodes available outside path"));
        }

        let mut rng = rand::rngs::StdRng::from_entropy();
        use rand::seq::SliceRandom;
        available.choose(&mut rng)
            .cloned()
            .ok_or_else(|| ReqError::transport("Failed to select snode"))
    }

    /// Déchiffre une seule couche de réponse
    fn decrypt_single_layer(
        &self,
        encrypted: &[u8],
        symmetric_key: &[u8; 32],
    ) -> Result<Vec<u8>, ReqError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        // La réponse est encodée en base64
        let encrypted_str = std::str::from_utf8(encrypted)
            .map_err(|e| ReqError::parsing(format!("Response is not valid UTF-8: {}", e)))?;

        let ciphertext = STANDARD.decode(encrypted_str.trim())
            .map_err(|e| ReqError::parsing(format!("Failed to decode base64: {}", e)))?;

        decrypt_from_snode(symmetric_key, &ciphertext)
    }

    /// Envoie une requête batch via onion routing
    ///
    /// C'est le format principal utilisé par Session Desktop.
    /// Format JSON-RPC 2.0: {"jsonrpc": "2.0", "method": "batch", "params": {"requests": [...]}}
    pub async fn batch_request(
        &self,
        requests: Vec<SubRequest>,
    ) -> Result<BatchResponse, ReqError> {
        let rpc = SessionRpcRequest::batch(requests);
        let rpc_bytes = rpc.to_json();

        let response_bytes = self.send_to_snode(&rpc_bytes).await?;

        // La réponse onion a le format: {"body": "...", "status": 200}
        // Où "body" est une chaîne JSON échappée qu'il faut re-parser
        let wrapper: serde_json::Value = serde_json::from_slice(&response_bytes)
            .map_err(|e| ReqError::parsing(format!("Failed to parse wrapper: {}", e)))?;

        let status = wrapper.get("status")
            .and_then(|s| s.as_u64())
            .unwrap_or(0) as u16;

        if status != 200 {
            let body = wrapper.get("body")
                .and_then(|b| b.as_str())
                .unwrap_or("Unknown error");
            return Err(ReqError::transport(format!("Snode error {}: {}", status, body)));
        }

        // Le body est une chaîne JSON qu'il faut parser
        let body_str = wrapper.get("body")
            .and_then(|b| b.as_str())
            .ok_or_else(|| ReqError::parsing("Missing body in response"))?;

        serde_json::from_str(body_str)
            .map_err(|e| ReqError::parsing(format!("Failed to parse batch body: {}", e)))
    }

    /// Envoie une requête simple via onion routing
    ///
    /// Emballe automatiquement dans une requête batch.
    pub async fn simple_request(
        &self,
        request: SubRequest,
    ) -> Result<serde_json::Value, ReqError> {
        let batch = self.batch_request(vec![request]).await?;

        if batch.results.is_empty() {
            return Err(ReqError::parsing("Empty batch response"));
        }

        let result = &batch.results[0];
        if result.code != 200 {
            return Err(ReqError::transport(format!(
                "Snode returned code {}: {:?}",
                result.code, result.body
            )));
        }

        Ok(result.body.clone())
    }

    /// Récupère les infos d'un snode via onion routing
    pub async fn info(&self) -> Result<serde_json::Value, ReqError> {
        self.simple_request(SubRequest::info()).await
    }

    /// Envoie une requête storage RPC via onion routing (legacy)
    ///
    /// Utilisé pour store/retrieve des messages sur le réseau Session.
    pub async fn storage_rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ReqError> {
        let rpc = SessionRpcRequest::new(method, params);
        let rpc_bytes = rpc.to_json();

        let response_bytes = self.send_to_snode(&rpc_bytes).await?;

        // La réponse onion a le format: {"body": "...", "status": 200}
        let wrapper: serde_json::Value = serde_json::from_slice(&response_bytes)
            .map_err(|e| ReqError::parsing(format!("Failed to parse wrapper: {}", e)))?;

        let status = wrapper.get("status")
            .and_then(|s| s.as_u64())
            .unwrap_or(0) as u16;

        if status != 200 {
            let body = wrapper.get("body")
                .and_then(|b| b.as_str())
                .unwrap_or("Unknown error");
            return Err(ReqError::transport(format!("Snode error {}: {}", status, body)));
        }

        // Le body est une chaîne JSON qu'il faut parser
        let body_str = wrapper.get("body")
            .and_then(|b| b.as_str())
            .ok_or_else(|| ReqError::parsing("Missing body in response"))?;

        serde_json::from_str(body_str)
            .map_err(|e| ReqError::parsing(format!("Failed to parse RPC body: {}", e)))
    }

    /// Récupère le swarm associé à une clé publique Session
    pub async fn get_swarm(&self, pubkey: &str) -> Result<Vec<Snode>, ReqError> {
        let response = self.storage_rpc("get_swarm", serde_json::json!({
            "pubkey": pubkey
        })).await?;

        // Parse la réponse pour extraire les snodes du swarm
        let snodes = response.get("snodes")
            .and_then(|s| s.as_array())
            .ok_or_else(|| ReqError::parsing("Invalid swarm response"))?;

        let mut result = Vec::new();
        for snode_val in snodes {
            if let (Some(ip), Some(port), Some(x25519), Some(ed25519)) = (
                snode_val.get("ip").and_then(|v| v.as_str()),
                snode_val.get("port").and_then(|v| v.as_u64()),
                snode_val.get("pubkey_x25519").and_then(|v| v.as_str()),
                snode_val.get("pubkey_ed25519").and_then(|v| v.as_str()),
            ) {
                let mut x25519_bytes = [0u8; 32];
                let mut ed25519_bytes = [0u8; 32];

                if let (Ok(x), Ok(e)) = (hex::decode(x25519), hex::decode(ed25519)) {
                    if x.len() == 32 && e.len() == 32 {
                        x25519_bytes.copy_from_slice(&x);
                        ed25519_bytes.copy_from_slice(&e);
                        result.push(Snode {
                            ip: ip.to_string(),
                            port: port as u16,
                            pubkey_x25519: x25519_bytes,
                            pubkey_ed25519: ed25519_bytes,
                        });
                    }
                }
            }
        }

        Ok(result)
    }

    /// Récupère un snode aléatoire du pool
    pub async fn get_random_snode(&self) -> Result<Snode, ReqError> {
        let snodes = self.snodes.read().await;
        let mut rng = rand::rngs::StdRng::from_entropy();
        snodes.choose(&mut rng)
            .cloned()
            .ok_or_else(|| ReqError::transport("No snodes available"))
    }

    /// Retourne la liste des snodes en cache
    pub async fn get_snodes(&self) -> Vec<Snode> {
        self.snodes.read().await.clone()
    }

    /// Retourne le chemin actuel
    pub async fn get_current_path(&self) -> Option<Vec<Snode>> {
        self.current_path.read().await.clone()
    }

    /// Envoie une requête directe à un snode (sans onion routing)
    ///
    /// Utile pour le debug et les tests.
    /// La requête est envoyée directement au snode via son endpoint storage_rpc.
    pub async fn direct_rpc(
        &self,
        snode: &Snode,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ReqError> {
        let rpc_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        });

        let url = snode.storage_url();

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "WhatsApp")
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| ReqError::transport(format!("Direct RPC failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ReqError::transport(format!(
                "Snode returned status {}: {}",
                status, body
            )));
        }

        response.json()
            .await
            .map_err(|e| ReqError::parsing(format!("Failed to parse RPC response: {}", e)))
    }
}

#[async_trait]
impl Transport for LokinetTransport {
    async fn send(&self, req: Request) -> Result<Response, ReqError> {
        let url = Url::parse(&req.url)
            .map_err(|e| ReqError::transport(format!("Invalid URL: {}", e)))?;

        let host = url.host_str()
            .ok_or_else(|| ReqError::transport("Missing hostname in URL".to_string()))?;
        let port = url.port_or_known_default()
            .ok_or_else(|| ReqError::transport("Missing port and no default".to_string()))?;
        let protocol = match url.scheme() {
            "https" => Protocol::Https,
            _ => Protocol::Http,
        };

        // Construit le path complet avec query string
        let path_and_query = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => url.path().to_string(),
        };
        let endpoint = if path_and_query.is_empty() { "/" } else { &path_and_query };

        // Pour les requêtes HTTP simples (non-SOGS), on envoie le body brut
        // Le snode exit fera la requête HTTP avec les infos du relay_metadata
        let body_payload = req.body.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);

        // Destination finale avec toutes les infos HTTP
        let destination = RelayDestination {
            host: host.to_string(),
            port,
            protocol,
            target: Some(endpoint.to_string()),
            method: Some(req.method.clone()),
        };

        // Récupère le chemin actuel
        let path = self.get_path().await?;

        // Envoie la requête via onion routing
        let (encrypted_response, symmetric_keys) = self.send_onion_request(
            &path,
            &destination,
            body_payload,
        ).await?;

        // Déchiffre la réponse
        let decrypted = self.decrypt_onion_response(&encrypted_response, &symmetric_keys)?;

        // Essaie de décoder comme V4 (pour SOGS), sinon comme JSON onion (serveurs externes)
        if let Ok(v4_response) = decode_v4_response(&decrypted) {
            // Réponse V4 (serveur SOGS compatible)
            let headers: Vec<(String, String)> = v4_response.headers.into_iter().collect();
            Ok(Response {
                status: v4_response.status_code,
                headers,
                body: Bytes::from(v4_response.body),
            })
        } else {
            // Réponse JSON onion (serveur HTTP externe)
            // Format: {"body": "...", "status": 200} ou {"body": "...", "code": 200}
            let wrapper: serde_json::Value = serde_json::from_slice(&decrypted)
                .map_err(|e| ReqError::parsing(format!("Failed to parse response: {}", e)))?;

            let status = wrapper.get("status")
                .or_else(|| wrapper.get("code"))
                .and_then(|s| s.as_u64())
                .unwrap_or(200) as u16;

            // Le body peut être une string ou un objet
            let body = if let Some(body_str) = wrapper.get("body").and_then(|b| b.as_str()) {
                body_str.as_bytes().to_vec()
            } else if let Some(body_val) = wrapper.get("body") {
                serde_json::to_vec(body_val).unwrap_or_default()
            } else {
                // Pas de wrapper, la réponse est directe
                decrypted
            };

            Ok(Response {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }
    }

    async fn recv(&self) -> Result<Response, ReqError> {
        Err(ReqError::other("recv() not implemented for LokinetTransport"))
    }
}

/// Variante du transport avec gestion avancée des erreurs et retry
pub struct LokinetTransportWithRetry {
    inner: LokinetTransport,
    max_retries: u32,
}

impl LokinetTransportWithRetry {
    /// Crée un transport avec retry automatique
    pub async fn new(max_retries: u32) -> Result<Self, ReqError> {
        Ok(Self {
            inner: LokinetTransport::new().await?,
            max_retries,
        })
    }

    /// Force une rotation du chemin
    pub async fn rotate_path(&self) -> Result<(), ReqError> {
        self.inner.rotate_path().await
    }

    /// Force un refresh des snodes
    pub async fn refresh_snodes(&self) -> Result<(), ReqError> {
        self.inner.refresh_snodes().await
    }
}

#[async_trait]
impl Transport for LokinetTransportWithRetry {
    async fn send(&self, req: Request) -> Result<Response, ReqError> {
        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            match self.inner.send(req.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);

                    if attempt < self.max_retries {
                        // Rotate vers un nouveau chemin et réessaye
                        let _ = self.inner.rotate_path().await;
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ReqError::transport("All retries failed")))
    }

    async fn recv(&self) -> Result<Response, ReqError> {
        self.inner.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Nécessite une connexion réseau
    async fn test_lokinet_transport_creation() {
        let result = LokinetTransport::new().await;
        assert!(result.is_ok(), "Failed to create transport: {:?}", result.err());
    }

    #[tokio::test]
    #[ignore] // Nécessite une connexion réseau
    async fn test_path_rotation() {
        let transport = LokinetTransport::new().await.unwrap();

        let path1 = transport.get_path().await.unwrap();
        transport.rotate_path().await.unwrap();
        let path2 = transport.get_path().await.unwrap();

        // Les chemins devraient être différents (avec haute probabilité)
        assert_eq!(path1.len(), PATH_LENGTH);
        assert_eq!(path2.len(), PATH_LENGTH);
    }
}
