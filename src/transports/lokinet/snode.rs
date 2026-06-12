use serde::{Deserialize, Serialize};
use crate::errors::errors::ReqError;

/// Service Node du réseau Session/Oxen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snode {
    pub ip: String,
    pub port: u16,
    #[serde(with = "hex_bytes")]
    pub pubkey_x25519: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub pubkey_ed25519: [u8; 32],
}

/// Réponse brute d'un seed node
#[derive(Debug, Deserialize)]
struct SeedNodeResponse {
    result: SeedNodeResult,
}

#[derive(Debug, Deserialize)]
struct SeedNodeResult {
    service_node_states: Vec<RawSnode>,
}

#[derive(Debug, Deserialize)]
struct RawSnode {
    public_ip: String,
    storage_port: u16,
    pubkey_x25519: String,
    pubkey_ed25519: String,
}

/// Liste des seed nodes officiels Session
pub const SEED_NODES: &[&str] = &[
    "https://seed1.getsession.org:4443/json_rpc",
    "https://seed2.getsession.org:4443/json_rpc",
    "https://seed3.getsession.org:4443/json_rpc",
];

/// Requête JSON-RPC pour obtenir les service nodes
#[derive(Serialize)]
struct GetServiceNodesRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: GetServiceNodesParams,
}

#[derive(Serialize)]
struct GetServiceNodesParams {
    active_only: bool,
    fields: RequestedFields,
}

#[derive(Serialize)]
struct RequestedFields {
    public_ip: bool,
    storage_port: bool,
    pubkey_x25519: bool,
    pubkey_ed25519: bool,
}

impl Default for GetServiceNodesRequest {
    fn default() -> Self {
        Self {
            jsonrpc: "2.0",
            method: "get_n_service_nodes",
            params: GetServiceNodesParams {
                active_only: true,
                fields: RequestedFields {
                    public_ip: true,
                    storage_port: true,
                    pubkey_x25519: true,
                    pubkey_ed25519: true,
                },
            },
        }
    }
}

/// Récupère la liste des snodes depuis les seed nodes officiels
/// Essaie chaque seed node jusqu'à ce qu'un réponde
pub async fn fetch_snodes_from_seeds() -> Result<Vec<Snode>, ReqError> {
    let mut last_error = None;

    for seed_url in SEED_NODES {
        match fetch_snodes_from_seed(seed_url).await {
            Ok(snodes) if !snodes.is_empty() => {
                return Ok(snodes);
            }
            Ok(_) => {
                last_error = Some(ReqError::transport("Seed returned empty snode list"));
            }
            Err(e) => {
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| ReqError::transport("All seed nodes failed")))
}

/// Récupère les snodes depuis un seed node spécifique
pub async fn fetch_snodes_from_seed(seed_url: &str) -> Result<Vec<Snode>, ReqError> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Seeds utilisent des certs self-signed
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ReqError::transport(format!("Failed to create HTTP client: {}", e)))?;

    let request_body = GetServiceNodesRequest::default();

    let response = client
        .post(seed_url)
        .header("User-Agent", "WhatsApp")
        .header("Accept-Language", "en-us")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| ReqError::transport(format!("Seed node request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(ReqError::transport(format!(
            "Seed node returned status: {}",
            response.status()
        )));
    }

    let seed_response: SeedNodeResponse = response
        .json()
        .await
        .map_err(|e| ReqError::parsing(format!("Failed to parse seed response: {}", e)))?;

    let snodes = seed_response
        .result
        .service_node_states
        .into_iter()
        .filter_map(|raw| parse_raw_snode(raw).ok())
        .collect();

    Ok(snodes)
}

/// Parse un snode brut en Snode typé
fn parse_raw_snode(raw: RawSnode) -> Result<Snode, ReqError> {
    let pubkey_x25519 = hex::decode(&raw.pubkey_x25519)
        .map_err(|e| ReqError::parsing(format!("Invalid x25519 key: {}", e)))?;

    let pubkey_ed25519 = hex::decode(&raw.pubkey_ed25519)
        .map_err(|e| ReqError::parsing(format!("Invalid ed25519 key: {}", e)))?;

    if pubkey_x25519.len() != 32 || pubkey_ed25519.len() != 32 {
        return Err(ReqError::parsing("Invalid key length"));
    }

    let mut x25519_arr = [0u8; 32];
    let mut ed25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(&pubkey_x25519);
    ed25519_arr.copy_from_slice(&pubkey_ed25519);

    Ok(Snode {
        ip: raw.public_ip,
        port: raw.storage_port,
        pubkey_x25519: x25519_arr,
        pubkey_ed25519: ed25519_arr,
    })
}

/// Helper pour sérialiser/désérialiser les clés en hex
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid key length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl Snode {
    /// URL de base pour les requêtes onion
    pub fn onion_url(&self) -> String {
        format!("https://{}:{}/onion_req/v2", self.ip, self.port)
    }

    /// URL pour les requêtes RPC storage
    pub fn storage_url(&self) -> String {
        format!("https://{}:{}/storage_rpc/v1", self.ip, self.port)
    }

    /// Clé ed25519 en hex (pour logging/debug)
    pub fn ed25519_hex(&self) -> String {
        hex::encode(self.pubkey_ed25519)
    }

    /// Clé x25519 en hex
    pub fn x25519_hex(&self) -> String {
        hex::encode(self.pubkey_x25519)
    }
}
