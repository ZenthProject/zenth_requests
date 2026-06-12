use crate::errors::errors::ReqError;
use super::crypto::{encrypt_for_snode, encode_ciphertext_plus_json, EncryptedPayload};
use super::snode::Snode;
use serde::Serialize;
use std::collections::HashMap;

/// Destination finale pour le relais (serveur externe, pas un snode)
#[derive(Debug, Clone)]
pub struct RelayDestination {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    /// Target path (default: /)
    pub target: Option<String>,
    /// HTTP method (default: GET)
    pub method: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Http,
    Https,
}

/// Informations pour encoder une requête V4
#[derive(Debug, Clone, Serialize)]
pub struct RequestInfoV4 {
    pub method: String,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

/// Résultat de la construction d'un payload onion
#[derive(Debug)]
pub struct OnionPayload {
    /// Payload final à envoyer au guard node: [4 bytes len][ciphertext][{ephemeral_key}]
    pub data: Vec<u8>,
    /// Clés symétriques pour déchiffrer les réponses (de l'extérieur vers l'intérieur)
    /// Index 0 = guard, dernier = destination finale
    pub symmetric_keys: Vec<[u8; 32]>,
}

/// Construit un payload onion pour une chaîne de snodes
///
/// Architecture Session Desktop:
/// - Le payload est construit de l'intérieur vers l'extérieur
/// - Chaque couche contient: [4 bytes len][ciphertext][JSON metadata]
/// - Le JSON metadata contient `ephemeral_key` et les infos de routage
///
/// # Arguments
/// * `path` - Liste des snodes (guard, middle, exit) - minimum 1, typiquement 3
/// * `body` - Corps de la requête à envoyer à la destination finale
/// * `final_relay` - Si Some, le dernier snode relayera vers ce serveur externe
///                   Si None, le dernier snode est la destination
///
/// # Retourne
/// Le payload chiffré multi-couche + les clés symétriques pour déchiffrer
pub fn build_onion_payload(
    path: &[Snode],
    body: &[u8],
    final_relay: Option<&RelayDestination>,
) -> Result<OnionPayload, ReqError> {
    if path.is_empty() {
        return Err(ReqError::transport("Path cannot be empty"));
    }

    let mut symmetric_keys = Vec::with_capacity(path.len());
    let last_snode = path.last().unwrap();
    let last_index = path.len() - 1;

    // === Étape 1: Chiffrer pour le dernier snode (exit) ===
    let mut current = if let Some(relay) = final_relay {
        // Le dernier snode doit relayer vers un serveur externe
        // On encode: [len][body][{host, port, protocol, target, method}]
        let relay_metadata = serde_json::json!({
            "host": relay.host,
            "target": relay.target.as_deref().unwrap_or("/"),
            "method": relay.method.as_deref().unwrap_or("GET"),
            "protocol": match relay.protocol {
                Protocol::Http => "http",
                Protocol::Https => "https",
            },
            "port": relay.port
        });
        let inner_payload = encode_ciphertext_plus_json(body, &relay_metadata);
        encrypt_for_snode(&last_snode.pubkey_x25519, &inner_payload)?
    } else {
        // Le dernier snode EST la destination (pas de relay externe)
        encrypt_for_snode(&last_snode.pubkey_x25519, body)?
    };
    symmetric_keys.push(current.symmetric_key);

    // === Étape 2: Construire les couches intermédiaires ===
    // On remonte du dernier snode vers le guard (de l'intérieur vers l'extérieur)
    // path = [guard, middle, exit]
    // i = 1 (middle), puis i = 0 (guard)

    for i in (0..last_index).rev() {
        let this_snode = &path[i];
        let next_snode = &path[i + 1];

        // Route vers le prochain snode (utilise ED25519 pour identifier le snode)
        let relay_info = serde_json::json!({
            "destination": hex::encode(next_snode.pubkey_ed25519),
            "ephemeral_key": hex::encode(current.ephemeral_key)
        });

        // Encode: [4 bytes len][ciphertext][JSON metadata]
        let payload = encode_ciphertext_plus_json(&current.ciphertext, &relay_info);

        // Chiffre cette couche pour ce snode
        current = encrypt_for_snode(&this_snode.pubkey_x25519, &payload)?;
        symmetric_keys.push(current.symmetric_key);
    }

    // === Étape 3: Payload final pour le guard node ===
    // Format: [4 bytes len][ciphertext][{ephemeral_key: "hex"}]
    let guard_metadata = serde_json::json!({
        "ephemeral_key": hex::encode(current.ephemeral_key)
    });
    let final_payload = encode_ciphertext_plus_json(&current.ciphertext, &guard_metadata);

    // Inverse les clés pour que index 0 = guard, dernier = destination
    symmetric_keys.reverse();

    Ok(OnionPayload {
        data: final_payload,
        symmetric_keys,
    })
}

/// Encode une requête au format V4 (bencode-like)
///
/// Format: l<len>:<json_without_body><body_len>:<body>e
/// Si pas de body: l<len>:<json>e
pub fn encode_v4_request(
    method: &str,
    endpoint: &str,
    headers: Option<&HashMap<String, String>>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let info = RequestInfoV4 {
        method: method.to_string(),
        endpoint: endpoint.to_string(),
        headers: headers.cloned(),
    };

    let json_bytes = serde_json::to_vec(&info).unwrap_or_default();
    let prefix = format!("l{}:", json_bytes.len());

    let mut result = Vec::new();
    result.extend_from_slice(prefix.as_bytes());
    result.extend_from_slice(&json_bytes);

    if let Some(body_data) = body {
        let body_prefix = format!("{}:", body_data.len());
        result.extend_from_slice(body_prefix.as_bytes());
        result.extend_from_slice(body_data);
    }

    result.push(b'e');
    result
}

/// Décode une réponse V4
///
/// Format: l<len>:<metadata_json><body_len>:<body>e
pub fn decode_v4_response(data: &[u8]) -> Result<DecodedResponseV4, ReqError> {
    if data.len() < 3 {
        return Err(ReqError::parsing("Response too short"));
    }

    if data[0] != b'l' || data[data.len() - 1] != b'e' {
        return Err(ReqError::parsing("Invalid V4 response format"));
    }

    // Parse metadata length
    let first_colon = data.iter().position(|&b| b == b':')
        .ok_or_else(|| ReqError::parsing("Missing colon in V4 response"))?;

    let len_str = std::str::from_utf8(&data[1..first_colon])
        .map_err(|_| ReqError::parsing("Invalid length encoding"))?;

    let metadata_len: usize = len_str.parse()
        .map_err(|_| ReqError::parsing("Invalid metadata length"))?;

    let metadata_start = first_colon + 1;
    let metadata_end = metadata_start + metadata_len;

    if metadata_end > data.len() {
        return Err(ReqError::parsing("Metadata length exceeds data"));
    }

    let metadata: ResponseMetadata = serde_json::from_slice(&data[metadata_start..metadata_end])
        .map_err(|e| ReqError::parsing(format!("Failed to parse metadata: {}", e)))?;

    // Parse body
    let body_start_search = metadata_end;
    let second_colon = data[body_start_search..].iter().position(|&b| b == b':')
        .map(|p| p + body_start_search);

    let body = if let Some(colon_pos) = second_colon {
        let body_len_str = std::str::from_utf8(&data[metadata_end..colon_pos])
            .map_err(|_| ReqError::parsing("Invalid body length encoding"))?;

        let body_len: usize = body_len_str.parse()
            .map_err(|_| ReqError::parsing("Invalid body length"))?;

        let body_start = colon_pos + 1;
        let body_end = body_start + body_len;

        if body_end > data.len() - 1 {
            return Err(ReqError::parsing("Body length exceeds data"));
        }

        data[body_start..body_end].to_vec()
    } else {
        Vec::new()
    };

    Ok(DecodedResponseV4 {
        status_code: metadata.code,
        headers: metadata.headers.unwrap_or_default(),
        body,
    })
}

#[derive(Debug, serde::Deserialize)]
struct ResponseMetadata {
    code: u16,
    headers: Option<HashMap<String, String>>,
}

/// Réponse V4 décodée
#[derive(Debug)]
pub struct DecodedResponseV4 {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Construit un payload onion avec une destination déjà chiffrée
///
/// Cette variante est utilisée quand on a un snode destination externe au chemin.
/// Le `dest_ctx` contient déjà le ciphertext chiffré pour la destination.
///
/// # Arguments
/// * `path` - Liste des snodes du chemin (guard, middle, exit)
/// * `dest_ctx` - Contexte de chiffrement pour le snode destination
/// * `destination_snode` - Le snode destination (externe au chemin)
///
/// # Retourne
/// Le payload chiffré multi-couche
pub fn build_onion_payload_with_dest(
    path: &[Snode],
    dest_ctx: &EncryptedPayload,
    destination_snode: &Snode,
) -> Result<OnionPayload, ReqError> {
    if path.is_empty() {
        return Err(ReqError::transport("Path cannot be empty"));
    }

    let mut symmetric_keys = Vec::with_capacity(path.len() + 1);

    // La clé de destination est déjà dans dest_ctx
    symmetric_keys.push(dest_ctx.symmetric_key);

    // Commence avec le ciphertext de destination
    let mut current = dest_ctx.clone();

    // Construit les couches du chemin (de la fin vers le début)
    // Le dernier snode (exit) doit relayer vers le snode destination
    for i in (0..path.len()).rev() {
        let this_snode = &path[i];

        // Métadonnées de routage
        let relay_info = if i == path.len() - 1 {
            // Dernier snode du chemin: relay vers le snode destination
            serde_json::json!({
                "destination": hex::encode(destination_snode.pubkey_ed25519),
                "ephemeral_key": hex::encode(current.ephemeral_key)
            })
        } else {
            // Snode intermédiaire: relay vers le prochain snode du chemin
            let next_snode = &path[i + 1];
            serde_json::json!({
                "destination": hex::encode(next_snode.pubkey_ed25519),
                "ephemeral_key": hex::encode(current.ephemeral_key)
            })
        };

        // Encode: [4 bytes len][ciphertext][JSON metadata]
        let payload = encode_ciphertext_plus_json(&current.ciphertext, &relay_info);

        // Chiffre cette couche pour ce snode
        current = encrypt_for_snode(&this_snode.pubkey_x25519, &payload)?;
        symmetric_keys.push(current.symmetric_key);
    }

    // Payload final pour le guard node
    let guard_metadata = serde_json::json!({
        "ephemeral_key": hex::encode(current.ephemeral_key)
    });
    let final_payload = encode_ciphertext_plus_json(&current.ciphertext, &guard_metadata);

    // Inverse les clés pour que index 0 = guard, dernier = destination
    symmetric_keys.reverse();

    Ok(OnionPayload {
        data: final_payload,
        symmetric_keys,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_v4_request_no_body() {
        let encoded = encode_v4_request("GET", "/test", None, None);
        let s = String::from_utf8_lossy(&encoded);

        assert!(s.starts_with("l"));
        assert!(s.ends_with("e"));
        assert!(s.contains("GET"));
        assert!(s.contains("/test"));
    }

    #[test]
    fn test_encode_v4_request_with_body() {
        let body = b"hello";
        let encoded = encode_v4_request("POST", "/api", None, Some(body));
        let s = String::from_utf8_lossy(&encoded);

        assert!(s.contains("5:hello"));
    }
}
