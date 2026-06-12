//! Cryptographie pour le réseau Session/Lokinet
//!
//! Implémente le chiffrement X25519 + AES-256-GCM utilisé par Session Desktop.
//! La dérivation de clé utilise HMAC-SHA256 avec le salt "LOKI".

use crate::errors::errors::ReqError;
use zenth_crypto::exchange::curve25519::PrivateKey;
use zenth_crypto::symmetric::{Aes256GcmEncryption, Aes256GcmDecryption};
use zenth_crypto::kdf::hmac_sha256;
use rand::RngCore;

/// AES-256-GCM tag size (16 bytes)
const AES_GCM_TAG_SIZE: usize = 16;
/// AES-256-GCM nonce size (12 bytes)
const AES_GCM_NONCE_SIZE: usize = 12;

/// Salt utilisé par Session pour la dérivation de clé
const LOKI_SALT: &[u8] = b"LOKI";

/// Résultat du chiffrement pour un snode
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    /// Données chiffrées (nonce 12 bytes || ciphertext || tag)
    pub ciphertext: Vec<u8>,
    /// Clé publique éphémère à envoyer au snode
    pub ephemeral_key: [u8; 32],
    /// Clé symétrique pour déchiffrer la réponse
    pub symmetric_key: [u8; 32],
}

/// Chiffre des données pour un snode avec X25519 + AES-256-GCM
///
/// Utilise le même algorithme que Session Desktop:
/// 1. Génère une paire de clés éphémère X25519
/// 2. Calcule le secret partagé via ECDH
/// 3. Dérive la clé symétrique avec HMAC-SHA256(salt="LOKI", shared_secret)
/// 4. Chiffre avec AES-256-GCM (nonce random 12 bytes)
pub fn encrypt_for_snode(
    snode_pubkey_x25519: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedPayload, ReqError> {
    // Génère une paire de clés éphémère avec zenth_crypto
    let mut rng = rand::rngs::OsRng;
    let ephemeral_key = PrivateKey::new(&mut rng);
    let ephemeral_public = ephemeral_key.derive_public_key_bytes();

    // Diffie-Hellman pour obtenir le secret partagé
    let shared_secret = ephemeral_key.calculate_agreement(snode_pubkey_x25519);

    // Dérive la clé symétrique avec HMAC-SHA256 (comme Session Desktop)
    let symmetric_key = derive_symmetric_key(&shared_secret);

    // Génère un nonce random de 12 bytes
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);

    // Chiffre avec AES-256-GCM via zenth_crypto
    let mut encryption = Aes256GcmEncryption::new(&symmetric_key, &nonce_bytes, &[])
        .map_err(|e| ReqError::transport(format!("Failed to create AES cipher: {:?}", e)))?;

    // Copie le plaintext pour chiffrement en place
    let mut encrypted_data = plaintext.to_vec();
    encryption.encrypt(&mut encrypted_data);
    let tag = encryption.compute_tag();

    // Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    let mut ciphertext = Vec::with_capacity(AES_GCM_NONCE_SIZE + encrypted_data.len() + AES_GCM_TAG_SIZE);
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&encrypted_data);
    ciphertext.extend_from_slice(&tag);

    Ok(EncryptedPayload {
        ciphertext,
        ephemeral_key: ephemeral_public,
        symmetric_key,
    })
}

/// Déchiffre une réponse d'un snode avec la clé symétrique
///
/// Le ciphertext contient: nonce (12 bytes) || encrypted_data || tag (16 bytes)
pub fn decrypt_from_snode(
    symmetric_key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ReqError> {
    // Minimum: nonce (12) + tag (16) = 28 bytes
    if ciphertext.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
        return Err(ReqError::parsing("Ciphertext too short"));
    }

    // Les 12 premiers bytes sont le nonce
    let nonce = &ciphertext[..AES_GCM_NONCE_SIZE];
    // Les 16 derniers bytes sont le tag
    let tag = &ciphertext[ciphertext.len() - AES_GCM_TAG_SIZE..];
    // Le reste est le ciphertext
    let encrypted_data = &ciphertext[AES_GCM_NONCE_SIZE..ciphertext.len() - AES_GCM_TAG_SIZE];

    // Déchiffre avec AES-256-GCM via zenth_crypto
    let mut decryption = Aes256GcmDecryption::new(symmetric_key, nonce, &[])
        .map_err(|e| ReqError::transport(format!("Failed to create AES cipher: {:?}", e)))?;

    // Copie pour déchiffrement en place
    let mut decrypted_data = encrypted_data.to_vec();
    decryption.decrypt(&mut decrypted_data);

    // Vérifie le tag d'authentification
    decryption
        .verify_tag(tag)
        .map_err(|e| ReqError::transport(format!("AES decryption failed: {:?}", e)))?;

    Ok(decrypted_data)
}

/// Dérive une clé symétrique 32 bytes depuis le secret partagé
///
/// Utilise HMAC-SHA256 avec le salt "LOKI" comme Session Desktop:
/// symmetric_key = HMAC-SHA256(key=salt, message=shared_secret)
fn derive_symmetric_key(shared_secret: &[u8]) -> [u8; 32] {
    // Utilise hmac_sha256 de zenth_crypto
    hmac_sha256(LOKI_SALT, shared_secret)
}

/// Encode le format Session: len(4 bytes LE) || data || json_metadata
///
/// Utilisé pour les couches intermédiaires de l'onion (routing).
pub fn encode_ciphertext_plus_json(
    ciphertext: &[u8],
    metadata: &serde_json::Value,
) -> Vec<u8> {
    let json_bytes = serde_json::to_vec(metadata).unwrap_or_default();

    let len = ciphertext.len() as u32;
    let mut result = Vec::with_capacity(4 + ciphertext.len() + json_bytes.len());

    // Longueur en little-endian (4 bytes)
    result.extend_from_slice(&len.to_le_bytes());
    // Ciphertext
    result.extend_from_slice(ciphertext);
    // JSON metadata
    result.extend_from_slice(&json_bytes);

    result
}

/// Encode le format Session pour le body destination: len(4 bytes LE) || plaintext || json_metadata
///
/// Utilisé pour le payload final vers un snode destination.
/// Le format est identique à encode_ciphertext_plus_json mais sémantiquement
/// c'est le plaintext (body RPC) + les metadata de requête (body: null).
pub fn encode_plaintext_plus_json(
    plaintext: &[u8],
    metadata: &serde_json::Value,
) -> Vec<u8> {
    // Le format est identique
    encode_ciphertext_plus_json(plaintext, metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Génère une paire de clés pour simuler un snode avec zenth_crypto
        let mut rng = rand::rngs::OsRng;
        let snode_key = PrivateKey::new(&mut rng);
        let snode_public = snode_key.derive_public_key_bytes();

        let plaintext = b"Hello Session Network!";

        // Chiffre pour le "snode"
        let encrypted = encrypt_for_snode(&snode_public, plaintext).unwrap();

        // Le snode dérive la même clé symétrique avec sa clé privée + la clé éphémère
        let shared_secret = snode_key.calculate_agreement(&encrypted.ephemeral_key);
        let derived_key = derive_symmetric_key(&shared_secret);

        // Les clés doivent être identiques
        assert_eq!(derived_key, encrypted.symmetric_key);

        // Déchiffre avec la clé dérivée
        let decrypted = decrypt_from_snode(&derived_key, &encrypted.ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let shared_secret = [42u8; 32];
        let key1 = derive_symmetric_key(&shared_secret);
        let key2 = derive_symmetric_key(&shared_secret);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_encode_ciphertext_plus_json() {
        let ciphertext = vec![1, 2, 3, 4, 5];
        let metadata = serde_json::json!({"ephemeral_key": "abc123"});

        let encoded = encode_ciphertext_plus_json(&ciphertext, &metadata);

        // Vérifie le format: 4 bytes len + ciphertext + json
        assert_eq!(&encoded[0..4], &5u32.to_le_bytes());
        assert_eq!(&encoded[4..9], &[1, 2, 3, 4, 5]);
    }
}
