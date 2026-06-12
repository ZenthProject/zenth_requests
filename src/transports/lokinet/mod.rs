//! Module Lokinet/Session pour zenth_requests
//!
//! Fournit les primitives pour communiquer via l'infrastructure Session:
//! - Récupération des Service Nodes depuis les seed nodes
//! - Chiffrement X25519 + AES-256-GCM pour les snodes
//! - Construction des payloads onion
//! - Format des requêtes RPC Session (JSON-RPC 2.0)
//! - Transport onion-routed compatible avec le trait Transport

pub mod snode;
pub mod crypto;
pub mod payload;
pub mod session_rpc;
pub mod transport;

pub use snode::{Snode, fetch_snodes_from_seeds, fetch_snodes_from_seed, SEED_NODES};
pub use crypto::{encrypt_for_snode, decrypt_from_snode, encode_ciphertext_plus_json, encode_plaintext_plus_json, EncryptedPayload};
pub use payload::{build_onion_payload, build_onion_payload_with_dest, encode_v4_request, decode_v4_response, RelayDestination, Protocol, OnionPayload};
pub use session_rpc::{SessionRpcRequest, SubRequest, BatchResponse};
pub use transport::{LokinetTransport, LokinetTransportWithRetry};
