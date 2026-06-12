//! Exemple basique d'utilisation du module Lokinet/Session
//!
//! Exécuter avec: cargo run --example lokinet_basic

use zenth_requests::transports::lokinet::{
    fetch_snodes_from_seeds,
    LokinetTransport,
    SEED_NODES,
};
use zenth_requests::transports::lokinet::session_rpc::SubRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Exemple Lokinet/Session pour Zenth ===\n");

    // =========================================
    // 1. BOOTSTRAP - Récupérer les Service Nodes
    // =========================================
    println!("[1] Récupération des snodes depuis les seed nodes...");
    println!("    Seeds disponibles: {:?}\n", SEED_NODES);

    let snodes = fetch_snodes_from_seeds().await?;
    println!("    {} snodes récupérés\n", snodes.len());

    // Affiche quelques snodes
    println!("[2] Exemples de snodes:");
    for (i, snode) in snodes.iter().take(3).enumerate() {
        println!("    Snode #{}:", i + 1);
        println!("      IP:Port     = {}:{}", snode.ip, snode.port);
        println!("      X25519      = {}...", &snode.x25519_hex()[..16]);
        println!("      Ed25519     = {}...", &snode.ed25519_hex()[..16]);
        println!();
    }

    // =========================================
    // 2. CRÉATION DU TRANSPORT LOKINET
    // =========================================
    println!("[3] Création du transport Lokinet...");
    let transport = LokinetTransport::new().await?;

    let path = transport.get_current_path().await.unwrap();
    println!("    Chemin onion (3 hops):");
    println!("      Guard:  {}:{}", path[0].ip, path[0].port);
    println!("      Middle: {}:{}", path[1].ip, path[1].port);
    println!("      Exit:   {}:{}", path[2].ip, path[2].port);
    println!();

    // =========================================
    // 3. TEST DIRECT RPC (sans onion routing)
    // =========================================
    println!("[4] Test Direct RPC (sans onion)...");
    let random_snode = transport.get_random_snode().await?;
    println!("    Snode: {}:{}", random_snode.ip, random_snode.port);

    match transport.direct_rpc(&random_snode, "info", serde_json::json!({})).await {
        Ok(response) => {
            println!("    Direct RPC OK!");
            if let Some(result) = response.get("result") {
                if let Some(version) = result.get("version") {
                    println!("    Version: {:?}", version);
                }
                if let Some(timestamp) = result.get("timestamp") {
                    println!("    Timestamp: {}", timestamp);
                }
            }
        }
        Err(e) => println!("    Direct RPC Error: {}", e),
    }
    println!();

    // =========================================
    // 4. TEST ONION ROUTING - Batch Request
    // =========================================
    println!("[5] Test Onion Routing - Batch Request (info)...");

    match transport.batch_request(vec![SubRequest::info()]).await {
        Ok(batch) => {
            println!("    Batch request OK!");
            for (i, result) in batch.results.iter().enumerate() {
                println!("    Result #{}: code={}", i, result.code);
                if result.code == 200 {
                    println!("    Body: {:?}", result.body);
                }
            }
        }
        Err(e) => {
            println!("    Batch request Error: {}", e);
            println!();

            // Test avec format simple
            println!("[6] Test Onion Routing - Simple RPC...");
            match transport.storage_rpc("info", serde_json::json!({})).await {
                Ok(response) => {
                    println!("    Simple RPC OK!");
                    println!("    Response: {:?}", response);
                }
                Err(e) => println!("    Simple RPC Error: {}", e),
            }
        }
    }
    println!();

    // =========================================
    // 5. TEST INFO via helper
    // =========================================
    println!("[7] Test info() helper...");
    match transport.info().await {
        Ok(info) => {
            println!("    Info OK!");
            println!("    {:?}", info);
        }
        Err(e) => println!("    Info Error: {}", e),
    }
    println!();

    // =========================================
    // 6. ROTATION DE CHEMIN
    // =========================================
    println!("[8] Rotation du chemin...");
    transport.rotate_path().await?;
    let new_path = transport.get_current_path().await.unwrap();
    println!("    Nouveau chemin:");
    println!("      Guard:  {}:{}", new_path[0].ip, new_path[0].port);
    println!("      Middle: {}:{}", new_path[1].ip, new_path[1].port);
    println!("      Exit:   {}:{}", new_path[2].ip, new_path[2].port);
    println!();

    println!("=== Exemple terminé ===");
    Ok(())
}
