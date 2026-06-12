//! Exemple d'utilisation du transport Lokinet/Session
//!
//! Démontre l'utilisation du wrapper LokinetTransport pour communiquer
//! via le réseau Session (onion routing avec 3 hops).
//!
//! **Important:** Le réseau Session est conçu pour la messagerie, pas comme
//! un proxy HTTP généraliste. Ce transport permet les requêtes vers les snodes.
//!
//! Usage: cargo run --example lokinet_transport

use zenth_requests::transports::lokinet::LokinetTransport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Test du LokinetTransport ===\n");

    // =========================================
    // 1. INITIALISATION
    // =========================================
    println!("[1] Initialisation du transport Lokinet...");
    println!("    - Récupération des Service Nodes depuis les seeds");
    println!("    - Sélection d'un chemin de 3 snodes (guard → middle → exit)");
    println!();

    let transport = match LokinetTransport::new().await {
        Ok(t) => {
            println!("[+] Transport initialisé avec succès!");
            t
        }
        Err(e) => {
            println!("[-] Erreur lors de l'initialisation: {}", e);
            return Err(e.into());
        }
    };

    // =========================================
    // 2. AFFICHAGE DES INFOS
    // =========================================
    let snodes = transport.get_snodes().await;
    println!("    {} snodes disponibles", snodes.len());

    if let Some(path) = transport.get_current_path().await {
        println!("\n[2] Chemin onion actuel:");
        println!("    Guard:  {}:{}", path[0].ip, path[0].port);
        println!("    Middle: {}:{}", path[1].ip, path[1].port);
        println!("    Exit:   {}:{}", path[2].ip, path[2].port);
    }

    // =========================================
    // 3. TEST REQUÊTE DIRECTE (sans onion)
    // =========================================
    println!("\n[3] Test d'une requête directe à un snode...");

    let random_snode = transport.get_random_snode().await?;
    println!("    Snode cible: {}:{}", random_snode.ip, random_snode.port);

    // Test avec oxend_request pour avoir des stats
    match transport.direct_rpc(&random_snode, "info", serde_json::json!({})).await {
        Ok(response) => {
            println!("[+] Réponse directe reçue!");
            if let Some(result) = response.get("result") {
                println!("    Version: {:?}", result.get("version"));
                println!("    Network: {:?}", result.get("network"));
            } else {
                println!("    {:?}", response);
            }
        }
        Err(e) => {
            println!("[-] Erreur: {}", e);
        }
    }

    // =========================================
    // 3b. TEST GET_SNODES via RPC direct
    // =========================================
    println!("\n[3b] Test get_snodes via RPC direct...");

    match transport.direct_rpc(&random_snode, "get_snodes_for_pubkey", serde_json::json!({
        "pubKey": "05".to_string() + &"a".repeat(64)
    })).await {
        Ok(response) => {
            println!("[+] Réponse get_snodes reçue!");
            println!("    {:?}", response);
        }
        Err(e) => {
            println!("[-] Erreur: {}", e);
        }
    }

    // =========================================
    // 4. TEST REQUÊTE ONION (via le chemin de 3 snodes)
    // =========================================
    println!("\n[4] Test d'une requête via ONION ROUTING...");
    println!("    Guard → Middle → Exit → Destination");

    // Encode une requête RPC simple
    let rpc_body = serde_json::to_vec(&serde_json::json!({
        "method": "info",
        "params": {}
    }))?;

    match transport.send_to_snode(&rpc_body).await {
        Ok(response) => {
            println!("[+] Réponse ONION reçue!");
            let response_str = String::from_utf8_lossy(&response);
            if response_str.len() > 200 {
                println!("    {}...", &response_str[..200]);
            } else {
                println!("    {}", response_str);
            }
        }
        Err(e) => {
            println!("[-] Erreur onion: {}", e);
        }
    }

    // Test avec storage_rpc via onion
    println!("\n[4b] Test storage_rpc via onion...");
    match transport.storage_rpc("info", serde_json::json!({})).await {
        Ok(response) => {
            println!("[+] storage_rpc via onion réussi!");
            println!("    {:?}", response);
        }
        Err(e) => {
            println!("[-] Erreur: {}", e);
        }
    }

    // =========================================
    // 5. ROTATION DU CHEMIN
    // =========================================
    println!("\n[5] Test de rotation du chemin...");
    transport.rotate_path().await?;

    if let Some(new_path) = transport.get_current_path().await {
        println!("[+] Nouveau chemin:");
        println!("    Guard:  {}:{}", new_path[0].ip, new_path[0].port);
        println!("    Middle: {}:{}", new_path[1].ip, new_path[1].port);
        println!("    Exit:   {}:{}", new_path[2].ip, new_path[2].port);
    }

    // =========================================
    // 6. EXEMPLE D'UTILISATION AVEC ZENTH
    // =========================================
    println!("\n[6] Exemple d'intégration avec Zenth:");
    println!(r#"
    use zenth_requests::transports::lokinet::LokinetTransport;
    use zenth_requests::transports::Transport;

    // Pour messagerie Session
    let transport = LokinetTransport::new().await?;

    // Récupérer le swarm d'un utilisateur
    let swarm = transport.get_swarm("05abc...").await?;

    // Envoyer un message via storage RPC
    let result = transport.storage_rpc("store", json!({{
        "pubkey": "05abc...",
        "data": base64_encoded_message
    }})).await?;
"#);

    println!("\n=== Test terminé ===");
    Ok(())
}
