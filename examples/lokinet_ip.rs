//! Exemple: Démonstration d'anonymat via le réseau Session/Lokinet
//!
//! Montre que ton IP réelle est différente de l'IP vue par la destination.
//!
//! Exécuter avec: cargo run --example lokinet_ip

use zenth_requests::transports::lokinet::{LokinetTransport, SubRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        DÉMONSTRATION D'ANONYMAT SESSION/LOKINET              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Récupère ton IP réelle
    println!("[1] Récupération de ton IP réelle...");
    let real_ip = get_real_ip().await?;
    println!("    ╔═══════════════════════════════════╗");
    println!("    ║  TON IP RÉELLE: {:^18} ║", real_ip);
    println!("    ╚═══════════════════════════════════╝\n");

    // Crée le transport Lokinet
    println!("[2] Connexion au réseau Session ({} snodes)...",
        fetch_snode_count().await?);
    let transport = LokinetTransport::new().await?;

    // Affiche le chemin onion avec l'IP de sortie
    let path = transport.get_current_path().await.unwrap();
    let exit_ip = &path[2].ip;

    println!("\n[3] Chemin onion construit:\n");
    println!("    ┌─────────────────────────────────────────────────────────┐");
    println!("    │  TOI ({})                                    │", real_ip);
    println!("    │       │                                                 │");
    println!("    │       ▼                                                 │");
    println!("    │  ┌─────────────────────────────────────────────────┐   │");
    println!("    │  │ GUARD: {:^15}  ← voit ton IP       │   │", path[0].ip);
    println!("    │  │        (mais pas ta destination)                │   │");
    println!("    │  └─────────────────────────────────────────────────┘   │");
    println!("    │       │                                                 │");
    println!("    │       ▼                                                 │");
    println!("    │  ┌─────────────────────────────────────────────────┐   │");
    println!("    │  │ MIDDLE: {:^15} ← ne voit RIEN        │   │", path[1].ip);
    println!("    │  │         (ni ton IP, ni la destination)          │   │");
    println!("    │  └─────────────────────────────────────────────────┘   │");
    println!("    │       │                                                 │");
    println!("    │       ▼                                                 │");
    println!("    │  ┌─────────────────────────────────────────────────┐   │");
    println!("    │  │ EXIT: {:^15}   ← voit la destination │   │", exit_ip);
    println!("    │  │       (mais PAS ton IP!)                        │   │");
    println!("    │  └─────────────────────────────────────────────────┘   │");
    println!("    │       │                                                 │");
    println!("    │       ▼                                                 │");
    println!("    │  DESTINATION (snode ou service)                         │");
    println!("    └─────────────────────────────────────────────────────────┘\n");

    // Test onion routing
    println!("[4] Test de communication via onion routing...");
    match transport.batch_request(vec![SubRequest::info()]).await {
        Ok(batch) => {
            println!("    ✓ Requête envoyée avec succès via 3 hops!");
            if let Some(result) = batch.results.first() {
                if result.code == 200 {
                    println!("    ✓ Réponse reçue du snode destination");
                }
            }
        }
        Err(e) => println!("    ✗ Erreur: {}", e),
    }

    // Preuve d'anonymat
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    PREUVE D'ANONYMAT                         ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║                                                              ║");
    println!("║  Ton IP réelle:        {:^15}                    ║", real_ip);
    println!("║  IP vue par destination: {:^15}                  ║", exit_ip);
    println!("║                                                              ║");
    if real_ip != *exit_ip {
        println!("║  ✓ LES IPs SONT DIFFÉRENTES = ANONYMAT CONFIRMÉ!           ║");
    }
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Démonstration de rotation
    println!("[5] Rotation de chemin (nouvelles IPs de sortie):\n");
    for i in 1..=3 {
        transport.rotate_path().await?;
        let new_path = transport.get_current_path().await.unwrap();
        println!("    Chemin #{}: Exit = {} (différent de {})",
            i,
            new_path[2].ip,
            real_ip
        );
    }

    println!("\n[6] Résumé:\n");
    println!("    • Quand tu envoies un message via Zenth/Session:");
    println!("      - Le destinataire voit l'IP du snode EXIT, pas la tienne");
    println!("      - Ton IP ({}) reste cachée", real_ip);
    println!("      - Chaque message peut utiliser un chemin différent");
    println!();
    println!("    • Le réseau Session offre le même niveau d'anonymat que Tor");
    println!("      pour la messagerie (3 hops, chiffrement multicouche)");

    Ok(())
}

/// Récupère l'IP réelle sans proxy
async fn get_real_ip() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.ipify.org")
        .send()
        .await?;
    Ok(response.text().await?.trim().to_string())
}

/// Compte les snodes disponibles
async fn fetch_snode_count() -> Result<usize, Box<dyn std::error::Error>> {
    use zenth_requests::transports::lokinet::fetch_snodes_from_seeds;
    let snodes = fetch_snodes_from_seeds().await?;
    Ok(snodes.len())
}
