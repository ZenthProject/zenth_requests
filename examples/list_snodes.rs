//! Liste tous les snodes du réseau Session
//!
//! Exécuter avec: cargo run --example list_snodes

use zenth_requests::transports::lokinet::fetch_snodes_from_seeds;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching snodes from Session network...\n");

    let snodes = fetch_snodes_from_seeds().await?;

    println!("=== {} SERVICE NODES ===\n", snodes.len());

    for (i, snode) in snodes.iter().enumerate() {
        println!(
            "[{:4}] {}:{:<5}  x25519={}  ed25519={}",
            i + 1,
            snode.ip,
            snode.port,
            snode.x25519_hex(),
            snode.ed25519_hex()
        );
    }

    println!("\n=== Total: {} snodes ===", snodes.len());
    Ok(())
}
