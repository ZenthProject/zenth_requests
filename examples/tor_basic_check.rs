use tokio;

use zenth_requests::{
    request::Request,
    response::Response,
    errors::errors::ReqError,
    transports::tor::TorTransport,
    transports::Transport,
};

#[tokio::main]
async fn main() -> Result<(), ReqError> {
    // 1️⃣ Créer le transport Tor
    println!("Bootstrapping Tor...");
    let tor_transport = TorTransport::new().await?;
    println!("Tor transport ready!");

    // 2️⃣ Construire une requête HTTP GET
    let req = Request {
        url: "https://httpbin.org/get".to_string(), // HTTPS
        method: "GET".to_string(),
        headers: vec![("Connection".to_string(), "close".to_string())],
        body: None,
    };


    // 3️⃣ Envoyer la requête via Tor
    println!("Sending request via Tor...");
    let resp: Response = tor_transport.send(req).await?;

    // 4️⃣ Afficher la réponse
    println!("Status: {}", resp.status);
    println!("Headers:");
    for (k, v) in resp.headers.iter() {
        println!("{}: {}", k, v);
    }

    let body_str = String::from_utf8_lossy(&resp.body);
    println!("Body:\n{}", body_str);

    Ok(())
}
