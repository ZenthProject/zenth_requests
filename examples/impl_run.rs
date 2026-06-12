use zenth_requests::implementations::RequestsNetwork;
use zenth_requests::request::Request;
use zenth_requests::errors::errors::ReqError;

#[tokio::main]
async fn main() -> Result<(), ReqError> {
    // Crée le transport Tor
    let network = RequestsNetwork::new("TOR").await?;

    // Prépare une requête simple
    let req = Request {
        method: "GET".to_string(),
        url: "https://check.torproject.org/".to_string(),
        headers: vec![],
        body: None,
    };

    // Envoie la requête via le transport Tor
    let resp = network.send(req).await?;

    println!("Status: {}", resp.status);
    println!("Headers: {:?}", resp.headers);
    println!("Body: {}", String::from_utf8_lossy(&resp.body));

    Ok(())
}
