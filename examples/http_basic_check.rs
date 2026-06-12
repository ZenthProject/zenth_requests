
use zenth_requests::{
    request::Request,
    implementations::RequestsNetwork
};


#[tokio::main]
async fn main() {
    let transport = RequestsNetwork::new("http")
        .await
        .expect("Cannot create transport");

    let req_get = Request {
        method: "GET".into(),
        url: "https://httpbin.org/get".into(),
        headers: vec![("User-Agent".into(), "RustClient".into())],
        body: None,
    };

    let response_get = transport.send(req_get).await.unwrap();

    println!("GET status: {}", response_get.status);
    println!("GET body: {}", String::from_utf8_lossy(&response_get.body));

    let req_post = Request {
        method: "POST".into(),
        url: "https://httpbin.org/post".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: Some(r#"{"test": "ok"}"#.as_bytes().to_vec().into()),
    };

    let response_post = transport.send(req_post).await.unwrap();

    println!("POST status: {}", response_post.status);
    println!("POST body: {}", String::from_utf8_lossy(&response_post.body));
}
