use poem::{
    get, handler, listener::TcpListener, middleware::Tracing, web::Path, EndpointExt, Route, Server,
};
use reqwest::Client;
use tokio::io::AsyncReadExt;

#[handler]
async fn hello() -> String {
    let client = Client::new();
    let req = client.get("http://localhost:7878/cpu");
    let res = req.send().await.unwrap();
    format!("{:?}", res.status())
}

async fn read_stdin() -> Result<(), std::io::Error> {
    let mut stdin = tokio::io::stdin();
    let mut buf: [u8; 256] = [0; 256];
    loop {
        let bytes = stdin.read(&mut buf).await.unwrap();
        let input = String::from_utf8(buf[..bytes].into()).unwrap();
        let input = input.trim();
        if input == "exit" {
            break;
        }
        println!("{:?}", input);
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }

    let app = Route::new().at("/api", get(hello)).with(Tracing);
    let mut handles = [
        tokio::spawn(
            Server::new(TcpListener::bind("[::1]:3001"))
                .name("hello-world")
                .run(app),
        ),
        tokio::spawn(read_stdin()),
    ];

    for handle in handles.iter_mut() {
        handle.await;
    }

    Ok(())
}
