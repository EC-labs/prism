use anyhow::Result;
use reqwest::Client;
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::builder().pool_max_idle_per_host(2).build()?;
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf: [u8; 256] = [0; 256];
        while let Ok(bytes) = stdin.read(&mut buf).await {
            println!("{:?}", bytes);
            let res = client.get("http://localhost:3000/api").send().await?;
            println!("{:?}", res.text().await?);
        }

        Ok(()) as Result<()>
    }).await;

    Ok(())
}
