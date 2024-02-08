use chrono::prelude::*;
use eyre::Result;
use reqwest::Client;
use std::sync::Arc;
use tokio::{
    sync::Mutex,
    time::{self, Duration as tDuration},
};

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let response_times: Arc<Mutex<Vec<(String, chrono::Duration)>>> =
        Arc::new(Mutex::new(Vec::new()));
    for nreq in [1, 1, 2, 3] {
        for req_id in 0..nreq {
            let response_times = response_times.clone();
            let handle = tokio::spawn(async move {
                let sleep_time = (1000 / nreq) * req_id;
                println!("sleep_time: {:?}", sleep_time);
                time::sleep(tDuration::from_millis(sleep_time)).await;
                let client = Client::new();
                let start = Utc::now();
                let response = client
                    .get("http://localhost:7878/cpu")
                    .send()
                    .await
                    .unwrap();
                let current_time = Utc::now();
                let response_time = current_time.signed_duration_since(start);
                response_times
                    .lock()
                    .await
                    .push((current_time.to_string(), response_time));

                println!(
                    "req_id {:?}: {:?}-{:?}",
                    req_id,
                    response.status(),
                    response_time.to_std().unwrap().as_millis()
                );
            });
        }
        time::sleep(tDuration::from_millis(1000)).await;
    }
    println!("{:#?}", response_times.lock().await);
    println!("Hello, world!");

    Ok(())
}
