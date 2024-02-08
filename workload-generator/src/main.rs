use chrono::prelude::*;
use eyre::Result;
use reqwest::Client;
use std::{fs::File, time::Duration};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    time::{self, Duration as tDuration},
};

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let (tx, mut rx): (Sender<(String, Duration)>, Receiver<(String, Duration)>) =
        mpsc::channel(1000);
    for nreq in [1, 1, 2, 10, 10, 10] {
        for req_id in 0..nreq {
            let tx = tx.clone();
            let handle = tokio::spawn(async move {
                let sleep_time = (1000 / nreq) * req_id;
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
                tx.send((current_time.to_rfc3339(), response_time.to_std().unwrap()))
                    .await
                    .unwrap();

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
    drop(tx);

    let file = File::create("../data/response_time.csv")?;
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record(&["ts", "duration_ms"])?;
    while let Some((ts, duration)) = rx.recv().await {
        wtr.write_record(&[ts, duration.as_millis().to_string()])?;
    }
    wtr.flush()?;

    Ok(())
}
