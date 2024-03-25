use chrono::prelude::*;
use eyre::Result;
use reqwest::Client;
use std::sync::Arc;
use std::{fs::File, iter, time::Duration};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    time::{self, Duration as tDuration},
};

#[derive(Clone)]
enum HttpMethod {
    Get,
    Post,
    Put,
}

async fn writer(mut rx: Receiver<(String, Duration)>) -> Result<()> {
    let file = File::create("../data/response_time.csv")?;
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record(&["end_ts", "duration_ms"])?;
    while let Some((ts, duration)) = rx.recv().await {
        wtr.write_record(&[ts, duration.as_millis().to_string()])?;
    }
    wtr.flush()?;
    Ok(())
}

async fn execute_pattern(
    url: Arc<str>,
    method: HttpMethod,
    pattern: Vec<u64>,
    tx: &Sender<(String, Duration)>,
) {
    for nreq in pattern {
        println!("Sending {:?}", nreq);
        let client = Client::new();

        for req_sequence in 0..nreq {
            let tx = tx.clone();
            let url = url.clone();
            let client = client.clone();
            let method = method.clone();

            tokio::spawn(async move {
                let sleep_time = (1000 / nreq) * req_sequence;
                time::sleep(tDuration::from_millis(sleep_time)).await;
                let start = Utc::now();
                let request = match method {
                    HttpMethod::Get => client.get(&*url),
                    HttpMethod::Post => client.post(&*url),
                    HttpMethod::Put => client.put(&*url),
                };
                request.send().await;
                let current_time = Utc::now();
                let response_time = current_time.signed_duration_since(start);
                tx.send((current_time.to_rfc3339(), response_time.to_std().unwrap()))
                    .await
                    .unwrap();
            });
        }
    }
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let (tx, rx) = mpsc::channel(1000);
    let writer = tokio::spawn(writer(rx));

    println!("GET: cpu");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/cpu");
    execute_pattern(url, HttpMethod::Get, pattern, &tx).await;
    time::sleep(tDuration::from_millis(30000)).await;

    println!("GET: disk");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/disk");
    execute_pattern(url, HttpMethod::Get, pattern, &tx).await;
    time::sleep(tDuration::from_millis(30000)).await;

    println!("POST: disk");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/disk");
    execute_pattern(url, HttpMethod::Post, pattern, &tx).await;
    time::sleep(tDuration::from_millis(30000)).await;

    println!("PUT: disk");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/disk");
    execute_pattern(url, HttpMethod::Put, pattern, &tx).await;

    drop(tx);

    writer.await.unwrap()
}
