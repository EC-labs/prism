use chrono::prelude::*;
use eyre::{Report, Result};
use reqwest::Client;
use std::{
    fs::{self, DirEntry, File, OpenOptions},
    io::Error,
    io::ErrorKind,
    sync::{
        mpsc::{Receiver as stdReceiver, Sender as stdSender},
        Arc,
    },
    time::Duration,
};
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
    let mut dirs: Vec<DirEntry> = fs::read_dir("./data")
        .unwrap()
        .into_iter()
        .map(|path| path.unwrap())
        .collect();

    dirs.sort_by(|a, b| {
        let a = a.path();
        let a = a.to_str();
        let b = b.path();
        let b = b.to_str();
        a.partial_cmp(&b).unwrap()
    });

    if dirs.len() == 0 {
        println!("No directory found");
        return Err(Error::from(ErrorKind::NotFound).into());
    }
    let data_directory = &dirs[dirs.len() - 1];
    let data_directory = format!(
        "{}/application-metrics",
        data_directory.path().to_str().unwrap()
    );
    fs::create_dir(&data_directory).expect("Failed to create application-metrics directory");

    let filename = format!("{}/response_time.csv", data_directory);
    let file = match OpenOptions::new().write(true).open(&filename) {
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                File::create(&filename)
            } else {
                Err(e)
            }
        }
        Ok(_) => Err(Error::from(ErrorKind::AlreadyExists)),
    }?;

    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record(&["end_ts", "duration_ms"])?;
    while let Some((ts, duration)) = rx.recv().await {
        wtr.write_record(&[ts, duration.as_millis().to_string()])?;
        wtr.flush()?;
    }
    Ok(())
}

async fn execute_pattern(
    url: Arc<str>,
    method: HttpMethod,
    pattern: Vec<u64>,
    tx: &Sender<(String, Duration)>,
) -> Result<()> {
    let (error_tx, error_rx): (stdSender<Report>, stdReceiver<Report>) = std::sync::mpsc::channel();

    for nreq in pattern {
        if let Ok(e) = error_rx.try_recv() {
            return Err(e.into());
        }

        println!("Sending {:?}", nreq);
        let client = Client::new();

        for req_sequence in 0..nreq {
            let tx = tx.clone();
            let url = url.clone();
            let client = client.clone();
            let method = method.clone();
            let error_tx = error_tx.clone();

            tokio::spawn(async move {
                let sleep_time = (1000 / nreq) * req_sequence;
                time::sleep(tDuration::from_millis(sleep_time)).await;
                let start = Utc::now();
                let request = match method {
                    HttpMethod::Get => client.get(&*url),
                    HttpMethod::Post => client.post(&*url),
                    HttpMethod::Put => client.put(&*url),
                };
                request.send().await.map_err(|e| {
                    let e = Arc::new(e);
                    error_tx.send(e.clone().into());
                    e
                })?;
                let current_time = Utc::now();
                let response_time = current_time.signed_duration_since(start);
                tx.send((current_time.to_rfc3339(), response_time.to_std().unwrap()))
                    .await
                    .map_err(|e| -> Report {
                        error_tx.send(e.clone().into());
                        e.into()
                    })?;
                Ok(()) as Result<()>
            });
        }
        time::sleep(Duration::from_millis(1000)).await;
    }
    Ok(())
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
    execute_pattern(url, HttpMethod::Get, pattern, &tx).await?;
    time::sleep(tDuration::from_millis(30000)).await;

    println!("GET: disk");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/disk");
    execute_pattern(url, HttpMethod::Get, pattern, &tx).await?;
    time::sleep(tDuration::from_millis(30000)).await;

    println!("POST: disk");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/disk");
    execute_pattern(url, HttpMethod::Post, pattern, &tx).await?;
    time::sleep(tDuration::from_millis(30000)).await;

    println!("PUT: disk");
    let pattern: Vec<u64> = vec![vec![2; 10], vec![10; 5], vec![1; 10]]
        .into_iter()
        .flatten()
        .collect();
    let url = Arc::from("http://localhost:7878/disk");
    execute_pattern(url, HttpMethod::Put, pattern, &tx).await?;

    drop(tx);
    writer.await.unwrap()
}
