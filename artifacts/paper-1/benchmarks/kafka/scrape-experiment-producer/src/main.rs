use csv::Writer;
use reqwest::Client;
use std::{
    fs::{self, File},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

#[derive(Debug)]
struct Metrics {
    total_events_counter: u64,
    current_experiments: usize,
    epoch_ms: u128,
}

impl Metrics {
    fn new(total_events: u64, running_experiments: usize) -> Self {
        let start = SystemTime::now();
        let epoch_ms = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
        Self {
            total_events_counter: total_events,
            current_experiments: running_experiments,
            epoch_ms,
        }
    }
    fn to_row(&self) -> Vec<String> {
        vec![
            self.epoch_ms.to_string(),
            self.total_events_counter.to_string(),
            self.current_experiments.to_string(),
        ]
    }
}

async fn timer_thread(interval_ms: u64, stop_flag: Arc<Mutex<bool>>, tx: Sender<bool>) {
    loop {
        if *stop_flag.lock().unwrap() == true {
            break;
        }
        thread::sleep(Duration::from_millis(interval_ms));
        tx.send(true).await.unwrap();
    }
}

fn parse_prometheus_client(content: &str) -> Metrics {
    let mut metrics = Metrics::new(0, 0);
    for line in content.lines() {
        if line.starts_with("#") {
            continue;
        }

        let mut elements = line.split(" ");
        let metric = elements.next().unwrap();
        if metric.starts_with("experiment_producer_event_count") {
            metrics.total_events_counter += elements.next().unwrap().parse::<u64>().unwrap();
        }

        if metric.starts_with("experiment_producer_num_experiments") {
            metrics.current_experiments = elements.next().unwrap().parse().unwrap();
        }
    }
    metrics
}

async fn scrape_loop(mut rx: Receiver<bool>, stop_flag: Arc<Mutex<bool>>) {
    let client = Client::new();
    let mut writer = Writer::from_writer(vec![]);
    writer
        .write_record(&["epoch_ms", "total_events", "current_consumers"])
        .unwrap();
    loop {
        if let None = rx.recv().await {
            break;
        }

        if *stop_flag.lock().unwrap() == true {
            break;
        }

        let res = client.get("http://localhost:3001/metrics").send().await;
        if let Ok(res) = res {
            let body = res.text().await.unwrap();
            let metrics = parse_prometheus_client(&body);
            println!("{}", metrics.to_row().join(","));
            writer.write_record(metrics.to_row()).unwrap();
        } else {
            let data = writer.into_inner().unwrap();
            fs::write("throughput.csv", &data).unwrap();
            break;
        }
    }
}

fn register_sighandler(stop_flag: Arc<Mutex<bool>>) {
    ctrlc::set_handler(move || {
        let mut terminate_flag = stop_flag.lock().unwrap();
        *terminate_flag = true;
    })
    .expect("Error setting Ctrl-C handler");
}

#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel(1000);
    let stop_flag = Arc::new(Mutex::new(false));
    register_sighandler(stop_flag.clone());

    tokio::spawn(timer_thread(1000, stop_flag.clone(), tx));
    scrape_loop(rx, stop_flag).await;
}
