pub mod clickhouse;
pub mod duckdb;
pub mod kafka;

use crate::{
    event::Event,
    sink::{clickhouse::ClickhouseSink, duckdb::DuckdbSink, kafka::KafkaSink},
};
use anyhow::Result;
use log::{error, info};
use std::{
    sync::{mpsc::Receiver, Arc, Mutex},
    thread::JoinHandle,
};

pub struct ClickhouseConfig {
    pub url: String,
    pub db: String,
    pub user: String,
    pub password: String,
}

pub enum SinkConfig {
    DuckDB(String),
    Kafka(String),
    Clickhouse(ClickhouseConfig),
}

pub struct Manager {
    handle: Option<JoinHandle<Result<()>>>,
}

impl Manager {
    pub fn new(
        terminate_flag: Arc<Mutex<bool>>,
        sink_config: &SinkConfig,
        sink_rx: Receiver<Event>,
    ) -> Result<Self> {
        let handle = match sink_config {
            SinkConfig::DuckDB(path_string) => {
                DuckdbSink::new(terminate_flag, path_string.as_str(), sink_rx)?
            }
            SinkConfig::Kafka(address) => KafkaSink::new(terminate_flag, address, sink_rx)?,
            SinkConfig::Clickhouse(config) => ClickhouseSink::new(terminate_flag, config, sink_rx)?,
        };

        Ok(Self {
            handle: Some(handle),
        })
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        info!("Waiting for sink thread to terminate");
        let handle = self.handle.take().expect("Missing handler");
        if let Err(e) = handle.join() {
            error!("Failed to join sink thread: {e:?}");
        }
    }
}
