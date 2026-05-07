use chrono::prelude::*;
use clap::ArgMatches;
use log::error;
use rand::RngExt;

use crate::sink::{ClickhouseConfig, SinkConfig};

pub struct Config {
    pub machine_id: u32,
    pub pids: Vec<usize>,
    pub sink_config: SinkConfig,
    pub process_name: Option<String>,
    pub containerd_container_filters: Option<Vec<String>>,
}

impl TryFrom<ArgMatches> for Config {
    type Error = Box<dyn std::error::Error>;
    fn try_from(mut matches: ArgMatches) -> Result<Self, Self::Error> {
        let pids: Option<Vec<usize>> = matches
            .remove_many::<usize>("pids")
            .map(|pids| pids.collect());
        let mut pids = pids.unwrap_or_default();

        let process_name = matches.remove_one::<String>("process-name");

        let mut rng = rand::rng();
        let random_machine_id: u32 = rng.random();

        let machine_id = matches
            .remove_one::<u32>("machine-id")
            .unwrap_or(random_machine_id);

        let sink_config = match matches
            .remove_one::<String>("backend")
            .expect("Missing backend")
            .as_str()
        {
            "duckdb" => {
                let duckdb_directory = matches
                    .remove_one::<String>("duckdb-directory")
                    .expect("Missing duckdb-directory");
                let duckdb_filename =
                    if let Some(filename) = matches.remove_one::<String>("duckdb-file") {
                        filename
                    } else {
                        let utc: DateTime<Utc> = Utc::now();
                        utc.to_rfc3339() + ".db3"
                    };

                let duckdb_store = format!("{duckdb_directory}/{duckdb_filename}",);
                SinkConfig::DuckDB(duckdb_store)
            }
            "clickhouse" => {
                let clickhouse_config = ClickhouseConfig {
                    url: matches
                        .remove_one::<String>("clickhouse-url")
                        .expect("Missing clickhouse url"),
                    db: matches
                        .remove_one::<String>("clickhouse-db")
                        .expect("Missing clickhouse db"),
                    user: matches
                        .remove_one::<String>("clickhouse-user")
                        .expect("Missing clickhouse user"),
                    password: matches
                        .remove_one::<String>("clickhouse-password")
                        .expect("Missing clickhouse password"),
                };
                SinkConfig::Clickhouse(clickhouse_config)
            }
            _ => {
                error!("Unsupported backend");
                panic!()
            }
        };

        if matches.get_flag("monitor-self") {
            let mc_pid = std::process::id() as usize;
            pids.push(mc_pid);
        };

        let containerd_container_filters = matches
            .remove_many::<String>("containerd-container-filters")
            .map(|v| v.collect::<Vec<_>>());

        Ok(Self {
            machine_id,
            pids,
            sink_config,
            process_name,
            containerd_container_filters,
        })
    }
}
