use chrono::prelude::*;
use clap::ArgMatches;
use log::error;

use crate::sink::{ClickhouseConfig, SinkConfig};

pub struct Config {
    pub machine_id: u32,
    pub pids: Option<Vec<usize>>,
    pub sink_config: SinkConfig,
    pub process_name: Option<String>,
}

impl TryFrom<ArgMatches> for Config {
    type Error = Box<dyn std::error::Error>;
    fn try_from(mut matches: ArgMatches) -> Result<Self, Self::Error> {
        let pids: Option<Vec<usize>> = matches
            .remove_many::<usize>("pids")
            .map(|pids| pids.collect());

        let process_name = matches.remove_one::<String>("process-name");

        let machine_id = matches
            .remove_one::<u32>("machine-id")
            .expect("Missing machine-id");

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

        Ok(Self {
            machine_id,
            pids,
            sink_config,
            process_name,
        })
    }
}
