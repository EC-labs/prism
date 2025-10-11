use chrono::prelude::*;
use clap::ArgMatches;

pub struct Config {
    pub machine_id: u32,
    pub pids: Option<Vec<usize>>,
    pub period: u64,
    pub prism_store: Box<str>,
    pub process_name: Option<String>,
}

impl TryFrom<ArgMatches> for Config {
    type Error = Box<dyn std::error::Error>;
    fn try_from(mut matches: ArgMatches) -> Result<Self, Self::Error> {
        let pids: Option<Vec<usize>> = matches
            .remove_many::<usize>("pids")
            .map(|pids| pids.collect());

        let process_name = matches.remove_one::<String>("process-name");

        let machine_id = matches.remove_one::<u32>("machine-id").expect("Missing machine-id");

        let period: u64 = matches
            .remove_one::<u64>("period")
            .expect("Missing period")
            .try_into()
            .expect("Convert usize to u64");

        let utc: DateTime<Utc> = Utc::now();
        let mut prism_store = matches
            .remove_one::<String>("data-directory")
            .expect("Required field");
        prism_store += &format!("/prism-{}.db3", utc.to_rfc3339());

        Ok(Self {
            machine_id,
            pids,
            period,
            prism_store: Box::from(prism_store),
            process_name,
        })
    }
}
