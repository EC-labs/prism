use chrono::prelude::*;
use clap::ArgMatches;
use eyre::eyre;
use std::rc::Rc;

pub struct Config {
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
        match (&pids, &process_name) {
            (None, None) => return Err(eyre!("Pass --process-name or --pid arg required").into()),
            (Some(_), Some(_)) => {
                return Err(
                    eyre!("Arguments --process-name and --pid are mutually exclusive").into(),
                )
            }
            _ => {}
        }

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
            pids,
            period,
            prism_store: Box::from(prism_store),
            process_name,
        })
    }
}
