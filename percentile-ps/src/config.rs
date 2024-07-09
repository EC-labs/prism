use clap::ArgMatches;
use eyre::{eyre, ErrReport};

pub enum Config {
    ResponseTimePercentile { percentile: f64, time_factor: u64 },
    ThroughputOps { time_factor: u64 },
}

impl TryFrom<ArgMatches> for Config {
    type Error = ErrReport;
    fn try_from(mut matches: ArgMatches) -> Result<Self, Self::Error> {
        match matches.get_flag("output-ops") {
            false => {
                let percentile = matches
                    .remove_one("percentile")
                    .ok_or(eyre!("Missing percentile"))?;
                let time_factor = matches
                    .remove_one("time-factor")
                    .ok_or(eyre!("Missing time-factor"))?;
                Ok(Config::ResponseTimePercentile {
                    percentile,
                    time_factor,
                })
            }
            true => {
                let time_factor = matches
                    .remove_one("time-factor")
                    .ok_or(eyre!("Missing time-factor"))?;
                Ok(Config::ThroughputOps { time_factor })
            }
        }
    }
}
