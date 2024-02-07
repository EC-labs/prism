use chrono::prelude::*;
use clap::{command, value_parser, Arg, ArgAction};
use polars::{df, prelude::*};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, thread, time::Duration};

#[derive(Debug)]
struct SchedStat {
    runtime: u64,
    rq_time: u64,
    run_periods: u64,
}

impl From<Vec<&str>> for SchedStat {
    fn from(v: Vec<&str>) -> Self {
        SchedStat {
            runtime: v[0].parse().unwrap(),
            rq_time: v[1].parse().unwrap(),
            run_periods: v[2].parse().unwrap(),
        }
    }
}

fn main() {
    let mut matches = command!() // requires `cargo` feature
        .next_line_help(true)
        .arg(
            Arg::new("pid")
                .required(true)
                .long("pid")
                .action(ArgAction::Set)
                .value_parser(value_parser!(usize))
                .help("The main process to monitor"),
        )
        .arg(
            Arg::new("period")
                .required(false)
                .default_value("1000")
                .long("period")
                .action(ArgAction::Set)
                .value_parser(value_parser!(usize))
                .help("The main process to monitor"),
        )
        .get_matches();

    let pid = matches.remove_one::<usize>("pid").expect("Required field");
    let period: u64 = matches
        .remove_one::<usize>("period")
        .expect("Missing period")
        .try_into()
        .expect("Convert usize to u64");

    let proc_root_dir = format!("/proc/{:?}", pid);

    let mut timeseries = DataFrame::new(vec![Series::new_empty("ts", &DataType::String)]).unwrap();

    loop {
        let tasks = fs::read_dir(format!("{proc_root_dir}/task")).unwrap();
        let ts: DateTime<Utc> = Utc::now();
        let mut row = DataFrame::new(vec![Series::new("ts", &[ts.to_string()])]).unwrap();
        for task in tasks {
            if let Err(_) = task {
                continue;
            }
            let dentry = task.unwrap();

            let dentry_path = dentry.path();
            let stem = dentry_path.file_stem().unwrap().to_str().unwrap();
            let dentry: String = dentry_path.to_str().unwrap().into();
            let filename = format!("{dentry}/schedstat");

            if let None = timeseries.get_column_index(&format!("{stem}.runtime")) {
                let df2 = DataFrame::new(vec![
                    Series::new_empty(&format!("ts"), &DataType::String),
                    Series::new_empty(&format!("{stem}.runtime"), &DataType::UInt64),
                ])
                .unwrap();
                timeseries = timeseries.left_join(&df2, ["ts"], ["ts"]).unwrap();
            }
            if let None = timeseries.get_column_index(&format!("{stem}.rq_time")) {
                let df2 = DataFrame::new(vec![
                    Series::new_empty(&format!("ts"), &DataType::String),
                    Series::new_empty(&format!("{stem}.rq_time"), &DataType::UInt64),
                ])
                .unwrap();
                timeseries = timeseries.left_join(&df2, ["ts"], ["ts"]).unwrap();
            }
            if let None = timeseries.get_column_index(&format!("{stem}.run_periods")) {
                let df2 = DataFrame::new(vec![
                    Series::new_empty(&format!("ts"), &DataType::String),
                    Series::new_empty(&format!("{stem}.run_periods"), &DataType::UInt64),
                ])
                .unwrap();
                timeseries = timeseries.left_join(&df2, ["ts"], ["ts"]).unwrap();
            }

            let contents = fs::read_to_string(&filename).unwrap().replace("\n", "");
            let schedstat = SchedStat::from(contents.split(" ").collect::<Vec<&str>>());

            row.hstack_mut(&[
                Series::new(&format!("{stem}.runtime"), &[schedstat.runtime]),
                Series::new(&format!("{stem}.rq_time"), &[schedstat.rq_time]),
                Series::new(&format!("{stem}.run_periods"), &[schedstat.run_periods]),
            ])
            .unwrap();
        }
        timeseries.vstack_mut(&row).unwrap();
        println!("{:?}", timeseries);
        thread::sleep(Duration::from_millis(period));
    }
}
