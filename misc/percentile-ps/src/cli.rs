use clap::{command, value_parser, Arg, ArgAction, Command};

pub fn register_args() -> Command {
    command!() // requires `cargo` feature
        .next_line_help(true)
        .arg(
            Arg::new("time-factor")
                .required(false)
                .long("time-factor")
                .action(ArgAction::Set)
                .value_parser(value_parser!(u64))
                .default_value("1000")
                .help(concat!(
                    "Time unit. The program expects the start, end, and duration to be represented in the time units.",
                    "If for example the time is measured in microseconds (us), then the time-factor should be 1_000_000",
                )),
        )
        .arg(
            Arg::new("output-ops")
                .required(false)
                .long("output-ops")
                .action(ArgAction::SetTrue)
                .help(concat!(
                    "Whether the program should output the number of operations per second (ops/s).",
                    "The default behaviour is to compute 95th percentile response time"
                )),
        )
        .arg(
            Arg::new("percentile")
                .required(false)
                .long("percentile")
                .action(ArgAction::Set)
                .value_parser(value_parser!(f64))
                .default_value("0.95")
                .help("The response time percentile to compute"),
        )
}
