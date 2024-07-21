use clap::{command, value_parser, Arg, ArgAction, Command};

pub fn register_args() -> Command {
    command!() // requires `cargo` feature
        .next_line_help(true)
        .arg(
            Arg::new("pids")
                .required(false)
                .long("pids")
                .action(ArgAction::Set)
                .value_parser(value_parser!(u64))
                .value_delimiter(',')
                .help("PID of the main process to monitor"),
        )
        .arg(
            Arg::new("period")
                .required(false)
                .default_value("1000")
                .long("period")
                .action(ArgAction::Set)
                .value_parser(value_parser!(u64))
                .help("Sleep time between two consecutive samples"),
        )
        .arg(
            Arg::new("data-directory")
                .required(false)
                .default_value("./data")
                .long("data-directory")
                .action(ArgAction::Set)
                .help("Root directory where data should be stored"),
        )
        .arg(
            Arg::new("process-name")
                .required(false)
                .long("process-name")
                .action(ArgAction::Set)
                .help("Name of the target process"),
        )
}
