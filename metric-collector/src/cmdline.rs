use clap::{command, value_parser, Arg, ArgAction, Command};

pub fn register_args() -> Command {
    command!() // requires `cargo` feature
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
                .value_parser(value_parser!(u64))
                .help("The main process to monitor"),
        )
        .arg(
            Arg::new("data_directory")
                .required(false)
                .default_value("./data")
                .long("data_directory")
                .action(ArgAction::Set)
                .help("The main process to monitor"),
        )
}
