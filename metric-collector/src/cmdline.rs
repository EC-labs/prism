use clap::{arg, command, value_parser, Arg, ArgAction, ArgGroup, Command};
use indoc::indoc;

pub fn register_args() -> Command {
    command!() // requires `cargo` feature
        .next_line_help(true)
        .arg(
            Arg::new("machine-id")
                .long("machine-id")
                .action(ArgAction::Set)
                .value_parser(value_parser!(u32))
                .help("ID of the machine"),
        )
        .arg(
            Arg::new("pids")
                .required(false)
                .long("pids")
                .action(ArgAction::Set)
                .value_parser(value_parser!(usize))
                .value_delimiter(',')
                .help("PID of the main process to monitor"),
        )
        .arg(
            Arg::new("process-name")
                .required(false)
                .long("process-name")
                .action(ArgAction::Set)
                .help("Name of the target process"),
        )
        // Sink options
        .arg(
            arg!(--"backend" <BACKEND> "data store backend type")
                .value_parser(["clickhouse", "duckdb"])
                .requires_if("clickhouse", "clickhouse-config")
                .default_value("duckdb")
        )
        // Duckdb sink configuration
        .arg(
            arg!(--"duckdb-directory" <DIRECTORY> "Directory where the duckdb database should be stored")
                .default_value("./data")
                .alias("data-directory")
        )
        .arg(
            arg!(--"duckdb-file"      <FILENAME> "Duckdb file name")
        )
        .group(ArgGroup::new("duckdb-config")
            .args(["duckdb-directory", "duckdb-file"])
            .multiple(true)
        )
        // Clickhouse sink configuration
        .arg(arg!(--"clickhouse-url"        <URL>        "clickhouse url. E.g. `http://localhost:8123`").env("CLICKHOUSE_URL"))
        .arg(arg!(--"clickhouse-user"       <USER>       "clickhouse user").env("CLIKCHOUSE_USER"))
        .arg(arg!(--"clickhouse-db"         <DB>         "clickhouse database").env("CLIKHOUSE_DB"))
        .arg(arg!(--"clickhouse-password"   <PASSWORD>   "clickhouse password").env("CLICKHOUSE_PASSWORD"))
        .group(ArgGroup::new("clickhouse-config")
            .args(["clickhouse-url", "clickhouse-db", "clickhouse-user", "clickhouse-password"])
            .multiple(true)
            .requires_all(["clickhouse-url", "clickhouse-db", "clickhouse-user", "clickhouse-password"])
            .conflicts_with("duckdb-config")
        )
        .arg(
            Arg::new("monitor-self")
                .long("monitor-self")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("containerd-container-filters")
                .long("containerd-container-filters")
                .action(ArgAction::Append)
                .help("Filters used to bootstrap prism on containerd containers. Multiple filters can be provided.")
                .long_help(indoc! {r#"
                    To bootstrap prism on all pids that are within containers that are part of a pod whose name includes `<substring>` *AND* the that are within the `<namespace>` namespace:
                        --containerd-container-filters "labels.io.kubernetes.pod.namespace==<namespace>,labels.io.kubernetes.pod.name~=<substring>"

                    Providing multiple filters will boostrap prism on all pids that are within containers that match either filter. I.e., the following options will bootstrap prism on pids obtained by `<filter1>`, and those obtained via `<filter2>`:
                        --containerd-container-filters <filter1> and --containerd-container-filters <filter2>
                "#})
        )
        .arg(
            Arg::new("docker-container-names")
                .long("docker-container-names")
                .action(ArgAction::Append)
                .help("Docker container names used to bootstrap prism. Multiple container names can be provided.")
                .long_help(indoc! {r#"
                    To bootstrap prism on all pids that are within containers that are part of a docker container whose name is `<container-name>`:
                        --docker-container-names <container-name>

                    Providing multiple values will boostrap prism on all pids that are within the listed containers. I.e., the following options will bootstrap prism on pids within containers `<container-1>` and `<container-2>`:
                        --docker-container-names <container-1> --docker-container-names <container-2>

                "#})
        )
}
