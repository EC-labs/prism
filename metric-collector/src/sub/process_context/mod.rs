use anyhow::{Context, Result};
use bollard::{query_parameters::InspectContainerOptions, Docker, API_DEFAULT_VERSION};
use containerd_client::{
    connect,
    services::v1::{
        containers_client::ContainersClient, tasks_client::TasksClient, GetContainerRequest,
        GetRequest, ListContainersRequest,
    },
    tonic::transport::Channel,
    with_namespace,
};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use regex::Regex;
use std::{
    ffi::CStr,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::{mpsc::SendError, Arc, Mutex},
    thread,
    time::Duration,
};
use tokio::sync::broadcast;
use tokio::{
    runtime::Runtime,
    sync::mpsc::{self, Receiver},
    time::timeout,
};
use tonic::Request;

use crate::event::{DockerEvent, Event, K8sEvent, ProcessContextEvent};

lazy_static! {
    static ref RE_DOCKER: Regex = Regex::new(r"\/docker-(\w+)").unwrap();
}
lazy_static! {
    static ref RE_CONTAINERD: Regex = Regex::new(r"containerd-(\w+)").unwrap();
}

#[derive(Debug)]
enum Container {
    Docker {
        cgroup: String,
        id: String,
        name: Option<String>,
        image_name: Option<String>,
        image_hash: Option<String>,
    },
    K8s {
        cgroup: String,
        id: String,
        namespace: Option<String>,
        pod_name: Option<String>,
        container_name: Option<String>,
        image_name: String,
    },
    Unknown,
}

impl Container {
    fn append_row(
        self,
        sink_tx: &std::sync::mpsc::Sender<Event>,
        machine_id: u32,
    ) -> Result<(), SendError<Event>> {
        match self {
            Self::Docker {
                cgroup,
                id,
                name,
                image_name,
                image_hash,
            } => {
                sink_tx.send(Event::Docker(DockerEvent {
                    machine_id,
                    cgroup,
                    id,
                    name,
                    image_name,
                    image_hash,
                }))?;
            }
            Self::K8s {
                cgroup,
                id,
                namespace,
                pod_name,
                container_name,
                image_name,
            } => {
                sink_tx.send(Event::K8s(K8sEvent {
                    machine_id,
                    cgroup,
                    id,
                    namespace,
                    pod_name,
                    container_name,
                    image_name,
                }))?;
            }
            Self::Unknown => {}
        }
        Ok(())
    }
}

struct ContainerRuntimes {
    docker_client: Option<Docker>,
    containerd_client: Option<Channel>,
}

impl ContainerRuntimes {
    fn init_async_runtime(
        mut self,
        mut cgroup_rx: Receiver<Cgroup>,
        sink_tx: std::sync::mpsc::Sender<Event>,
        machine_id: u32,
    ) -> Runtime {
        let async_rt = Runtime::new().expect("Failed to start async runtime");
        async_rt.spawn(async move {
            // search for containers with provided filter
            loop {
                let Some(cgroup) = cgroup_rx.recv().await else {
                    break;
                };
                let container = match self.get_container_metadata(cgroup).await {
                    Ok(container) => container,
                    Err(e) => {
                        warn!("Failed to get container metadata: {e}");
                        continue;
                    }
                };

                if let Err(e) = container.append_row(&sink_tx, machine_id) {
                    error!("failed to send process object");
                    panic!("{e}");
                }
            }
            Ok(()) as Result<()>
        });
        async_rt
    }

    fn new() -> Self {
        let docker_client = Docker::connect_with_socket_defaults().ok();
        let containerd_client = None;
        Self {
            docker_client,
            containerd_client,
        }
    }

    async fn containerd_connection() -> Option<Channel> {
        let socks = [
            "/proc/1/root/run/containerd/containerd.sock",
            "/proc/1/root/var/snap/microk8s/common/run/containerd.sock",
            "/proc/1/root/run/k0s/containerd.sock",
            "/proc/1/root/run/k3s/containerd/containerd.sock",
        ];
        for sock in socks {
            if let Ok(channel) = connect(sock).await {
                return Some(channel);
            }
        }
        None
    }

    async fn connect_containerd(&mut self) {
        self.containerd_client = Self::containerd_connection().await;
    }

    fn connect_docker(&mut self) {
        self.docker_client = Docker::connect_with_socket(
            "unix:///proc/1/root/var/run/docker.sock",
            120,
            API_DEFAULT_VERSION,
        )
        .inspect_err(|e| warn!("Could not connect to docker socket: {e}"))
        .ok();
    }

    async fn get_container_metadata(&mut self, cgroup: Cgroup) -> Result<Container> {
        let cgroup_str = cgroup
            .0
            .to_str()
            .context("cgroup failed to convert to str")?;

        if let Some(captures) = RE_DOCKER.captures(cgroup_str) {
            let container_id = captures
                .iter()
                .last()
                .context("missing captures")?
                .unwrap()
                .as_str();
            if self.docker_client.is_none() {
                self.connect_docker();
            }

            let Some(docker_client) = &self.docker_client else {
                return Ok(Container::Unknown);
            };
            let options = Some(InspectContainerOptions { size: false });
            let md = docker_client
                .inspect_container(container_id, options)
                .await?;

            let container = Container::Docker {
                cgroup: String::from(cgroup_str),
                id: String::from(container_id),
                name: md.name,
                image_hash: md.image,
                image_name: md.config.map(|v| v.image).unwrap_or(None),
            };

            debug!("{:?}", container);
            Ok(container)
        } else if let Some(captures) = RE_CONTAINERD.captures(cgroup_str) {
            let container_id = captures
                .iter()
                .last()
                .context("missing captures")?
                .unwrap()
                .as_str();
            if self.containerd_client.is_none() {
                self.connect_containerd().await;
            }

            let Some(containerd_client) = &mut self.containerd_client else {
                return Ok(Container::Unknown);
            };
            let mut containers_client = ContainersClient::new(containerd_client);
            let req = GetContainerRequest {
                id: container_id.into(),
            };
            let req = with_namespace!(req, "k8s.io");
            let resp = containers_client.get(req).await?;
            let Some(mut container) = resp.into_inner().container else {
                warn!("Unexpected `None` in response's `container` attribute");
                return Ok(Container::Unknown);
            };

            let container = Container::K8s {
                cgroup: String::from(cgroup_str),
                id: String::from(container_id),
                namespace: container.labels.remove("io.kubernetes.pod.namespace"),
                pod_name: container.labels.remove("io.kubernetes.pod.name"),
                container_name: container.labels.remove("io.kubernetes.container.name"),
                image_name: container.image,
            };

            debug!("{:?}", container);
            Ok(container)
        } else {
            warn!("unknown cgroup manager {:?}", cgroup);
            Ok(Container::Unknown)
        }
    }

    async fn containerd_processes_in_containers(filters: Vec<String>) -> Vec<usize> {
        let Some(containerd_client) = Self::containerd_connection().await else {
            return Vec::new();
        };
        let mut containers_client = ContainersClient::new(containerd_client.clone());

        let list_req = ListContainersRequest { filters: filters };
        let list_req = with_namespace!(list_req, "k8s.io");
        let Ok(res) = containers_client.list(list_req).await else {
            return Vec::new();
        };
        let res = res.into_inner();

        let mut tasks_client = TasksClient::new(containerd_client);
        let mut pids = Vec::new();
        for container in res.containers {
            let id = container.id.clone();
            let get_task_req = GetRequest {
                container_id: id.clone(),
                exec_id: String::new(),
            };
            let get_task_req = with_namespace!(get_task_req, "k8s.io");
            let Ok(res) = tasks_client.get(get_task_req).await else {
                continue;
            };

            let res = res.into_inner();
            let Some(process) = res.process else { continue };
            pids.push(process.pid as usize);
        }
        pids
    }
}

#[derive(Debug, Clone)]
struct Cgroup(PathBuf);

struct Pid(u32);

#[derive(Debug)]
pub struct ProcessContext {
    pid: u32,
    cgroup: Cgroup,
    argv: Vec<String>,
    exe: PathBuf,
}

impl ProcessContext {
    fn append_row(
        self,
        sink_tx: &std::sync::mpsc::Sender<Event>,
        machine_id: u32,
    ) -> Result<(), SendError<Event>> {
        sink_tx.send(Event::ProcessContext(ProcessContextEvent {
            machine_id: machine_id,
            pid: self.pid,
            cgroup: self.cgroup.0.to_str().map(|s| s.to_string()),
            argv: self.argv.join(" "),
            exe: self.exe.to_str().map(|s| s.to_string()),
        }))
    }
}

impl TryFrom<Pid> for ProcessContext {
    type Error = anyhow::Error;

    fn try_from(pid: Pid) -> Result<Self> {
        let pid_proc = format!("/proc/{}", pid.0);
        let pid_proc_path = Path::new(pid_proc.as_str());

        let pid_cgroup_path = pid_proc_path.join("cgroup");
        let pid_cgroup_file = File::open(pid_cgroup_path)?;
        let mut cgroup_first_line = String::new();
        BufReader::new(pid_cgroup_file).read_line(&mut cgroup_first_line)?;
        let cgroup_path = cgroup_first_line
            .split(":")
            .nth(2)
            .context("cgroup should have 3 parts")?;
        let cgroup = Cgroup(PathBuf::from(cgroup_path.trim()));

        let cmdline_path = pid_proc_path.join("cmdline");
        let mut cmdline_file = File::open(cmdline_path)?;
        let mut cmdline_content = Vec::new();
        cmdline_file.read_to_end(&mut cmdline_content)?;
        let cmdline_null_bytes =
            cmdline_content
                .iter()
                .enumerate()
                .fold(Vec::new(), |mut acc, (pos, x)| {
                    if pos == 0 {
                        acc.push(pos);
                    }

                    if *x == 0 {
                        acc.push(pos + 1);
                    }
                    acc
                });

        let mut argv = Vec::new();
        for pair in cmdline_null_bytes.windows(2) {
            match CStr::from_bytes_with_nul(&cmdline_content[pair[0]..pair[1]])?.to_str() {
                Ok(arg) => {
                    argv.push(String::from(arg));
                }
                Err(e) => {
                    warn!("error converting process cmdline to String: {}", e);
                    argv.push(String::from("InvalidUtf8"))
                }
            }
        }

        let exe_file = pid_proc_path.join("exe");
        let exe = fs::read_link(exe_file)?;

        Ok(Self {
            cgroup,
            argv,
            exe,
            pid: pid.0,
        })
    }
}

fn process_context_thread(
    terminate_flag: Arc<Mutex<bool>>,
    sink_tx: std::sync::mpsc::Sender<Event>,
    mut pid_rx: broadcast::Receiver<u32>,
    machine_id: u32,
    containerd_container_filters: Option<Vec<String>>,
    init_pids_tx: std::sync::mpsc::Sender<Vec<usize>>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel(1000);
    let container_runtimes = ContainerRuntimes::new();
    let async_rt = container_runtimes.init_async_runtime(rx, sink_tx.clone(), machine_id);

    let mut init_pids = Vec::new();
    if let Some(ref containerd_container_filters) = containerd_container_filters {
        let filters = containerd_container_filters.clone();
        init_pids.extend(async_rt.block_on(async move {
            ContainerRuntimes::containerd_processes_in_containers(filters).await
        }));
    }

    if let Err(e) = init_pids_tx.send(init_pids) {
        warn!("Failed to announce containerd pids with filter {containerd_container_filters:?}:\n{e:?}");
    }

    loop {
        let Ok(terminate) = terminate_flag.lock() else {
            break;
        };
        if *terminate {
            break;
        }
        drop(terminate);

        let res =
            async_rt.block_on(async { timeout(Duration::from_millis(100), pid_rx.recv()).await });
        let res = match res {
            Ok(res) => res,
            Err(_) => {
                // Elapsed
                continue;
            }
        };

        let pid = match res {
            Ok(pid) => Pid(pid),
            Err(e) => {
                info!("Terminating process context thread: {e}");
                return Err(e.into());
            }
        };

        let Ok(context) = ProcessContext::try_from(pid) else {
            continue;
        };
        let cgroup = context.cgroup.clone();
        debug!("process context {:?}", context);
        if let Err(e) = context.append_row(&sink_tx, machine_id) {
            error!("failed to send process object");
            panic!("{e}")
        };

        match tx.blocking_send(cgroup) {
            Ok(_) => {}
            Err(e) => {
                error!("failed to send cgroup event");
                panic!("{e}")
            }
        }
    }

    Ok(())
}

pub fn init_thread(
    terminate_flag: Arc<Mutex<bool>>,
    sink_tx: std::sync::mpsc::Sender<Event>,
    pid_rx: broadcast::Receiver<u32>,
    machine_id: u32,
    containerd_container_filters: Option<Vec<String>>,
) -> Result<Vec<usize>> {
    let (init_pids_tx, init_pids_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        process_context_thread(
            terminate_flag,
            sink_tx,
            pid_rx,
            machine_id,
            containerd_container_filters,
            init_pids_tx,
        )
    });
    let pids = match init_pids_rx.recv() {
        Ok(pids) => pids,
        Err(e) => {
            warn!("Failed to receive container init pids: {e:?}");
            return Err(e.into());
        }
    };
    Ok(pids)
}
