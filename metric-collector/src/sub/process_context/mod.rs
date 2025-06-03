use anyhow::{Context, Result};
use bus::BusReader;
use duckdb::Connection;
use log::{debug, warn, error};
use tokio::{runtime::Runtime, sync::mpsc::{self, Receiver, Sender}};
use std::{ffi::CStr, fs::{self, File}, io::{BufRead, BufReader, Read}, path::{Path, PathBuf}, sync::{mpsc::channel, Arc, Mutex}, thread, time::Duration};
use lazy_static::lazy_static;
use regex::Regex;
use bollard::{query_parameters::InspectContainerOptions, Docker};
use containerd_client::{
    connect, services::v1::{containers_client::ContainersClient, GetContainerRequest}, tonic::transport::Channel, with_namespace
};
use tonic::Request;

lazy_static! {
    static ref RE_DOCKER: Regex = Regex::new(r"\/docker-(\w+)").unwrap();
}
lazy_static! {
    static ref RE_CONTAINERD: Regex = Regex::new(r"containerd-(\w+)").unwrap();
}


#[derive(Debug)]
enum Container {
    Docker { cgroup: String, id: String, name: Option<String>, image_name: Option<String>, image_hash: Option<String> },
    K8s { cgroup: String, id: String, namespace: Option<String>, pod_name: Option<String>, container_name: Option<String>, image_name: String },
    Unknown
}

struct ContainerRuntimes {
    docker_client: Option<Docker>,
    containerd_client: Option<ContainersClient<Channel>>,
}

impl ContainerRuntimes {
    fn init_async_runtime(mut cgroup_rx: Receiver<Cgroup>) -> Result<Runtime> {
        let mut runtimes = ContainerRuntimes::new();
        let async_rt = Runtime::new()?;
        async_rt.spawn(async move {
            loop {
                let Some(cgroup) = cgroup_rx.recv().await else { break };
                println!("{:?}", runtimes.get_container_metadata(cgroup).await);
            }
        });
        Ok(async_rt)
    }

    fn new() -> Self {
        let docker_client = Docker::connect_with_socket_defaults().ok();
        let containerd_client = None;
        Self { docker_client, containerd_client }
    }

    async fn connect_containerd(&mut self) {
        let socks = [
            "/run/containerd/containerd.sock",
            "/var/snap/microk8s/common/run/containerd.sock",
            "/run/k0s/containerd.sock",
            "/run/k3s/containerd/containerd.sock",
        ];
        for sock in socks {
            match connect(sock).await {
                Ok(channel) => {
                    self.containerd_client = Some(ContainersClient::new(channel));
                    break;
                }, 
                _ => {}
            }
        }
    }

    fn connect_docker(&mut self) {
        self.docker_client = Docker::connect_with_socket_defaults().ok();
    }

    async fn get_container_metadata(&mut self, cgroup: Cgroup) -> Result<Container> {
        let cgroup_str = cgroup.0.to_str().context("cgroup failed to convert to str")?;
        if let Some(captures) = RE_DOCKER.captures(cgroup_str) {
            let container_id = captures.iter().last().context("missing captures")?.unwrap().as_str();
            if self.docker_client.is_none() {
                self.connect_docker();
            }

            let Some(docker_client) = &self.docker_client else { return Ok(Container::Unknown) };
            let options = Some(InspectContainerOptions{
                size: false,
            });
            let md = docker_client.inspect_container(container_id, options).await?;

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
            let container_id = captures.iter().last().context("missing captures")?.unwrap().as_str();
            if self.containerd_client.is_none() {
                self.connect_containerd().await;
            }

            let Some(containerd_client) = &mut self.containerd_client else { return Ok(Container::Unknown) };
            let req = GetContainerRequest { id: container_id.into() };
            let req = with_namespace!(req, "k8s.io");
            let Ok(resp) = containerd_client.get(req).await else { return Ok(Container::Unknown) };
            let Some(mut container) = resp.into_inner().container else { return Ok(Container::Unknown) };

            let container = Container::K8s { 
                cgroup: String::from(cgroup_str), 
                id: String::from(container_id), 
                namespace: container.labels.remove("io.kubernetes.pod.namespace"),
                pod_name: container.labels.remove("io.kubernetes.pod.name"), 
                container_name: container.labels.remove("io.kubernetes.container.name"),
                image_name: container.image.into(),
            };

            Ok(container)
        } else {
            warn!("unknown cgroup manager {:?}", cgroup);
            Ok(Container::Unknown)
        }
    }
}

#[derive(Debug)]
struct Cgroup(PathBuf);

struct Pid(u32);

#[derive(Debug)]
pub struct ProcessContext {
    cgroup: Cgroup, 
    argv: Vec<String>,
    exe: PathBuf,
}

impl TryFrom<Pid> for ProcessContext {
    type Error = anyhow::Error;

    fn try_from(value: Pid) -> Result<Self> {
        let pid_proc = format!("/proc/{}", value.0);
        let pid_proc_path = Path::new(pid_proc.as_str());

        let pid_cgroup_path = pid_proc_path.join("cgroup");
        let pid_cgroup_file = File::open(pid_cgroup_path)?;
        let mut cgroup_first_line = String::new();
        BufReader::new(pid_cgroup_file).read_line(&mut cgroup_first_line);
        let cgroup_path = cgroup_first_line.split(":").nth(2).context("cgroup should have 3 parts")?;
        let cgroup = Cgroup(PathBuf::from(cgroup_path.trim()));
        
        let cmdline_path = pid_proc_path.join("cmdline");
        let mut cmdline_file = File::open(cmdline_path)?;
        let mut cmdline_content = Vec::new();
        cmdline_file.read_to_end(&mut cmdline_content);
        let cmdline_null_bytes = cmdline_content.iter().enumerate().fold(Vec::new(), |mut acc, (pos, x)| {
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
                    argv.push(String::from("InvalidUtf8"))
                }
            }
        }

        let exe_file = pid_proc_path.join("exe");
        let exe = fs::read_link(exe_file)?;

        Ok(Self { cgroup, argv, exe })
    }
}

fn process_context_thread(terminate_flag: Arc<Mutex<bool>>, conn: Connection, mut pid_rx: BusReader<u32>) -> Result<()> {
    let (tx, rx) = mpsc::channel(1000);
    let async_rt = ContainerRuntimes::init_async_runtime(rx);

    loop {
        let Ok(terminate) = terminate_flag.lock() else { break };
        if *terminate == true {
            break;
        }
        drop(terminate);

        let pid = match pid_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(pid) => Pid(pid),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => { continue }
            Err(e) => { break }
        };
        let Ok(context) = ProcessContext::try_from(pid) else { continue };
        debug!("process context {:?}", context);
        match tx.blocking_send(context.cgroup) {
            Ok(_) => {}
            Err(e) => {
                error!("failed to send cgroup event");
            }
        }
    }

    Ok(())
}

pub fn init_thread(terminate_flag: Arc<Mutex<bool>>, conn: &Connection, pid_rx: BusReader<u32>) -> Result<()> {
    let conn = conn.try_clone()?;
    thread::spawn(move || process_context_thread(terminate_flag, conn, pid_rx));
    Ok(())
}
