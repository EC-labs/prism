use crate::event::{
    AioFileEvent, AioGeteventsEvent, AioSubmitEvent, DockerEvent, Event, FutexWaitEvent,
    FutexWakeEvent, IoWaitEvent, K8sEvent, LinuxConstsEvent, MuxioFileEvent, MuxioWaitEvent,
    ProcessContextEvent, SocketContextEvent, SocketInetEvent, SocketMapEvent, TaskstatsEvent,
    TcpDiscoveryEvent, VfsEvent,
};

use anyhow::Result;
use clickhouse::Row;
use clickhouse::{error::Error, inserter::Inserter, Client};
use log::{debug, error, info};
use std::sync::{
    mpsc::{Receiver, RecvTimeoutError},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

pub struct ClickhouseSink;

impl ClickhouseSink {
    pub fn new(
        terminate_flag: Arc<Mutex<bool>>,
        url: &str,
        sink_rx: Receiver<Event>,
    ) -> Result<JoinHandle<Result<()>>> {
        let client = Client::default()
            .with_url(url)
            .with_user("user")
            .with_password("password")
            .with_database("default");
        Ok(std::thread::spawn(move || {
            let runtime = Runtime::new()?;
            runtime.block_on(async {
                let mut inserter = ClickhouseInserter::new(&client);
                let mut last_commit = Instant::now();
                loop {
                    match sink_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(msg) => {
                            inserter.produce(msg).await;
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            if *terminate_flag.lock().expect("Lock poisoned") {
                                info!("Terminating inserter");
                                inserter.end().await;
                                break;
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            info!("Terminating inserter");
                            inserter.end().await;
                            break;
                        }
                    }

                    let now = Instant::now();
                    if now - last_commit < Duration::from_secs(1) {
                        continue;
                    }

                    // It has been 1 second since we last committed.
                    // Check if there is new data to commit
                    match inserter.commit().await {
                        Err(Error::TimedOut) | Err(Error::Network(_)) => {
                            todo!()
                        }
                        Err(e) => {
                            error!("Clickhouse commit failed: {e}");
                        }
                        Ok(()) => {}
                    };
                    last_commit = now;
                }
                Ok(())
            })
        }))
    }
}

pub struct ClickhouseInserter {
    inserter_linux_consts: Inserter<LinuxConstsEvent>,
    inserter_iowait: Inserter<IoWaitEvent>,
    inserter_aio_getevents: Inserter<AioGeteventsEvent>,
    inserter_aio_submit: Inserter<AioSubmitEvent>,
    inserter_aio_file: Inserter<AioFileEvent>,
    inserter_tcp_discovery: Inserter<TcpDiscoveryEvent>,
    inserter_vfs: Inserter<VfsEvent>,
    inserter_futex_wait: Inserter<FutexWaitEvent>,
    inserter_futex_wake: Inserter<FutexWakeEvent>,
    inserter_muxio_wait: Inserter<MuxioWaitEvent>,
    inserter_muxio_file: Inserter<MuxioFileEvent>,
    inserter_socket_context: Inserter<SocketContextEvent>,
    inserter_socket_inet: Inserter<SocketInetEvent>,
    inserter_socket_map: Inserter<SocketMapEvent>,
    inserter_docker: Inserter<DockerEvent>,
    inserter_k8s: Inserter<K8sEvent>,
    inserter_process_context: Inserter<ProcessContextEvent>,
    inserter_taskstats: Inserter<TaskstatsEvent>,
}

impl ClickhouseInserter {
    pub fn new(client: &Client) -> Self {
        let inserter_linux_consts = Self::create_default_inserter(client, "linux_consts");
        let inserter_iowait = Self::create_default_inserter(client, "iowait");
        let inserter_aio_getevents = Self::create_default_inserter(client, "aio_getevents");
        let inserter_aio_submit = Self::create_default_inserter(client, "aio_submit");
        let inserter_aio_file = Self::create_default_inserter(client, "aio_file");
        let inserter_tcp_discovery = Self::create_default_inserter(client, "tcp_discovery");
        let inserter_vfs = Self::create_default_inserter::<VfsEvent>(client, "vfs");
        let inserter_futex_wait = Self::create_default_inserter(client, "futex_wait");
        let inserter_futex_wake = Self::create_default_inserter(client, "futex_wake");
        let inserter_muxio_wait = Self::create_default_inserter(client, "muxio_wait");
        let inserter_muxio_file = Self::create_default_inserter(client, "muxio_file");
        let inserter_socket_context = Self::create_default_inserter(client, "socket_context");
        let inserter_socket_inet = Self::create_default_inserter(client, "socket_inet");
        let inserter_socket_map = Self::create_default_inserter(client, "socket_map");
        let inserter_docker = Self::create_default_inserter(client, "docker");
        let inserter_k8s = Self::create_default_inserter(client, "k8s");
        let inserter_process_context = Self::create_default_inserter(client, "process_context");
        let inserter_taskstats = Self::create_default_inserter(client, "taskstats");
        Self {
            inserter_linux_consts,
            inserter_iowait,
            inserter_aio_getevents,
            inserter_aio_submit,
            inserter_aio_file,
            inserter_tcp_discovery,
            inserter_vfs,
            inserter_futex_wait,
            inserter_futex_wake,
            inserter_muxio_wait,
            inserter_muxio_file,
            inserter_socket_context,
            inserter_socket_inet,
            inserter_socket_map,
            inserter_docker,
            inserter_k8s,
            inserter_process_context,
            inserter_taskstats,
        }
    }

    fn create_default_inserter<R: Row>(client: &Client, table: &str) -> Inserter<R> {
        client
            .inserter(table)
            // https://docs.rs/clickhouse/0.13.2/src/clickhouse/inserter.rs.html#56
            .unwrap()
            .with_max_bytes(10_000)
            .with_max_rows(1000)
            .with_period(Some(Duration::from_secs(10)))
    }

    async fn produce(&mut self, event: Event) {
        match event {
            Event::LinuxConsts(e, _) => {
                self.inserter_linux_consts.write(&e).unwrap();
            }
            Event::IoWait(e) => {
                self.inserter_iowait.write(&e).unwrap();
            }
            Event::AioGetevents(e) => {
                self.inserter_aio_getevents.write(&e).unwrap();
            }
            Event::AioSubmit(e) => {
                self.inserter_aio_submit.write(&e).unwrap();
            }
            Event::AioFile(e) => {
                self.inserter_aio_file.write(&e).unwrap();
            }
            Event::TcpDiscovery(e) => {
                self.inserter_tcp_discovery.write(&e).unwrap();
            }
            Event::Vfs(e) => {
                self.inserter_vfs.write(&e).unwrap();
            }
            Event::FutexWait(e) => {
                self.inserter_futex_wait.write(&e).unwrap();
            }
            Event::FutexWake(e) => {
                self.inserter_futex_wake.write(&e).unwrap();
            }
            Event::MuxioWait(e) => {
                self.inserter_muxio_wait.write(&e).unwrap();
            }
            Event::MuxioFile(e) => {
                self.inserter_muxio_file.write(&e).unwrap();
            }
            Event::SocketContext(e) => {
                self.inserter_socket_context.write(&e).unwrap();
            }
            Event::SocketInet(e) => {
                self.inserter_socket_inet.write(&e).unwrap();
            }
            Event::SocketMap(e) => {
                self.inserter_socket_map.write(&e).unwrap();
            }
            Event::Docker(e) => {
                self.inserter_docker.write(&e).unwrap();
            }
            Event::K8s(e) => {
                self.inserter_k8s.write(&e).unwrap();
            }
            Event::ProcessContext(e) => {
                self.inserter_process_context.write(&e).unwrap();
            }
            Event::Taskstats(e) => {
                self.inserter_taskstats.write(&e).unwrap();
            }
        }
    }

    async fn commit(&mut self) -> Result<(), Error> {
        let mut nrows = 0;
        nrows += self.inserter_linux_consts.commit().await?.rows;
        nrows += self.inserter_iowait.commit().await?.rows;
        nrows += self.inserter_aio_getevents.commit().await?.rows;
        nrows += self.inserter_aio_submit.commit().await?.rows;
        nrows += self.inserter_aio_file.commit().await?.rows;
        nrows += self.inserter_tcp_discovery.commit().await?.rows;
        nrows += self.inserter_vfs.commit().await?.rows;
        nrows += self.inserter_futex_wait.commit().await?.rows;
        nrows += self.inserter_futex_wake.commit().await?.rows;
        nrows += self.inserter_muxio_wait.commit().await?.rows;
        nrows += self.inserter_muxio_file.commit().await?.rows;
        nrows += self.inserter_socket_context.commit().await?.rows;
        nrows += self.inserter_socket_inet.commit().await?.rows;
        nrows += self.inserter_socket_map.commit().await?.rows;
        nrows += self.inserter_docker.commit().await?.rows;
        nrows += self.inserter_k8s.commit().await?.rows;
        nrows += self.inserter_process_context.commit().await?.rows;
        nrows += self.inserter_taskstats.commit().await?.rows;
        debug!("inserted {} rows", nrows);
        Ok(())
    }

    async fn end(self) {
        info!("Run ClickhouseInserter End");
        let mut handles = Vec::new();
        handles.push(tokio::spawn(self.inserter_linux_consts.end()));
        handles.push(tokio::spawn(self.inserter_iowait.end()));
        handles.push(tokio::spawn(self.inserter_aio_getevents.end()));
        handles.push(tokio::spawn(self.inserter_aio_submit.end()));
        handles.push(tokio::spawn(self.inserter_aio_file.end()));
        handles.push(tokio::spawn(self.inserter_tcp_discovery.end()));
        handles.push(tokio::spawn(self.inserter_vfs.end()));
        handles.push(tokio::spawn(self.inserter_futex_wait.end()));
        handles.push(tokio::spawn(self.inserter_futex_wake.end()));
        handles.push(tokio::spawn(self.inserter_muxio_wait.end()));
        handles.push(tokio::spawn(self.inserter_muxio_file.end()));
        handles.push(tokio::spawn(self.inserter_socket_context.end()));
        handles.push(tokio::spawn(self.inserter_socket_inet.end()));
        handles.push(tokio::spawn(self.inserter_socket_map.end()));
        handles.push(tokio::spawn(self.inserter_docker.end()));
        handles.push(tokio::spawn(self.inserter_k8s.end()));
        handles.push(tokio::spawn(self.inserter_process_context.end()));
        handles.push(tokio::spawn(self.inserter_taskstats.end()));
        for handle in handles {
            handle.await.unwrap().expect("Inserter `end()` error");
        }
    }
}
