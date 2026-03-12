use crate::event::Event;
use anyhow::Result;
use log::info;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseProducer, BaseRecord};
use std::thread::JoinHandle;
use std::{
    sync::{mpsc::Receiver, Arc, Mutex},
    time::Duration,
};

pub struct KafkaSink {
    producer: BaseProducer,
}

impl KafkaSink {
    pub fn new(
        terminate_flag: Arc<Mutex<bool>>,
        address: String,
        sink_rx: Receiver<Event>,
    ) -> Result<JoinHandle<Result<()>>> {
        let producer: BaseProducer = ClientConfig::new()
            .set("bootstrap.servers", &address)
            .set("message.timeout.ms", "5000")
            .create()?;
        info!("Kafka sink initialized, routing events to {}", address);

        Ok(std::thread::spawn(move || {
            let mut sink = KafkaSink { producer };
            loop {
                let Ok(msg) = sink_rx.recv_timeout(Duration::from_secs(2)) else {
                    if *terminate_flag.lock().unwrap() {
                        break;
                    }
                    continue;
                };
                log::info!("kafka producing: {}", msg.variant_name());
                if let Err(e) = sink.produce(msg) {
                    log::error!("produce failed: {e}");
                    return Err(e);
                }
            }
            Ok(())
        }))
    }

    fn produce(&mut self, event: Event) -> Result<()> {
        match event {
            Event::LinuxConsts(e, mid) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("linux_consts")
                            .key(&mid.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::IoWait(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("iowait")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::AioGetevents(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("aio_getevents")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::AioSubmit(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("aio_submit")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::AioFile(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("aio_file")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::TcpDiscovery(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("tcp_discovery")
                            .key(&e.local_machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::Vfs(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("vfs")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::FutexWait(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("futex_wait")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::FutexWake(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("futex_wake")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::MuxioWait(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("muxio_wait")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::MuxioFile(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("muxio_file")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::SocketContext(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("socket_context")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::SocketInet(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("socket_inet")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::SocketMap(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("socket_map")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::Taskstats(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("taskstats")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::Docker(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("docker")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::K8s(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("k8s")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
            Event::ProcessContext(e) => {
                let json = serde_json::to_string(&e)?;
                self.producer
                    .send(
                        BaseRecord::to("process_context")
                            .key(&e.machine_id.to_ne_bytes())
                            .payload(json.as_bytes()),
                    )
                    .map_err(|(e, _)| anyhow::anyhow!(e))?;
            }
        }
        self.producer.poll(Duration::from_millis(0));
        Ok(())
    }
}
