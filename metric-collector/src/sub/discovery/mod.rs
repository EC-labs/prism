use anyhow::Result;
use bus::BusReader;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapHandle, RingBufferBuilder, TcHook, TcHookBuilder, TC_EGRESS,
};
use log::{debug, error, warn};
use std::{
    mem::MaybeUninit,
    os::fd::AsFd,
    sync::mpsc::RecvTimeoutError,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, SystemTime},
};

use crate::event::{Event, TcpDiscoveryEvent};

mod discovery_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/discovery/bpf/discovery.skel.rs"
    ));
}
use discovery_skel::{types::tcp_discovery_event, DiscoverySkelBuilder};

struct TcHook_ {
    pidfd: i64,
    hook: TcHook,
}

impl Drop for TcHook_ {
    fn drop(&mut self) {
        let ret = unsafe { libc::setns(self.pidfd as i32, libc::CLONE_NEWNET) };
        if ret == 0 {
            let _ = self.hook.detach();
            let _ = self.hook.destroy();
        }
    }
}

pub struct Discovery {
    hooks: Vec<TcHook_>,
    hook_rx: Receiver<TcHook_>,
}

impl Discovery {
    pub fn new(
        sink_tx: Sender<Event>,
        machine_id: u32,
        pid_map: MapHandle,
        pid_rb: MapHandle,
        net_socket_context: MapHandle,
        net_rb: MapHandle,
        mut pid_rx: BusReader<u32>,
    ) -> Self {
        let (hook_tx, hook_rx) = mpsc::channel();
        thread::spawn(move || -> Result<()> {
            let skel_builder = DiscoverySkelBuilder::default();
            let mut open_object = MaybeUninit::uninit();
            let mut open_skel = skel_builder
                .open(&mut open_object)
                .expect("Discovery skel open failed");
            open_skel.maps.rodata_data.machine_id = machine_id;
            open_skel
                .maps
                .pids
                .reuse_fd(pid_map.as_fd())
                .expect("Discovery pid_map reuse failed");
            open_skel
                .maps
                .pid_rb
                .reuse_fd(pid_rb.as_fd())
                .expect("Discovery pid_rb reuse failed");
            open_skel
                .maps
                .socket_context
                .reuse_fd(net_socket_context.as_fd())
                .expect("Discovery net_socket_context reuse failed");
            open_skel
                .maps
                .rb
                .reuse_fd(net_rb.as_fd())
                .expect("Discovery net_rb reuse failed");

            let mut skel = open_skel.load().expect("Discovery skel load failed");
            let mut builder = RingBufferBuilder::new();
            builder
                .add(&skel.maps.rb_skb_data, |_: &[u8]| 0)
                .expect("Discovery failed to register rb_skb_data callback");
            let rb = builder
                .build()
                .expect("Discovery failed to build rb_skb_data handler");

            let mut builder = RingBufferBuilder::new();
            builder
                .add(&skel.maps.tcp_discovery_rb, tcp_discovery_callback(sink_tx))
                .expect("Discovery failed to register tcp_discovery_rb callback");
            let tcp_discovery_rb = builder
                .build()
                .expect("Discovery failed to build tcp_discovery_rb handler");

            if let Err(e) = skel.attach() {
                warn!("Failed to attach Discovery programs:\n{e}");
                return Err(e.into());
            }

            loop {
                loop {
                    let pid = pid_rx.recv_timeout(Duration::from_millis(100));
                    let pid = match pid {
                        Ok(pid) => pid,
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(e) => {
                            return Err(e.into());
                        }
                    };
                    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                    if pidfd < 0 {
                        continue;
                    }

                    let ret = unsafe { libc::setns(pidfd as i32, libc::CLONE_NEWNET) };
                    if ret == 0 {
                        for iface in pnet::datalink::interfaces() {
                            let mut tc_builder = TcHookBuilder::new(skel.progs.tc_egress.as_fd());
                            tc_builder
                                .ifindex(iface.index as i32)
                                .replace(true)
                                .handle(1)
                                .priority(1);

                            if let Ok(mut hook) = tc_builder.hook(TC_EGRESS).create() {
                                let Ok(hook) = hook.attach() else {
                                    let _ = hook.destroy();
                                    continue;
                                };
                                if let Err(e) = hook_tx.send(TcHook_ { pidfd, hook }) {
                                    error!("failed to send hook");
                                    panic!("{e}");
                                };
                            }

                            debug!(
                                "register interface for pid {}: {} {}",
                                pid, iface.name, iface.index
                            );
                        }
                    }
                }
                if let Err(e) = tcp_discovery_rb.consume() {
                    warn!("Failed to consume tcp_discovery_rb: `{e}`");
                }
                if let Err(e) = rb.consume() {
                    warn!("Failed to consume rb_skb_data: `{e}`");
                }
            }
        });

        Self {
            hook_rx,
            hooks: Vec::new(),
        }
    }

    pub fn sample(&mut self) -> Result<()> {
        while let Ok(hook) = self.hook_rx.try_recv() {
            self.hooks.push(hook);
        }
        Ok(())
    }
}

fn tcp_discovery_callback(sink_tx: Sender<Event>) -> impl FnMut(&[u8]) -> i32 {
    move |data: &[u8]| {
        let event: &[u8; size_of::<tcp_discovery_event>()] =
            &data[..size_of::<tcp_discovery_event>()].try_into().unwrap();
        let event = unsafe {
            std::mem::transmute::<&[u8; size_of::<tcp_discovery_event>()], &tcp_discovery_event>(
                event,
            )
        };
        debug!(
            "{:x} {} {:x} {}",
            event.local_machine_id,
            event.local_inode_id,
            event.remote_machine_id,
            event.remote_inode_id
        );
        let epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let send_result = sink_tx.send(Event::TcpDiscovery(TcpDiscoveryEvent {
            local_machine_id: event.local_machine_id,
            local_inode_id: (event.local_inode_id as u64),
            remote_machine_id: event.remote_machine_id,
            remote_inode_id: (event.remote_inode_id as u64),
            inserted_at: epoch,
        }));

        match send_result {
            Ok(_) => 0,
            Err(_) => 1, // This terminates the ringbuffer consumption
        }
    }
}
