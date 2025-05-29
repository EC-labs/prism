// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::Result;
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder}, MapCore, MapHandle, OpenObject, RingBuffer, RingBufferBuilder, TcHook, TcHookBuilder, TC_EGRESS
};
use log::{debug, info};
use std::{
    fmt::Debug, mem::MaybeUninit, net::{IpAddr, Ipv4Addr, Ipv6Addr}, os::fd::{AsFd, BorrowedFd}, sync::mpsc::{Receiver, self}, thread, sync::mpsc::RecvTimeoutError, time::Duration,
};
use bus::{Bus, BusReader};

mod discovery {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/discovery/bpf/discovery.skel.rs"
    ));
}
use discovery::{
    types::{tcp_discovery_event, tcphdr},
    DiscoverySkel, DiscoverySkelBuilder,
};

struct TcHook_ {
    pidfd: i64,
    hook: TcHook,
}

impl Drop for TcHook_ {
    fn drop(&mut self) {
        let ret = unsafe { libc::setns(self.pidfd as i32, libc::CLONE_NEWNET) };
        if ret == 0 {
            self.hook.detach();
            self.hook.destroy();
        }
    }
}

pub struct Discovery {
    hooks: Vec<TcHook_>,
    hook_rx: Receiver<TcHook_>,
}

impl Discovery {
    pub fn new<'conn>(
        conn: &'conn Connection,
        pid_map: MapHandle,
        pid_rb: MapHandle,
        net_socket_context: MapHandle,
        net_rb: MapHandle,
        mut pid_rx: BusReader<u32>,
    ) -> Result<Self>
    where
    {
        let (hook_tx, hook_rx) = mpsc::channel();
        let conn = conn.try_clone()?;
        Self::init_store(&conn);

        thread::spawn(move || -> Result<()> {
            let skel_builder = DiscoverySkelBuilder::default();
            let mut open_object = MaybeUninit::uninit();
            let mut open_skel = skel_builder.open(&mut open_object)?;
            open_skel.maps.rodata_data.machine_id = 0xccccdddd;
            open_skel.maps.pids.reuse_fd(pid_map.as_fd())?;
            open_skel.maps.pid_rb.reuse_fd(pid_rb.as_fd())?;
            open_skel.maps.socket_context.reuse_fd(net_socket_context.as_fd())?;
            open_skel.maps.rb.reuse_fd(net_rb.as_fd())?;

            let mut skel = open_skel.load()?;
            let mut builder = RingBufferBuilder::new();
            builder.add(
                &skel.maps.rb_skb_data,
                |data: &[u8]| 0,
            )?;
            let rb = builder.build()?;

            let mut builder = RingBufferBuilder::new();
            builder.add(
                &skel.maps.tcp_discovery_rb,
                tcp_discovery_callback(conn.appender("tcp_discovery").unwrap()),
            )?;
            let tcp_discovery_rb = builder.build()?;

            skel.attach()?;

            loop {
                while let pid = pid_rx.recv_timeout(Duration::from_millis(100)) {
                    let pid = match pid {
                        Ok(pid) => pid,
                        Err(RecvTimeoutError::Timeout) => { break }
                        Err(e) => { return Err(e.into()); }

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

                            match tc_builder.hook(TC_EGRESS).create() {
                                Ok(mut hook) => {
                                    let Ok(hook) = hook.attach() else { hook.destroy(); continue; };
                                    hook_tx.send(TcHook_ { pidfd, hook });
                                }
                                Err(_) => {}
                            }

                            debug!("register interface for pid {}: {} {}", pid, iface.name, iface.index);
                        }
                    }
                }
                tcp_discovery_rb.consume()?;
                rb.consume()?;
            }
            Ok(()) as Result<()>
        });

        Ok(Self { hook_rx, hooks: Vec::new() })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE tcp_discovery (
                    local_machine_id    UINTEGER,
                    local_inode_id      UBIGINT,
                    remote_machine_id   UINTEGER,
                    remote_inode_id     UBIGINT,
                );
            ",
        )?;
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        while let Ok(hook) = self.hook_rx.try_recv() {
            self.hooks.push(hook);
        }
        Ok(())
    }
}

fn tcp_discovery_callback<'conn>(
    mut tcp_discovery_appender: Appender<'conn>,
) -> impl FnMut(&[u8]) -> i32 + use<'conn> {
    move |data: &[u8]| {
        let event: &[u8; size_of::<tcp_discovery_event>()] = &data[..size_of::<tcp_discovery_event>()].try_into().unwrap();
        let event = unsafe {std::mem::transmute::<_, &tcp_discovery_event>(event)};
        debug!("{:x} {} {:x} {}", event.local_machine_id, event.local_inode_id, event.remote_machine_id, event.remote_inode_id);
        tcp_discovery_appender.append_row([&event.local_machine_id as &dyn ToSql, &event.local_inode_id, &event.remote_machine_id, &event.remote_inode_id]);
        0
    }
}
