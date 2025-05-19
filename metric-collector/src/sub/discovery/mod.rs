// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::Result;
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder}, OpenObject, RingBuffer, RingBufferBuilder, TcHook, TcHookBuilder, TC_EGRESS
};
use log::debug;
use std::{
    fmt::Debug,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{BorrowedFd, AsFd},
};

use discovery::{DiscoverySkel, DiscoverySkelBuilder};

mod discovery {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/discovery/bpf/discovery.skel.rs"
    ));
}

pub struct Discovery {
    hooks: Vec<TcHook>,
}

impl Discovery {
    pub fn new(
        open_object: &mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
    ) -> Result<Self>
    where
    {
        let skel_builder = DiscoverySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map)?;
        open_skel.maps.pid_rb.reuse_fd(pid_rb)?;

        let mut skel = open_skel.load()?;

        let mut hooks = Vec::new();
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
                    hooks.push(hook);
                }
                Err(_) => {}
            }

            println!("{}: {:?}", iface.name, iface.index);
        }

        Ok(Self { hooks })
    }

    pub fn sample(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        while let Some(mut hook) = self.hooks.pop() {
            hook.detach();
            hook.destroy();
        }
    }
}
