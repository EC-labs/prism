use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject, RingBuffer, RingBufferBuilder,
};
use libc::{AF_INET, AF_INET6, AF_UNIX, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_STREAM};
use log::{debug, info, warn};
use net_skel::{types::socket_context_value, NetSkel, NetSkelBuilder};
use std::{
    fmt::Debug,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::BorrowedFd,
    sync::mpsc::Sender,
};

use crate::event::{Event, SocketContextEvent, SocketInetEvent, SocketMapEvent};

mod net_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/net/bpf/net.skel.rs"
    ));
}

#[derive(Debug, Default)]
struct SocketContext {
    netns_cookie: u64,
    inode_id: u64,
    sk_family: u16,
    sk_type: u16,
    sk_protocol: u16,
    src_addr: Option<IpAddr>,
    src_port: Option<u16>,
    dst_addr: Option<IpAddr>,
    dst_port: Option<u16>,
}

impl TryFrom<&socket_context_value> for SocketContext {
    type Error = ();
    fn try_from(value: &socket_context_value) -> Result<Self, Self::Error> {
        // let mut res = SocketContext::default();
        let mut res = Self {
            netns_cookie: value.netns_cookie,
            inode_id: value.inode_id,
            sk_family: value.family,
            sk_type: value.sk_type,
            sk_protocol: value.sk_protocol,
            ..Default::default()
        };
        match value.family as i32 {
            AF_INET => {
                let src_addr = unsafe { u32::from_be(value.__anon_5.ipv4.src_addr) };
                res.src_addr = Some(IpAddr::V4(Ipv4Addr::from(src_addr)));

                let dst_addr = unsafe { u32::from_be(value.__anon_5.ipv4.dst_addr) };
                res.dst_addr = Some(IpAddr::V4(Ipv4Addr::from(dst_addr)));

                match value.sk_type as i32 {
                    SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => {
                        res.src_port = Some(value.src_port);
                        res.dst_port = Some(u16::from_be(value.dst_port));
                    }
                    _ => {}
                }
            }
            AF_INET6 => {
                let src_addr = unsafe { value.__anon_5.ipv6.src_addr };
                let src_addr: u128 = unsafe { std::mem::transmute(src_addr) };
                let src_addr = u128::from_be(src_addr);
                res.src_addr = Some(IpAddr::V6(Ipv6Addr::from(src_addr)));

                let dst_addr = unsafe { value.__anon_5.ipv6.dst_addr };
                let dst_addr: u128 = unsafe { std::mem::transmute(dst_addr) };
                let dst_addr = u128::from_be(dst_addr);
                res.dst_addr = Some(IpAddr::V6(Ipv6Addr::from(dst_addr)));

                match value.sk_type as i32 {
                    SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => {
                        res.src_port = Some(value.src_port);
                        res.dst_port = Some(u16::from_be(value.dst_port));
                    }
                    _ => {}
                }
            }
            AF_UNIX => {}
            _ => return Err(()),
        }

        Ok(res)
    }
}

pub struct Net<'obj> {
    pub skel: NetSkel<'obj>,
    rb: RingBuffer<'obj>,
    socket_socket_rb: RingBuffer<'obj>,
}

impl<'obj> Net<'obj> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        sink_tx: Sender<Event>,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
        samples_map: BorrowedFd,
        pending_map: BorrowedFd,
        to_update_map: BorrowedFd,
        machine_id: u32,
    ) -> Self {
        let skel_builder = NetSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .expect("Net skel open failed");
        open_skel
            .maps
            .pids
            .reuse_fd(pid_map)
            .expect("Net pid_map reuse failed");
        open_skel
            .maps
            .samples
            .reuse_fd(samples_map)
            .expect("Net samples_map reuse failed");
        open_skel
            .maps
            .pending
            .reuse_fd(pending_map)
            .expect("Net pending_map reuse failed");
        open_skel
            .maps
            .to_update
            .reuse_fd(to_update_map)
            .expect("Net to_update_map reuse failed");
        open_skel
            .maps
            .pid_rb
            .reuse_fd(pid_rb)
            .expect("Net pid_rb reuse failed");

        let mut skel = open_skel.load().expect("Failed to load Net programs");
        let mut builder = RingBufferBuilder::new();
        builder
            .add(&skel.maps.rb, wrapped_callback(sink_tx.clone(), machine_id))
            .expect("Net failed to register rb callback");
        let rb = builder.build().expect("Net failed to build rb handler");

        let mut builder = RingBufferBuilder::new();
        builder
            .add(
                &skel.maps.socket_socket_rb,
                socket_socket_callback(sink_tx, machine_id),
            )
            .expect("Net failed to register socket_socket_rb callback");
        let socket_socket_rb = builder
            .build()
            .expect("Net failed to build socket_socket_rb handler");

        if let Err(e) = skel.attach() {
            warn!("Failed to attach Net programs:\n{e}");
        } else {
            info!("Successfully registered Net");
        }

        Self {
            skel,
            rb,
            socket_socket_rb,
        }
    }

    pub fn sample(&mut self) -> Result<()> {
        self.rb.consume()?;
        self.socket_socket_rb.consume()?;

        Ok(())
    }
}

fn socket_socket_callback(sink_tx: Sender<Event>, machine_id: u32) -> impl FnMut(&[u8]) -> i32 {
    move |data: &[u8]| {
        let data: &[u8; size_of::<[u64; 2]>()] = &data[..size_of::<[u64; 2]>()].try_into().unwrap();
        let data: &[u64; 2] = unsafe { std::mem::transmute::<_, _>(data) };
        let (sock1, sock2) = (data[0], data[1]);
        debug!("map {sock1} - {sock2}");

        let res1 = sink_tx.send(Event::SocketMap(SocketMapEvent {
            machine_id: machine_id,
            sock1_inode_id: sock1,
            sock2_inode_id: sock2,
        }));
        let res2 = sink_tx.send(Event::SocketMap(SocketMapEvent {
            machine_id: machine_id,
            sock1_inode_id: sock2,
            sock2_inode_id: sock1,
        }));

        match (res1, res2) {
            (Err(_), _) => 1,
            (_, Err(_)) => 1,
            _ => 0,
        }
    }
}

fn wrapped_callback(sink_tx: Sender<Event>, machine_id: u32) -> impl FnMut(&[u8]) -> i32 {
    move |data: &[u8]| {
        let data: &[u8; size_of::<socket_context_value>()] = &data
            [..size_of::<socket_context_value>()]
            .try_into()
            .unwrap();
        let socket_context: &socket_context_value = unsafe { std::mem::transmute(data) };
        let Ok(context) = SocketContext::try_from(socket_context) else {
            return 0;
        };

        debug!(
            "ns[{}] ino[{}] {:?} {:?} -> {:?} {:?}",
            context.netns_cookie,
            context.inode_id,
            context.src_addr,
            context.src_port,
            context.dst_addr,
            context.dst_port
        );
        let res = sink_tx.send(Event::SocketContext(SocketContextEvent {
            machine_id: machine_id,
            inode_id: context.inode_id,
            family: context.sk_family,
            type_: context.sk_type,
            protocol: context.sk_protocol,
        }));

        if let Err(_) = res {
            return 1;
        }

        let res = match (context.src_addr, context.dst_addr) {
            (Some(IpAddr::V4(src_addr)), Some(IpAddr::V4(dst_addr))) => {
                sink_tx.send(Event::SocketInet(SocketInetEvent {
                    machine_id: machine_id,
                    inode_id: context.inode_id,
                    netns_cookie: context.netns_cookie,
                    src_address: src_addr.to_string(),
                    src_port: context.src_port.unwrap_or(0),
                    dst_address: dst_addr.to_string(),
                    dst_port: context.dst_port.unwrap_or(0),
                }))
            }
            (Some(IpAddr::V4(src_addr)), None) => {
                sink_tx.send(Event::SocketInet(SocketInetEvent {
                    machine_id: machine_id,
                    inode_id: context.inode_id,
                    netns_cookie: context.netns_cookie,
                    src_address: src_addr.to_string(),
                    src_port: context.src_port.unwrap_or(0),
                    dst_address: Ipv4Addr::from(0).to_string(),
                    dst_port: context.dst_port.unwrap_or(0),
                }))
            }
            (Some(IpAddr::V6(src_addr)), Some(IpAddr::V6(dst_addr))) => {
                sink_tx.send(Event::SocketInet(SocketInetEvent {
                    machine_id: machine_id,
                    inode_id: context.inode_id,
                    netns_cookie: context.netns_cookie,
                    src_address: src_addr.to_string(),
                    src_port: context.src_port.unwrap_or(0),
                    dst_address: dst_addr.to_string(),
                    dst_port: context.dst_port.unwrap_or(0),
                }))
            }
            (Some(IpAddr::V6(src_addr)), None) => {
                sink_tx.send(Event::SocketInet(SocketInetEvent {
                    machine_id: machine_id,
                    inode_id: context.inode_id,
                    netns_cookie: context.netns_cookie,
                    src_address: src_addr.to_string(),
                    src_port: context.src_port.unwrap_or(0),
                    dst_address: Ipv4Addr::from(0).to_string(),
                    dst_port: context.dst_port.unwrap_or(0),
                }))
            }
            _ => {
                return 0;
            }
        };

        if let Err(_) = res {
            return 1;
        }

        0
    }
}
