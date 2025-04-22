// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::Result;
use duckdb::{Appender, Connection, ToSql};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject, RingBuffer, RingBufferBuilder,
};
use libc::{AF_INET, AF_INET6, AF_UNIX, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_STREAM};
use log::debug;
use net::{types::socket_context_value, NetSkel, NetSkelBuilder};
use std::{
    fmt::Debug,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::BorrowedFd,
};

mod net {
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
    _skel: NetSkel<'obj>,
    rb: RingBuffer<'obj>,
    socket_socket_rb: RingBuffer<'obj>,
}

impl<'obj> Net<'obj> {
    pub fn new<'conn>(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        conn: &'conn Connection,
        pid_map: BorrowedFd,
        pid_rb: BorrowedFd,
        samples_map: BorrowedFd,
        pending_map: BorrowedFd,
        to_update_map: BorrowedFd,
    ) -> Result<Self>
    where
        'conn: 'obj,
    {
        Self::init_store(conn)?;
        let skel_builder = NetSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map)?;
        open_skel.maps.samples.reuse_fd(samples_map)?;
        open_skel.maps.pending.reuse_fd(pending_map)?;
        open_skel.maps.to_update.reuse_fd(to_update_map)?;
        open_skel.maps.pid_rb.reuse_fd(pid_rb)?;

        let mut skel = open_skel.load()?;
        let mut builder = RingBufferBuilder::new();
        builder.add(
            &skel.maps.rb,
            wrapped_callback(
                conn.appender("socket_context").unwrap(),
                conn.appender("socket_inet").unwrap(),
            ),
        )?;
        let rb = builder.build()?;

        let mut builder = RingBufferBuilder::new();
        builder.add(
            &skel.maps.socket_socket_rb,
            socket_socket_callback(conn.appender("socket_map").unwrap()),
        )?;
        let socket_socket_rb = builder.build()?;

        skel.attach()?;

        Ok(Self {
            _skel: skel,
            rb,
            socket_socket_rb,
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE socket_context (
                    inode_id UBIGINT,
                    family          USMALLINT, 
                    type            USMALLINT, 
                    protocol        USMALLINT, 
                );

                CREATE OR REPLACE TABLE socket_inet (
                    inode_id        UBIGINT,
                    netns_cookie    UBIGINT,
                    src_address     VARCHAR,
                    src_port        USMALLINT, 
                    dst_address     VARCHAR,
                    dst_port        USMALLINT, 
                );

                CREATE OR REPLACE TABLE socket_map (
                    sock1_inode_id UBIGINT,
                    sock2_inode_id UBIGINT,
                );
            ",
        )?;
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        self.rb.consume()?;
        self.socket_socket_rb.consume()?;

        Ok(())
    }
}

fn socket_socket_callback<'conn>(
    mut socket_socket_appender: Appender<'conn>,
) -> impl FnMut(&[u8]) -> i32 + use<'conn> {
    move |data: &[u8]| {
        let data: &[u8; size_of::<[u64; 2]>()] = &data[..size_of::<[u64; 2]>()].try_into().unwrap();
        let data: &[u64; 2] = unsafe { std::mem::transmute::<_, _>(data) };
        let (sock1, sock2) = (data[0], data[1]);
        debug!("map {sock1} - {sock2}");
        socket_socket_appender.append_row([sock1, sock2]).unwrap();
        socket_socket_appender.append_row([sock2, sock1]).unwrap();
        0
    }
}

fn wrapped_callback<'conn>(
    mut socket_context_appender: Appender<'conn>,
    mut socket_inet_appender: Appender<'conn>,
) -> impl FnMut(&[u8]) -> i32 + use<'conn> {
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

        socket_context_appender
            .append_row([
                &context.inode_id as &dyn ToSql,
                &context.sk_family,
                &context.sk_type,
                &context.sk_protocol,
            ])
            .unwrap();
        match (context.src_addr, context.dst_addr) {
            (Some(IpAddr::V4(src_addr)), Some(IpAddr::V4(dst_addr))) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &dst_addr.to_string(),
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            (Some(IpAddr::V4(src_addr)), None) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &Ipv4Addr::from(0).to_string() as &dyn ToSql,
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            (Some(IpAddr::V6(src_addr)), Some(IpAddr::V6(dst_addr))) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &dst_addr.to_string(),
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            (Some(IpAddr::V6(src_addr)), None) => {
                socket_inet_appender
                    .append_row([
                        &context.inode_id as &dyn ToSql,
                        &context.netns_cookie as &dyn ToSql,
                        &src_addr.to_string(),
                        &context.src_port.unwrap_or(0),
                        &Ipv4Addr::from(0).to_string() as &dyn ToSql,
                        &context.dst_port.unwrap_or(0),
                    ])
                    .unwrap();
            }
            _ => {}
        }
        0
    }
}
