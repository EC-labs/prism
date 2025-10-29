use anyhow::Result;
use duckdb::{Appender, Connection};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, OpenObject,
};
use std::{mem::MaybeUninit, os::fd::BorrowedFd};

mod mux_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sub/mux/bpf/mux.skel.rs"
    ));
}
use mux_skel::*;

pub struct Muxio<'obj, 'conn> {
    skel: MuxSkel<'obj>,
    muxio_appender: Appender<'conn>,
    machine_id: u32,
}

impl<'obj, 'conn> Muxio<'obj, 'conn> {
    pub fn new(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        pid_map: BorrowedFd,
        conn: &'conn Connection,
        machine_id: u32,
    ) -> Result<Self> {
        let skel_builder = MuxSkelBuilder::default();

        let mut open_skel = skel_builder.open(open_object)?;
        open_skel.maps.pids.reuse_fd(pid_map)?;

        let mut skel = open_skel.load()?;
        // samples_init::<granularity, stats>(&skel.maps.samples)?;
        skel.attach()?;

        Self::init_store(conn)?;
        let muxio_appender = conn.appender("muxio_wait")?;
        Ok(Self {
            skel,
            muxio_appender,
            machine_id,
        })
    }

    fn init_store(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
                CREATE OR REPLACE TABLE muxio_wait (
                    machine_id UINTEGER,
                    ts_s TIMESTAMP,
                    pid UINTEGER,
                    tid UINTEGER,
                    is_epoll BOOLEAN,
                    poll_id UBIGINT,
                    total_time UBIGINT,
                    total_requests UBIGINT,
                );
            ",
        )?;
        Ok(())
    }

    pub fn sample(&mut self) -> Result<()> {
        Ok(())
    }
}
