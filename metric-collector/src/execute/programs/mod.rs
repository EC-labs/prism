use libc::{self, c_int};
use std::{fs::File, os::unix::prelude::*, process, sync::RwLock};

pub mod clone;
pub mod futex;
pub mod iowait;
pub mod ipc;

pub static BOOT_EPOCH_NS: RwLock<u128> = RwLock::new(0);

type Receiver = File;
type Sender = File;

pub fn pipe() -> (Receiver, Sender) {
    let mut fds: [c_int; 2] = [0; 2];
    let res = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if res != 0 {
        process::exit(1);
    }
    let reader = unsafe { File::from_raw_fd(fds[0]) };
    let writer = unsafe { File::from_raw_fd(fds[1]) };
    (reader, writer)
}

pub fn fcntl_setfd(file: &mut File, flags: c_int) {
    let res = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags) };
    if res != 0 {
        println!("Non-zero fcntl return {:?}", res);
    }
}

pub fn bpf_pipe(buf_size: u32) -> (Receiver, Sender) {
    let (bpf_pipe_rx, bpf_pipe_tx) = pipe();
    let res = unsafe { libc::fcntl(bpf_pipe_rx.as_raw_fd(), libc::F_SETPIPE_SZ, buf_size) };
    let buf_size: i32 = buf_size.try_into().unwrap();
    if res != buf_size {
        println!("Could not change pipe rx buffer to {:?}", buf_size);
    }
    let res = unsafe { libc::fcntl(bpf_pipe_tx.as_raw_fd(), libc::F_SETPIPE_SZ, buf_size) };
    if res != buf_size {
        println!("Could not change pipe tx buffer to {:?}", buf_size);
    }
    (bpf_pipe_rx, bpf_pipe_tx)
}
