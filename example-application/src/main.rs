use clap::{command, value_parser, Arg, ArgAction};
use core_affinity::{self, CoreId};
use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

type Job = Box<dyn FnOnce() -> () + Send + 'static>;

struct Worker {
    id: usize,
    handle: JoinHandle<()>,
}

impl Worker {
    fn new(id: usize, rx: Arc<Mutex<Receiver<Job>>>, core: Option<CoreId>) -> Self {
        let handle = thread::spawn(move || loop {
            if let Some(core) = core {
                core_affinity::set_for_current(core);
            }

            let job = rx.lock().unwrap().recv().unwrap();
            println!("worker {:?} start", id);
            job();
            println!("worker {:?} end", id);
        });

        Self { id, handle }
    }
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    tx: Sender<Job>,
}

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        assert!(size > 0);

        let mut workers = Vec::with_capacity(size);
        let (tx, rx) = mpsc::channel();
        let rx = Arc::new(Mutex::new(rx));
        let cores = core_affinity::get_core_ids().unwrap();
        core_affinity::set_for_current(cores[0]);

        for id in 0..size {
            workers.push(Worker::new(id, rx.clone(), Some(cores[id + 1])));
        }

        Self { workers, tx }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() -> () + Send + 'static,
    {
        let job = Box::new(f);
        self.tx.send(job).unwrap();
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let mut buf = BufReader::new(&mut stream);
    buf.fill_buf().unwrap();
    req.parse(buf.buffer()).unwrap();
    match req.path {
        Some("/cpu") => {
            cpu_workload();
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        }
        Some("/memory") => {
            memory_workload();
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap()
        }
        Some("/disk") => {
            disk_workload();
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap()
        }
        Some("/overload_cpu") => stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(),
        Some("/overload_disk") => stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(),
        Some(_) => stream.write_all(b"HTTP/1.1 404 NOT FOUND\r\n\r\n").unwrap(),
        _ => stream.write_all(b"HTTP/1.1 404 NOT FOUND\r\n\r\n").unwrap(),
    }
}

fn cpu_workload() {
    println!("Executing short cpu workload");
    for _ in 0..100000000 {}
}

fn disk_workload() {
    println!("Executing short disk workload");
}

fn memory_workload() {}

fn main() {
    let mut matches = command!() // requires `cargo` feature
        .next_line_help(true)
        .arg(
            Arg::new("threads")
                .required(true)
                .long("threads")
                .action(ArgAction::Set)
                .value_parser(value_parser!(usize))
                .help("The main process to monitor"),
        )
        .get_matches();
    let threads = matches
        .remove_one::<usize>("threads")
        .expect("Required argument");

    let listener = TcpListener::bind("127.0.0.1:7878").expect("Port unavailable");
    let pool = ThreadPool::new(threads);

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        pool.execute(|| {
            handle_connection(stream);
        });
    }
}
