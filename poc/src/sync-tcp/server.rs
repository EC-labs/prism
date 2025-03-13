use std::{
    io::{Read, Write},
    net::TcpListener,
};

fn main() {
    let server = TcpListener::bind("::1:8080").unwrap();
    let (mut conn, addr) = server.accept().unwrap();
    let mut read_buf: [u8; 16] = [0; 16];
    loop {
        let Ok(len) = conn.read(&mut read_buf) else {
            break;
        };
        println!("{}", String::from_utf8(read_buf[..len].into()).unwrap());
        conn.write("response".as_bytes()).unwrap();
    }
    println!("{:?}", addr);
}
