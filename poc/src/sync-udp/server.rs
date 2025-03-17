use std::net::UdpSocket;

fn main() {
    let server = UdpSocket::bind("127.0.0.1:5150").unwrap();
    let mut read_buf: [u8; 16] = [0; 16];
    loop {
        let Ok((len, src)) = server.recv_from(&mut read_buf) else {
            break;
        };
        server.send_to("response".as_bytes(), src).unwrap();
        println!(
            "received {}",
            String::from_utf8(read_buf[..len].into()).unwrap()
        );
    }
}
