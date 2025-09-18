use rand::Rng;
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect("127.0.0.1:5150").unwrap();
    loop {
        client.send("request".as_bytes()).unwrap();
        let millis = rand::thread_rng().gen_range(0..5000);
        println!("{:?}", millis);
        std::thread::sleep(Duration::from_millis(millis));
    }
}
