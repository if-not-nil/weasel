use lung::Server;

fn main() {
    // println!("{:?}", shared)
    Server::new("0.0.0.0:1337").listen();
}
