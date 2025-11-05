use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use crate::{
    comms::{Request, Response},
    encryption::gen_token,
    meta::{HeaderKind, StatusCode},
    server::db::{self, SuitableDB},
};

fn handler_nyi(mut stream: TcpStream, req: Request, db: &mut db::InMemory) {
    let _ = stream.write_all(
        Response::new(StatusCode::Unsupported)
            .to_string()
            .as_bytes(),
    );
}

fn handler_hash(mut stream: TcpStream, req: Request, db: &mut db::InMemory) {
    let hash = req.headers.get(&HeaderKind::Hash).unwrap();
    let client = req.headers.get(&HeaderKind::Client).unwrap();

    let session_id_mock = gen_token(8); // store in db, maybe replace with jwt later?
    // todo use constant_time_eq
    if db.check_client_auth(client, hash) {
        let _ = stream.write_all(
            Response::new(StatusCode::HashAccepted)
                .to_string()
                .header(ResponseHeaderKind::Ok, "true")
                .header(ResponseHeaderKind::SessionID, session_id_mock)
                .as_bytes(),
        );
    } else {
        let _ = stream.write_all(
            Response::new(StatusCode::AuthInvalid)
                .to_string()
                .as_bytes(),
        );
    }
}

type Handler = fn(TcpStream, Request, &mut db::InMemory);

fn write_error(
    mut writer: impl Write,
    code: StatusCode,
    message: impl Into<String>,
) -> Result<(), std::io::Error> {
    writer.write_all(Response::with_body(code, message).to_string().as_bytes())
}

pub struct Server {
    address: std::net::SocketAddr,
    db: db::InMemory, // can be any db really, depending on the implementation
}

impl Server {
    pub fn new<T: std::net::ToSocketAddrs>(addr: T) -> Self {
        Self {
            db: db::InMemory::new(),
            address: addr.to_socket_addrs().unwrap().next().unwrap(),
        }
    }
    pub fn listen(mut self) {
        let listener = TcpListener::bind(self.address).unwrap();
        loop {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).unwrap();

            let request_text = String::from_utf8_lossy(&buf);
            match Request::try_from(request_text.to_string()) {
                Ok(request) => {
                    println!("got request: {:#?}", request);
                    self.process_request(stream, request);
                }
                Err(e) => {
                    write_error(stream, e.clone().to_status_code(), e.inner()).unwrap();
                }
            }
        }
    }

    fn process_request(&mut self, mut stream: TcpStream, request: Request) {
        let handler: Handler = match request.kind {
            crate::meta::RequestKind::Send => handler_nyi,
            crate::meta::RequestKind::ChallengePlease => handler_nyi,
            crate::meta::RequestKind::ChallengeAccepted => handler_nyi,
            crate::meta::RequestKind::Certificate => handler_nyi,
            crate::meta::RequestKind::HashAuth => handler_hash,
        };
        handler(stream, request, &mut self.db);
    }
}
