use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use ::rustls::{ClientConfig, ServerConfig, ClientSession, ServerSession, Session, StreamOwned};
use ::simple_parse::{SpRead, SpWrite};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(SpRead, SpWrite)]
pub enum Message {
    Echo(String),
}
pub struct Comms<T: Session + Sized> {
    pub addr: String,
    pub conn: StreamOwned<T, TcpStream>,
}

impl<T: Session + Sized> Comms<T> {
    pub fn recv_msg(&mut self) -> Result<Message> {
        Ok(Message::from_reader(&mut self.conn.sock)?)
    }
    pub fn send_msg(&mut self, msg: &Message) -> Result<usize> {
        Ok(msg.to_writer(&mut self.conn.sock)?)
    }
}

impl Comms<ClientSession> {
    pub fn connect(addr: &str, server_cn: &str, config: ClientConfig) -> Result<Self> {
        
        // Create tls session from config
        let mut session = ClientSession::new(
            &Arc::new(config),
            webpki::DNSNameRef::try_from_ascii_str(server_cn)?,
        );

        println!("Connecting to '{}' ...", addr);
        // connect to remote addr
        let mut tcp_sock = TcpStream::connect(addr)?;

        println!("Performing handshake !");
        session.complete_io(&mut tcp_sock)?;
        while session.wants_write() && session.write_tls(&mut tcp_sock)? > 0 {};
        
        println!("Connected !");
        let conn = StreamOwned::new(session, tcp_sock);

        Ok(Self { addr: addr.to_string(), conn })
    }
}
impl Comms<ServerSession> {
    pub fn connect(addr: &str, config: ServerConfig) -> Result<Self> {
        
        let mut session = ServerSession::new(&Arc::new(config));
        let listenner = TcpListener::bind(addr)?;

        println!("Waiting for connection on '{}'...", addr);
        let (mut tcp_sock, addr) = listenner.accept()?;

        println!("Performing handshake !");
        session.complete_io(&mut tcp_sock)?;

        println!("Peer connected !");

        let conn = StreamOwned::new(session, tcp_sock);

        Ok(Self { addr: addr.to_string(), conn })
    }
}