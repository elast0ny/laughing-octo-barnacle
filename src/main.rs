use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;

use clap::{Clap, ValueHint};
use rustls::{AllowAnyAuthenticatedClient, ClientConfig, ClientSession, ServerConfig, ServerSession};

use comms::*;
mod comms;

#[derive(Clap)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
/// Basic TLS over TCP echo server
struct Args {
    /// Address to listen/connect to
    addr: String,

    /// Whether to run as a server or as a client
    #[clap(subcommand)]
    mode: SubCommand,
}
#[derive(Debug, Clap)]
pub enum SubCommand {
    #[clap(name = "server")]
    Server(ServerArgs),
    #[clap(name = "client")]
    Client(ClientArgs),
}

#[derive(Debug, Clap)]
pub struct ServerArgs {
    #[clap(long, parse(from_os_str), value_hint = ValueHint::FilePath)]
    priv_key: PathBuf,
    #[clap(long, parse(from_os_str), value_hint = ValueHint::FilePath)]
    pub_key: PathBuf,

    /// PEM file containing the CA that is supposed to have signed the client
    #[clap(short, long, parse(from_os_str), value_hint = ValueHint::FilePath)]
    client_root_store: Option<PathBuf>,
}

#[derive(Debug, Clap)]
pub struct ClientArgs {
    /// PEM file containing the CA that is supposed to have signed the server certs
    #[clap(parse(from_os_str), value_hint = ValueHint::FilePath)]
    root_store: PathBuf,

    /// Common name that identifies the server
    #[clap(short, long)]
    server_cn: String,

    #[clap(long, requires="pub-key", parse(from_os_str), value_hint = ValueHint::FilePath)]
    priv_key: Option<PathBuf>,
    #[clap(long, requires="priv-key", parse(from_os_str), value_hint = ValueHint::FilePath)]
    pub_key: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    match args.mode {
        SubCommand::Client(client_args) => {
            let mut config = ClientConfig::new();
            if let Err(e) = config.root_store.add_pem_file(&mut BufReader::new(File::open(client_args.root_store)?)) {
                eprintln!("unable to load root store : {:?}", e);
                return Err(From::from("Fatal error".to_string()));
            }
            
            // If client certs are provided, load them
            if let (Some(priv_key), Some(pub_key)) = (client_args.priv_key, client_args.pub_key) {
                let mut cert_file = BufReader::new(File::open(pub_key).expect("Cannot open client pub_key"));
                let certs = rustls_pemfile::certs(&mut cert_file).unwrap().iter().map(|v| rustls::Certificate(v.clone())).collect();
                
                let mut key_file = BufReader::new(File::open(priv_key).expect("Cannot open client priv_key"));
                let key = loop {
                    match rustls_pemfile::read_one(&mut key_file).expect("Cannot parse client priv_key file") {
                        Some(rustls_pemfile::Item::RSAKey(key)) => break rustls::PrivateKey(key),
                        Some(rustls_pemfile::Item::PKCS8Key(key)) => break rustls::PrivateKey(key),
                        None => {
                            return Err(From::from("Failed to load client priv_key".to_string()));
                        }
                        _ => {
                            continue;
                        },
                    }
                };
                config.set_single_client_cert(certs, key).expect("Invalid client pub-key or priv-key");
                println!("Loaded client auhtnetication certs !");
            } else {
                println!("No client authentication certs");
            }

            let comms = Comms::<ClientSession>::connect(args.addr.as_str(), client_args.server_cn.as_str(), config)?;
            client_echo(comms);
        },
        SubCommand::Server(server_args) => {
            loop {
                // Load up client CA and force authentication if provided
                let client_auth = if let Some(ref root_store_path) = server_args.client_root_store {
                    let mut root_store = rustls::RootCertStore::empty();
                    if let Err(e) = root_store.add_pem_file(&mut BufReader::new(File::open(root_store_path)?)) {
                        eprintln!("unable to load root store : {:?}", e);
                        return Err(From::from("Fatal error".to_string()));
                    }
                    println!("Client authentication CA loaded");
                    AllowAnyAuthenticatedClient::new(root_store)
                } else {
                    println!("No client authentication");
                    rustls::NoClientAuth::new()
                };

                let mut config = ServerConfig::new(client_auth);
                
                let mut cert_file = BufReader::new(File::open(&server_args.pub_key).expect("Cannot open pub_key"));
                let certs = rustls_pemfile::certs(&mut cert_file).unwrap().iter().map(|v| rustls::Certificate(v.clone())).collect();
                
                let mut key_file = BufReader::new(File::open(&server_args.priv_key).expect("Cannot open priv_key"));
                let key = loop {
                    match rustls_pemfile::read_one(&mut key_file).expect("Cannot parse priv_key file") {
                        Some(rustls_pemfile::Item::RSAKey(key)) => break rustls::PrivateKey(key),
                        Some(rustls_pemfile::Item::PKCS8Key(key)) => break rustls::PrivateKey(key),
                        None => {
                            return Err(From::from("Failed  to load priv_key".to_string()));
                        }
                        _ => {
                            continue;
                        },
                    }
                };

                config.set_single_cert(certs, key).expect("Bad certificates/private key");

                let comms = match Comms::<ServerSession>::connect(args.addr.as_str(), config) {
                    Err(e) => {
                        eprintln!("{:?}", e);
                        continue;
                    },
                    Ok(c) => c,
                };
                server_echo(comms);
            }
        }
    };

    Ok(())
}


pub fn client_echo(mut comms: Comms<ClientSession>) {

    let mut buffer = String::new();
    let stdin = std::io::stdin();

    while buffer != "q\r\n" {
        buffer.clear();
        if let Err(e) = stdin.read_line(&mut buffer) {
            eprintln!("Failed to read stdin : {:?}", e);
            break;
        }

        // Send the input to the server
        if let Err(e) = comms.send_msg(&Message::Echo(buffer.clone())) {
            eprintln!("Failed to send message : {:?}", e);
            break;
        }

        // Print the response
        match comms.recv_msg() {
            Ok(Message::Echo(msg)) => println!("[RECV] {}", msg),
            Err(e) => {
                eprintln!("Failed to recv message : {:?}" , e);
                break;
            },
        };
        
    }

    println!("Client disconnecting...");
}

pub fn server_echo(mut comms: Comms<ServerSession>) {
    loop {
        match comms.recv_msg() {
            Ok(msg) => {
                match msg {
                    Message::Echo(msg) => {
                        if let Err(e) = comms.send_msg(&Message::Echo(msg.clone())) {
                            eprintln!("Failed to forward echo message : {:?}", e);
                            break;
                        }
                    },
                }
            },
            Err(e) => {
                eprintln!("Failed to receive message : {:?}", e);
                break;
            }
        }
    }
}