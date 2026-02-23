extern crate env_logger;
extern crate log;
use chrono::Utc;
use log::{info, warn};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[macro_use]
extern crate serde_derive;

extern crate clap_log_flag;
extern crate clap_verbosity_flag;

extern crate strum;
#[macro_use]
extern crate strum_macros;

extern crate confy;

extern crate chrono;

use std::{net::IpAddr, net::Ipv4Addr, sync::Arc};

use rustls::{self, RootCertStore, ServerConfig, ServerConnection};

use clap::Parser;
use std::net;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

use kmip_server::ServerContext;
use kmip_server::crypto::rng::SecureRngSource;
use kmip_server::store::KmipStore;
use kmip_server::{ClockSource, handle_client};
// use bson;

#[derive(Debug, Clone, EnumString)]
enum StoreType {
    Memory,
    MongoDB,
}

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
#[command(name = "server")]
#[command(about = "KMIP server", long_about = None)]
struct CmdLine {
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    // #[structopt(flatten)]
    // log: clap_log_flag::Log,
    #[arg(name = "debug", short = 'd', long = "debug")]
    /// Debug output
    debug: bool,

    /// Server PEM Certificate
    #[arg(name = "serverCert", long = "serverCert")]
    server_cert_file: PathBuf,

    /// Server Key Certificate
    #[arg(name = "serverKey", long = "serverKey")]
    server_key_file: PathBuf,

    /// CA Certificate File
    #[arg(name = "caFile", long = "caFile")]
    ca_cert_file: PathBuf,

    /// Port to listen on
    #[arg(name = "port", long = "port", default_value = "5696")]
    port: u16,

    /// Store to use
    #[arg(name = "store", long = "store", default_value = "Memory")]
    store: StoreType,
}

// #[derive(Serialize, Deserialize, Debug)]
// struct MyConfig {
//     version: u8,
//     api_key: String,
// }

// /// `MyConfig` implements `Default`
// impl ::std::default::Default for MyConfig {
//     fn default() -> Self {
//         Self {
//             version: 0,
//             api_key: "".into(),
//         }
//     }
// }

pub struct PreciseClockSource {}

impl PreciseClockSource {
    pub fn new() -> PreciseClockSource {
        PreciseClockSource {}
    }
}

impl Default for PreciseClockSource {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockSource for PreciseClockSource {
    fn now(&self) -> chrono::DateTime<Utc> {
        Utc::now()
    }
}

fn main() {
    env_logger::init();

    let args = CmdLine::parse();
    println!("{:?}", args);

    //args.log.log_all(args.verbose.log_level());

    info!("starting up");
    // warn!("oops, nothing implemented!");

    // let cfg = confy::load::<MyConfig>("qrb").unwrap();

    // println!("cfg {:?}", cfg);

    // confy::store("qrb", cfg).expect("foooooo3124123");

    let addr: net::SocketAddr =
        net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), args.port);
    //TODO addr.set_port(args.flag_port.unwrap_or(5696));

    let listener = TcpListener::bind(&addr).expect("cannot listen on port");

    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let ca_cert = CertificateDer::from_pem_file(args.ca_cert_file).unwrap();

    root_store.add(ca_cert).unwrap();

    let server_cert = CertificateDer::from_pem_file(args.server_cert_file).unwrap();
    let server_cert_private_key = PrivateKeyDer::from_pem_file(args.server_key_file).unwrap();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_cert_private_key)
        .unwrap();

    let clock_source = Arc::new(PreciseClockSource::new());
    let rng_source = Arc::new(SecureRngSource::new());

    let store: Arc<KmipStore> = match args.store {
        StoreType::Memory => {
            info!("Using Memory Store");
            Arc::new(KmipStore::new_mem(clock_source.clone()))
        }
        StoreType::MongoDB => {
            info!("Using MongoDB Store");
            let uri = "mongodb://localhost:27017/";
            Arc::new(KmipStore::new_mongodb(clock_source.clone(), uri))
        }
    };

    let server_context = Arc::new(ServerContext::new(store, clock_source, rng_source));
    let sc = Arc::new(server_config);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("new client!");
                let sc2 = sc.clone();
                let server_context2 = server_context.clone();

                thread::spawn(move || {
                    let mut tls_session = ServerConnection::new(sc2).unwrap();
                    let mut tls = rustls::Stream::new(&mut tls_session, &mut stream);

                    loop {
                        handle_client(&mut tls, &server_context2);
                    }
                });
            }
            Err(e) => warn!("Connection failed: {}", e),
        }
    }
}
