#[macro_use]
extern crate log;
extern crate env_logger;
use log::{info, warn};

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate structopt;
extern crate clap_log_flag;
extern crate clap_verbosity_flag;
use structopt::StructOpt;

extern crate strum;
#[macro_use]
extern crate strum_macros;

extern crate confy;

extern crate chrono;

use std::sync::Arc;

use rustls;

use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, Session,
};

use std::fs;
use std::io::BufReader;
use std::net;
use std::net::TcpListener;
use std::path::PathBuf;
use std::string::ToString;
use std::thread;

use kmip_server::handle_client;
use kmip_server::store::KmipMemoryStore;
use kmip_server::store::KmipMongoDBStore;
use kmip_server::ServerContext;
use kmip_server::{store::KmipStore, TestClockSource};

// use bson;

// mod git;
// mod watchman;
#[derive(Debug, EnumString)]
enum StoreType {
    Memory,
    MongoDB,
}

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, StructOpt)]
#[structopt(global_settings(&[structopt::clap::AppSettings::ColoredHelp]))]
struct CmdLine {
    #[structopt(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    // #[structopt(flatten)]
    // log: clap_log_flag::Log,
    #[structopt(name = "debug", short = "d", long = "debug")]
    /// Debug output
    debug: bool,

    /// Server PEM Certificate
    #[structopt(parse(from_os_str), name = "serverCert", long = "serverCert")]
    server_cert_file: PathBuf,

    /// Server Key Certificate
    #[structopt(parse(from_os_str), name = "serverKey", long = "serverKey")]
    server_key_file: PathBuf,

    /// CA Certificate File
    #[structopt(parse(from_os_str), name = "caFile", long = "caFile")]
    ca_cert_file: PathBuf,

    /// Port to listen on
    #[structopt(name = "port", long = "port", default_value = "5696")]
    port: u16,

    /// Store to use
    #[structopt(name = "store", long = "store", default_value = "Memory")]
    store: StoreType,
}

#[derive(Serialize, Deserialize, Debug)]
struct MyConfig {
    version: u8,
    api_key: String,
}

/// `MyConfig` implements `Default`
impl ::std::default::Default for MyConfig {
    fn default() -> Self {
        Self {
            version: 0,
            api_key: "".into(),
        }
    }
}

fn load_certs(filename: &PathBuf) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &PathBuf) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn main() {
    println!("Hello, world!");

    env_logger::init();

    let args = CmdLine::from_args();
    println!("{:?}", args);

    //args.log.log_all(args.verbose.log_level());

    info!("starting up");
    warn!("oops, nothing implemented!");

    // let cfg = confy::load::<MyConfig>("qrb").unwrap();

    // println!("cfg {:?}", cfg);

    // confy::store("qrb", cfg).expect("foooooo3124123");

    let addr: net::SocketAddr = "0.0.0.0:5696".parse().unwrap();
    //TODO addr.set_port(args.flag_port.unwrap_or(5696));

    let listener = TcpListener::bind(&addr).expect("cannot listen on port");
    let mut server_config = rustls::ServerConfig::new(NoClientAuth::new());

    let mut server_certs = load_certs(&args.server_cert_file);
    let privkey = load_private_key(&args.server_key_file);

    let mut ca_certs = load_certs(&args.ca_cert_file);

    server_certs.append(&mut ca_certs);

    server_config.set_single_cert(server_certs, privkey);

    let store: Arc<dyn KmipStore + Send + Sync> = match args.store {
        StoreType::Memory => {
            info!("Using Memory Store");
            Arc::new(KmipMemoryStore::new())
        }
        StoreType::MongoDB => {
            info!("Using MongoDB Store");
            let uri = "mongodb://localhost:27017/";
            Arc::new(KmipMongoDBStore::new(uri))
        }
    };

    let clock_source = Arc::new(TestClockSource::new());
    let server_context = Arc::new(ServerContext::new(store, clock_source));
    let sc = Arc::new(server_config);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("new client!");
                let sc2 = sc.clone();
                let server_context2 = server_context.clone();

                thread::spawn(move || {
                    let mut tls_session = rustls::ServerSession::new(&sc2);
                    let mut tls = rustls::Stream::new(&mut tls_session, &mut stream);

                    while true {
                        handle_client(&mut tls, &server_context2);
                    }
                });
            }
            Err(e) => warn!("Connection failed: {}", e),
        }
    }
}
