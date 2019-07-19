use std::sync::Arc;

use std::net::TcpStream;
use std::io::{Read, Write, stdout};
use std::fs;
use std::io::{BufReader};
use std::path::PathBuf;

#[macro_use]
extern crate structopt;
extern crate clap_log_flag;
extern crate clap_verbosity_flag;
use structopt::StructOpt;

#[macro_use]
extern crate log;

use rustls;
use webpki;
use rustls::Session;

use pretty_hex::*;

use protocol::read_msg;

use ttlv::*;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, StructOpt)]
#[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
struct CmdLine {
    #[structopt(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[structopt(flatten)]
    log: clap_log_flag::Log,

    #[structopt(name = "debug", short = "d", long = "debug")]
    /// Debug output
    debug: bool,

    /// Client PEM Certificate
    #[structopt(parse(from_os_str), name = "clientCert", long = "clientCert")]
    client_cert_file: PathBuf,

    /// Client Key Certificate
    #[structopt(parse(from_os_str), name = "clientKey", long = "clientKey")]
    client_key_file: PathBuf,

    /// CA Certificate File
    #[structopt(parse(from_os_str), name = "caFile", long = "caFile")]
    ca_cert_file: PathBuf,

    /// Host name to connect to
    #[structopt(name = "host", long = "host", default_value="localhost")]
    host: String,

    /// Port to connect to
    #[structopt(name = "port", long = "port", default_value="7000")]
    port: u16,
}


// fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
//     let certfile = fs::File::open(filename).expect("cannot open certificate file");
//     let mut reader = BufReader::new(certfile);
//     rustls::internal::pemfile::certs(&mut reader).unwrap()
// }

// fn load_private_key(filename: &str) -> rustls::PrivateKey {
//     let rsa_keys = {
//         let keyfile = fs::File::open(filename).expect("cannot open private key file");
//         let mut reader = BufReader::new(keyfile);
//         rustls::internal::pemfile::rsa_private_keys(&mut reader)
//             .expect("file contains invalid rsa private key")
//     };

//     let pkcs8_keys = {
//         let keyfile = fs::File::open(filename).expect("cannot open private key file");
//         let mut reader = BufReader::new(keyfile);
//         rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
//             .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
//     };

//     // prefer to load pkcs8 keys
//     if !pkcs8_keys.is_empty() {
//         pkcs8_keys[0].clone()
//     } else {
//         assert!(!rsa_keys.is_empty());
//         rsa_keys[0].clone()
//     }
// }



fn main() {
    println!("Hello, world!");

    env_logger::init();

    let args = CmdLine::from_args();
    println!("{:?}", args);

    args.log.log_all(Option::Some(args.verbose.log_level()));

    info!("starting up");
    warn!("oops, nothing implemented!");


    // TODO - add client auth

    let mut config = rustls::ClientConfig::new();
    //config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);


    let certfile = fs::File::open(args.ca_cert_file).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    config.root_store
        .add_pem_file(&mut reader)
        .unwrap();


    // let mut server_certs = load_certs(args.serverCertFile.as_ref());
    // let privkey = load_private_key(args.serverKeyFile.as_ref());

    // let mut ca_certs = load_certs(args.caCertFile.as_ref());



    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&args.host).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect( (args.host.as_str(), args.port)).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    // tls.write(concat!("GET / HTTP/1.1\r\n",
    //                   "Host: google.com\r\n",
    //                   "Connection: close\r\n",
    //                   "Accept-Encoding: identity\r\n",
    //                   "\r\n")
    //           .as_bytes())
    //     .unwrap();

    let bytes = vec![
        0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x01, 0x20, 0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00,
        0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0d, 0x02,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
        0x01, 0x00, 0x00, 0x00, 0xd8, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x42,
        0x00, 0x57, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x91, 0x01, 0x00, 0x00, 0x00, 0xa8, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
        0x30, 0x42, 0x00, 0x0a, 0x07, 0x00, 0x00, 0x00, 0x17, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f,
        0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
        0x68, 0x6d, 0x00, 0x42, 0x00, 0x0b, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a,
        0x07, 0x00, 0x00, 0x00, 0x14, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
        0x68, 0x69, 0x63, 0x20, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00, 0x42,
        0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07, 0x00, 0x00, 0x00,
        0x18, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20,
        0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x4d, 0x61, 0x73, 0x6b, 0x42, 0x00, 0x0b, 0x02, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    ];

    tls.write(&bytes).unwrap();

    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(&mut std::io::stderr(), "Current ciphersuite: {:?}", ciphersuite.suite).unwrap();

    info!("Waiting for data....");

    let mut plaintext : Vec<u8> = Vec::new();
    let msg = read_msg(&mut tls);
    info!("Response Message: {:?}", msg.hex_dump());

    to_print(&msg);

   //tls.read_to_end(&mut plaintext).unwrap();

    //stdout().write_all(&plaintext).unwrap();
}