use std::{fs::File, sync::Arc};

use std::fs;
use std::io::BufReader;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

#[macro_use]
extern crate structopt;
extern crate clap_log_flag;
extern crate clap_verbosity_flag;
use structopt::StructOpt;

#[macro_use]
extern crate log;

use rustls;
use rustls::Session;
use webpki;

use pretty_hex::*;

use protocol::*;

use kmip_client::Client;

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
    #[structopt(name = "host", long = "host", default_value = "localhost")]
    host: String,

    /// Port to connect to
    #[structopt(name = "port", long = "port", default_value = "5696")]
    port: u16,

    #[structopt(subcommand)] // Note that we mark a field as a subcommand
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(name = "createsymmetrickey")]
    /// Create a symmetric key
    CreateSymmetricKey {
        /// Remote Directory
        #[structopt(name = "remote_path", long = "remote-path", value_name = "PATH")]
        remote_path: String,
    },
    #[structopt(name = "get")]
    /// Do a remote build of a project
    Get {
        /// ID of thing to get
        //#[structopt(short = "p")]
        id: String,
    },
    #[structopt(name = "xml")]
    /// Do a remote build of a project
    RunXml {
        /// Path to XML file to run
        #[structopt(parse(from_os_str), name = "file", long = "file")]
        file: PathBuf,
    },
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

// struct StreamAdapter<'a> {
//     stream : &'a mut rustls::Stream<'a>,
// }

// impl<'a> StreamAdapter<'a> {
//     fn new(stream : &'a mut rustls::Stream)  -> StreamAdapter<'a> {
//         return StreamAdapter {
//             stream : stream,
//         }
//     }
// }

// impl<'a> kmip_client::Stream  for StreamAdapter<'a>  {

// }
extern crate minidom;
//extern crate quick_xml;
use minidom::Element;

fn run_xml<'a, T>(filename: &PathBuf, client: &mut Client<'a, T>)
where
    T: 'a + Read + Write,
{
    let mut file = minidom::quick_xml::Reader::from_file(filename).unwrap();
    let root: Element = Element::from_reader(&mut file).unwrap();

    let mut reqs: Vec<String> = Vec::new();
    let mut resps: Vec<String> = Vec::new();
    for child in root.children() {
        let mut buf: Vec<u8> = Vec::new();
        child.write_to(&mut buf).unwrap();
        let xml_str = std::str::from_utf8(&buf).unwrap().to_string();
        // println!("{:?}", child);
        println!("xml_str{:?}", xml_str);
        if child.name() == "RequestMessage" {
            reqs.push(xml_str);
        } else if child.name() == "ResponseMessage" {
            resps.push(xml_str);
        } else {
            panic!(format!("Unknown XML child {:?}", child.name()));
        }
    }
    assert_eq!(reqs.len(), resps.len());

    for req in reqs {
        let resp = client.make_xml_request(&req);
        eprintln!("{:?}", resp);
    }
}

fn main() {
    println!("Hello, world!");

    env_logger::init();

    let args = CmdLine::from_args();
    println!("{:?}", args);

    //args.log.log_all(Option::Some(args.verbose.log_level()));

    info!("starting up");
    warn!("oops, nothing implemented!");

    // TODO - add client auth

    let mut config = rustls::ClientConfig::new();
    //config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let certfile = fs::File::open(args.ca_cert_file).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    config.root_store.add_pem_file(&mut reader).unwrap();

    // let mut server_certs = load_certs(args.serverCertFile.as_ref());
    // let privkey = load_private_key(args.serverKeyFile.as_ref());

    // let mut ca_certs = load_certs(args.caCertFile.as_ref());

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&args.host).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect((args.host.as_str(), args.port)).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    //let kmip_stream = StreamAdapter::new(&mut tls);
    let mut client = Client::create_from_stream(&mut tls);

    // tls.write(concat!("GET / HTTP/1.1\r\n",
    //                   "Host: google.com\r\n",
    //                   "Connection: close\r\n",
    //                   "Accept-Encoding: identity\r\n",
    //                   "\r\n")
    //           .as_bytes())
    //     .unwrap();

    match args.cmd {
        Command::CreateSymmetricKey { remote_path } => {
            let response = client.create_symmetric_key(CryptographicAlgorithm::AES, 256);

            println!("Response: {:#?} ", response);
        }
        Command::Get { id } => {
            let response = client.get(&id);

            println!("Response: {:#?} ", response);
        }
        Command::RunXml { file } => {
            run_xml(&file, &mut client);
        } // _ => {
          //     unimplemented!();
          // }
    };

    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite
    )
    .unwrap();

    // tls.write(&bytes).unwrap();
    // info!("Waiting for data....");

    // let mut plaintext : Vec<u8> = Vec::new();
    // let msg = read_msg(&mut tls);
    // info!("Response Message: {:?}", msg.hex_dump());

    // to_print(&msg);

    //tls.read_to_end(&mut plaintext).unwrap();

    //stdout().write_all(&plaintext).unwrap();
}
