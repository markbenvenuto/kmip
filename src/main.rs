#[allow(non_snake_case)]
#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate lazy_static;

#[allow(unused_imports)]
extern crate pretty_hex;
//extern crate serde_transcode;

#[macro_use]
extern crate log;
extern crate env_logger;
use log::{info, warn};

#[macro_use]
extern crate serde_derive;

//#[macro_use]
extern crate serde_enum;

use std::path::Path;

#[macro_use]
extern crate structopt;
extern crate clap_log_flag;
extern crate clap_verbosity_flag;
use structopt::StructOpt;

extern crate strum;
#[macro_use]
extern crate strum_macros;

use pretty_hex::*;

extern crate confy;

extern crate chrono;

use chrono::DateTime;
use chrono::Utc;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use rustls;

use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, Session,
};

use std::io;
use std::io::Cursor;
use vecio::Rawv;

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::string::ToString;
use std::thread;

#[macro_use(bson, doc)]
extern crate bson;

extern crate ring;
use ring::rand::*;

// use bson;

// mod git;
// mod watchman;
mod store;

use protocol::*;

use store::KmipMemoryStore;
use store::KmipMongoDBStore;
use store::KmipStore;
use store::ManagedAttributes;
use store::ManagedObject;
use store::ManagedObjectEnum;

#[derive(Debug, EnumString)]
enum StoreType {
    Memory,
    MongoDB,
}

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
    #[structopt(name = "port", long = "port", default_value = "7000")]
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

/// Process some amount of received plaintext.
fn handle_client<T>(stream: &mut T, server_context: &ServerContext)
where
    T: Read + Write,
{
    let buf = read_msg(stream).unwrap();

    let mut rc = RequestContext::new(server_context);

    //rc.set_peer_addr(self.socket.peer_addr().unwrap());

    let response = process_kmip_request(&mut rc, buf.as_slice());

    stream.write_all(response.as_slice()).unwrap();
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

struct ServerContextInner {
    count: i32,
}

#[derive(Clone)]
struct ServerContext {
    inner: Arc<Mutex<ServerContextInner>>,
    store: Arc<dyn KmipStore + Send + Sync>,
}

impl ServerContext {
    fn new(store: Arc<dyn KmipStore + Send + Sync>) -> ServerContext {
        ServerContext {
            inner: Arc::new(Mutex::new(ServerContextInner { count: 0 })),
            store: store,
        }
    }

    fn get_store(&self) -> &dyn KmipStore {
        return self.store.as_ref();
    }
}

///////////////////////

lazy_static! {
    static ref GLOBAL_RAND: SystemRandom = SystemRandom::new();
}

struct KmipCrypto;

impl KmipCrypto {
    // TODO - is there a secure vector?
    fn gen_rand_bytes(len: usize) -> Vec<u8> {
        let mut a: Vec<u8> = Vec::new();
        a.resize(len, 0);
        GLOBAL_RAND.fill(a.as_mut());

        return a;
    }
}

struct RequestContext<'a> {
    //store: &'a mut KmipStore,
    peer_addr: Option<SocketAddr>,
    server_context: &'a ServerContext,
}

impl<'a> RequestContext<'a> {
    fn new(server_context: &'a ServerContext) -> RequestContext<'a> {
        RequestContext {
            peer_addr: None,
            server_context: server_context,
        }
    }

    fn get_server_context(&self) -> &ServerContext {
        return self.server_context;
    }

    fn set_peer_addr(&mut self, addr: SocketAddr) {
        self.peer_addr = Some(addr);
    }

    // fn get_store() -> std::sync::MutexGuard<KmipStore> + 'static {
    //     return GLOBAL_STORE.lock().unwrap();
    // }
}

fn create_error_response(msg: Option<String>) -> Vec<u8> {
    let r = protocol::ResponseMessage {
        response_header: protocol::ResponseHeader {
            protocol_version: protocol::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            time_stamp: Utc::now(),
            batch_count: 1,
        },
        batch_item: protocol::ResponseBatchItem {
            //Operation: None,
            result_status: protocol::ResultStatus::OperationFailed,
            result_reason: Some(protocol::ResultReason::GeneralFailure),
            result_message: msg,
            response_payload: None,
            // ResponseOperation: None,
        },
    };

    return protocol::to_bytes(&r).unwrap();
}

use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct KmipResponseError {
    msg: String,
}

impl KmipResponseError {
    fn new(msg: &str) -> KmipResponseError {
        KmipResponseError {
            msg: msg.to_owned(),
        }
    }
}

impl fmt::Display for KmipResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KMIP Response error: {}", self.msg)
    }
}

impl Error for KmipResponseError {
    fn description(&self) -> &str {
        "KMIP Response error"
    }
}

// fn find_one<T,S>(vec : Vec<T>) -> Option<S> {
//     for x in vec {
//         if let S(a) = x {
//             return  a
//         }
//     }

//     return None;
// }

// fn find_attr<F>(tas: &Vec<TemplateAttribute>, func: F) -> Option<i32>
// where
//     F: Fn(&protocol::AttributesEnum) -> Option<i32>,
// {
//     for ta in tas {
//         for attr in &ta.attribute {
//             let r = func(&attr);
//             if r.is_some() {
//                 return r;
//             }
//         }
//     }

//     return None;
// }

fn merge_to_managed_attributes(ma: &mut ManagedAttributes, tas: &Vec<TemplateAttribute>) {
    for ta in tas {
        for attr in &ta.attribute {
            match attr {
                protocol::AttributesEnum::CryptographicAlgorithm(a) => {
                    // TODO - validate
                    ma.cryptographic_algorithm = Some(*a);
                }
                protocol::AttributesEnum::CryptographicLength(a) => {
                    // TODO - validate
                    ma.cryptographic_length = Some(*a);
                    //                    ma.cryptographic_algorithm = Some(num::FromPrimitive::from_i32(*a).unwrap());
                }
                protocol::AttributesEnum::CryptographicUsageMask(a) => {
                    // TODO - validate
                    ma.cryptographic_usage_mask = Some(*a);
                }
                protocol::AttributesEnum::ActivationDate(a) => {
                    // TODO - validate
                    ma.activation_date = Some(*a);
                }
            }
        }
    }
}

fn process_create_request(
    rc: &RequestContext,
    req: &CreateRequest,
) -> std::result::Result<CreateResponse, KmipResponseError> {
    let mut ma = ManagedAttributes {
        state: ObjectStateEnum::PreActive,
        initial_date: Utc::now(),

        activation_date: None,

        cryptographic_algorithm: None,

        cryptographic_length: None,

        cryptographic_usage_mask: None,
    };

    match req.object_type {
        ObjectTypeEnum::SymmetricKey => {
            // TODO - validate message
            merge_to_managed_attributes(&mut ma, &req.template_attribute);

            let crypt_len = ma.cryptographic_length.unwrap();
            let algo = num::FromPrimitive::from_i32(ma.cryptographic_algorithm.unwrap()).unwrap();
            //                    ma.cryptographic_algorithm = Some(num::FromPrimitive::from_i32(*a).unwrap());

            // TODO - process activation date if set

            // key lengths are in bits
            let key = KmipCrypto::gen_rand_bytes((crypt_len / 8) as usize);

            let id = rc.get_server_context().get_store().gen_id();
            let mo = store::ManagedObject {
                id: id.to_string(),
                payload: store::ManagedObjectEnum::SymmetricKey(SymmetricKey {
                    key_block: KeyBlock {
                        key_format_type: KeyFormatTypeEnum::Raw,
                        key_value: KeyValue { key_material: key },
                        key_compression_type: None,
                        cryptographic_algorithm: algo,
                        cryptographic_length: crypt_len,
                    },
                }),
                attributes: ma,
            };

            let d = bson::to_bson(&mo).unwrap();

            if let bson::Bson::Document(d1) = d {
                rc.get_server_context().get_store().add(id.as_ref(), d1);

                return Ok(CreateResponse {
                    object_type: ObjectTypeEnum::SymmetricKey,
                    unique_identifier: id,
                });
            } else {
                return Err(KmipResponseError::new("Barff"));
            }
        }
        _ => Err(KmipResponseError::new("Foo")),
    }
}

fn process_get_request(
    rc: &RequestContext,
    req: GetRequest,
) -> std::result::Result<GetResponse, KmipResponseError> {
    let doc_maybe = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier);
    if doc_maybe.is_none() {
        return Err(KmipResponseError::new("Thing not found"));
    }
    let doc = doc_maybe.unwrap();

    let mo: ManagedObject = bson::from_bson(bson::Bson::Document(doc)).unwrap();

    let mut resp = GetResponse {
        object_type: ObjectTypeEnum::SymmetricKey,
        unique_identifier: req.unique_identifier,
        symmetric_key: None,
    };

    match mo.payload {
        ManagedObjectEnum::SymmetricKey(x) => {
            resp.symmetric_key = Some(x);
        }
    }

    Ok(resp)
}

fn process_activate_request(
    rc: &RequestContext,
    req: ActivateRequest,
) -> std::result::Result<ActivateResponse, KmipResponseError> {
    let doc_maybe = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier);
    if doc_maybe.is_none() {
        return Err(KmipResponseError::new("Thing not found"));
    }
    let doc = doc_maybe.unwrap();

    let mut mo: ManagedObject = bson::from_bson(bson::Bson::Document(doc)).unwrap();

    // TODO - throw an error on illegal state transition??
    if mo.attributes.state == ObjectStateEnum::PreActive {
        mo.attributes.state = ObjectStateEnum::Active;

        let d = bson::to_bson(&mo).unwrap();

        if let bson::Bson::Document(d1) = d {
            rc.get_server_context()
                .get_store()
                .update(&req.unique_identifier, d1);
        } else {
            return Err(KmipResponseError::new("Barff"));
        }
    }

    let resp = ActivateResponse {
        unique_identifier: req.unique_identifier,
    };

    Ok(resp)
}

fn create_ok_response(op: protocol::ResponseOperationEnum) -> Vec<u8> {
    let r = protocol::ResponseMessage {
        response_header: protocol::ResponseHeader {
            protocol_version: protocol::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            time_stamp: Utc::now(),
            batch_count: 1,
        },
        batch_item: protocol::ResponseBatchItem {
            result_status: protocol::ResultStatus::Success,
            result_reason: Some(protocol::ResultReason::GeneralFailure),
            result_message: None,
            response_payload: Some(op),
            // ResponseOperation: None,
        },
    };

    return protocol::to_bytes(&r).unwrap();
}

// fn process_request(batchitem: &RequestBatchItem) -> {ResponseOperationEnum

// }

fn process_kmip_request(rc: &mut RequestContext, buf: &[u8]) -> Vec<u8> {
    let k: KmipEnumResolver = protocol::KmipEnumResolver {};

    info!("Request Message: {:?}", buf.hex_dump());
    protocol::to_print(buf);

    let request = protocol::from_bytes::<RequestMessage>(&buf, &k).unwrap();

    // TODO - check protocol version
    info!(
        "Received message: {}.{}",
        request
            .request_header
            .protocol_version
            .protocol_version_major,
        request
            .request_header
            .protocol_version
            .protocol_version_minor
    );

    let result = match request.batch_item {
        RequestBatchItem::Create(x) => {
            info!("Got Create Request");
            process_create_request(&rc, &x).map(|r| ResponseOperationEnum::Create(r))
        }
        RequestBatchItem::Get(x) => {
            info!("Got Get Request");
            process_get_request(&rc, x).map(|r| ResponseOperationEnum::Get(r))
        }
        RequestBatchItem::Activate(x) => {
            info!("Got Activate Request");
            process_activate_request(&rc, x).map(|r| ResponseOperationEnum::Activate(r))
        }
    };

    let vr = match result {
        std::result::Result::Ok(t) => create_ok_response(t),
        std::result::Result::Err(e) => {
            let msg = format!("error: {}", e);
            create_error_response(Some(msg))
        }
    };

    info!("Response Message: {:?}", vr.hex_dump());

    protocol::to_print(vr.as_slice());

    return vr;
}

fn main() {
    println!("Hello, world!");

    env_logger::init();

    let args = CmdLine::from_args();
    println!("{:?}", args);

    args.log.log_all(Option::Some(args.verbose.log_level()));

    info!("starting up");
    warn!("oops, nothing implemented!");

    // let cfg = confy::load::<MyConfig>("qrb").unwrap();

    // println!("cfg {:?}", cfg);

    // confy::store("qrb", cfg).expect("foooooo3124123");

    let addr: net::SocketAddr = "0.0.0.0:7000".parse().unwrap();
    //TODO addr.set_port(args.flag_port.unwrap_or(7000));

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

    let server_context = Arc::new(ServerContext::new(store));
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

#[test]
fn test_create_request() {
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

    protocol::to_print(bytes.as_slice());

    let k: KmipEnumResolver = KmipEnumResolver {};

    let a = protocol::from_bytes::<RequestMessage>(&bytes, &k).unwrap();
}

#[test]
fn test_create_request2() {
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

    let store = Arc::new(KmipMemoryStore::new());

    let server_context = ServerContext::new(store);

    let mut rc = RequestContext::new(&server_context);
    process_kmip_request(&mut rc, bytes.as_slice());

    //unimplemented!();
}

#[test]
fn test_create_request3() {
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

    let store = Arc::new(KmipMemoryStore::new());

    let server_context = ServerContext::new(store);

    let mut rc = RequestContext::new(&server_context);
    process_kmip_request(&mut rc, bytes.as_slice());

    let get_bytes = vec![
        0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x70, 0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00,
        0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0d, 0x02,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f,
        0x01, 0x00, 0x00, 0x00, 0x28, 0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x10, 0x42,
        0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x01, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    process_kmip_request(&mut rc, get_bytes.as_slice());

    //unimplemented!();
}
