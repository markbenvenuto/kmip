#[allow(non_snake_case)]
#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate lazy_static;

#[allow(unused_imports)]
extern crate pretty_hex;
extern crate serde_transcode;

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

use chrono::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use rustls;

use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, Session,
};

use mio;
use mio::tcp::{Shutdown, TcpListener, TcpStream};

use std::io;
use std::io::Cursor;
use vecio::Rawv;

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net;
use std::string::ToString;

use strum::AsStaticRef;

#[macro_use(bson, doc)]
extern crate bson;

extern crate ring;
use ring::rand::*;

// use bson;

// mod git;
// mod watchman;
mod messages;
mod store;

use messages::*;
use ttlv::*;

use store::KmipStore;
use store::ManagedObject;
use store::ManagedObjectEnum;
use store::KmipMemoryStore;
use store::KmipMongoDBStore;


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

    serverCertFile: String,

    serverKeyFile: String,

    caCertFile: String,
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

/// This glues our `rustls::WriteV` trait to `vecio::Rawv`.
pub struct WriteVAdapter<'a> {
    rawv: &'a mut dyn Rawv,
}

impl<'a> WriteVAdapter<'a> {
    pub fn new(rawv: &'a mut dyn Rawv) -> WriteVAdapter<'a> {
        WriteVAdapter { rawv }
    }
}

impl<'a> rustls::WriteV for WriteVAdapter<'a> {
    fn writev(&mut self, bytes: &[&[u8]]) -> io::Result<usize> {
        self.rawv.writev(bytes)
    }
}

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    server_context : ServerContext,
}

impl TlsServer {
    fn new(server: TcpListener, server_context: ServerContext, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            server_context : server_context,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                info!("Accepting new connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);

                let token = mio::Token(self.next_id);
                self.next_id += 1;

                self.connections
                    .insert(token, Connection::new(socket, token, self.server_context.clone(), tls_session));
                self.connections[&token].register(poll);
                true
            }
            Err(e) => {
                error!("encountered error while accepting connection; err={:?}", e);
                false
            }
        }
    }

    fn conn_event(&mut self, poll: &mut mio::Poll, event: &mio::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections.get_mut(&token).unwrap().ready(poll, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    tls_session: rustls::ServerSession,
    server_context : ServerContext,
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl Connection {
    fn new(socket: TcpStream, token: mio::Token, server_context: ServerContext, tls_session: rustls::ServerSession) -> Connection {
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            tls_session,
            server_context : server_context,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
        }

        if ev.readiness().is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing && !self.tls_session.wants_write() {
            let _ = self.socket.shutdown(Shutdown::Both);
            self.closed = true;
        } else {
            self.reregister(poll);
        }
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let io::ErrorKind::WouldBlock = err.kind() {
                return;
            }

            error!("read error {:?}", err);
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            debug!("eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            error!("cannot process packet: {:?}", processed);
            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            error!("plaintext read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        if !buf.is_empty() {
            debug!("plaintext read {:?}", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        if buf.len() < 8 {
            error!("Invalid KMIP Request, less then 8 bytes");
            return;
        }

        // Check length
        let mut cur = Cursor::new(buf);
        read_tag(&mut cur);
        let t = read_type(&mut cur);
        if t != ttlv::ItemType::Structure {
            error!("Expected struct, received {:?}", t);
            return;
        }

        let len = read_len(&mut cur) as usize;
        if buf.len() < len  {
            error!("Unexpected leng, received {:?}, expected {:?}", buf.len(), len);
            return;
        }


        let mut rc = RequestContext::new(&self.server_context);

        rc.set_peer_addr(self.socket.peer_addr().unwrap());

        let response = process_kmip_request(&mut rc, buf);

        self.tls_session.write_all(response.as_slice()).unwrap();

        // TODO
        //self.tls_session.send_close_notify();
    }

    #[cfg(target_os = "windows")]
    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_session.write_tls(&mut self.socket)
    }

    #[cfg(not(target_os = "windows"))]
    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_session
            .writev_tls(&mut WriteVAdapter::new(&mut self.socket))
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&self, poll: &mut mio::Poll) {
        poll.register(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
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
    count : i32,
}

#[derive(Clone)]
struct ServerContext {
    inner: Arc<Mutex<ServerContextInner>>,
    store : Arc<dyn KmipStore>,
}

impl ServerContext {
    fn new(store: Arc<dyn KmipStore> ) -> ServerContext {
        ServerContext {
            inner : Arc::new(Mutex::new(ServerContextInner {
                count : 0
            })),
            store : store,
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
        let mut a : Vec<u8> = Vec::new();
        a.resize(len, 0);
        GLOBAL_RAND.fill(a.as_mut());

        return a;
    }
}

struct RequestContext<'a> {
    //store: &'a mut KmipStore,
    peer_addr : Option<SocketAddr>,
    server_context : &'a ServerContext,
}

impl<'a> RequestContext<'a> {
    fn new(server_context : &'a ServerContext ) -> RequestContext<'a> {
        RequestContext {
            peer_addr : None,
            server_context : server_context,
        }
    }

    fn get_server_context(&self) -> &ServerContext {
        return self.server_context;
    }

    fn set_peer_addr(&mut self, addr : SocketAddr) {
        self.peer_addr = Some(addr);
    }

    // fn get_store() -> std::sync::MutexGuard<KmipStore> + 'static {
    //     return GLOBAL_STORE.lock().unwrap();
    // }
}

fn create_error_response(msg: Option<String>) -> Vec<u8> {
    let r = messages::ResponseMessage {
        response_header: messages::ResponseHeader {
            protocol_version: messages::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            time_stamp: Utc::now(),
            batch_count: 1,
        },
        batch_item: messages::ResponseBatchItem {
            //Operation: None,
            result_status: messages::ResultStatus::OperationFailed,
            result_reason: messages::ResultReason::GeneralFailure,
            result_message: msg,
            response_payload: None,
            // ResponseOperation: None,
        },
    };

    return ttlv::to_bytes(&r).unwrap();
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

fn find_attr<F>(tas: &Vec<TemplateAttribute>, func: F) -> Option<i32>
    where F: Fn(&messages::AttributesEnum) -> Option<i32>
{
    for ta in tas {
        for attr in &ta.attribute {
            let r = func(&attr);
            if r.is_some() {
                return r;
            }
        }
    }

    return None;
}

fn process_create_request(
    rc: &RequestContext,
    req: &CreateRequest,
) -> std::result::Result<CreateResponse, KmipResponseError> {
    match req.object_type {
        ObjectTypeEnum::SymmetricKey => {
            // TODO - validate message
            let algo2 = find_attr(&req.template_attribute,
                |x| if let messages::AttributesEnum::CryptographicAlgorithm(a) = x { Some(*a) } else {None}  ).unwrap();

            let algo : CryptographicAlgorithm = num::FromPrimitive::from_i32(algo2).unwrap();

            let crypt_len = find_attr(&req.template_attribute,
                |x| if let messages::AttributesEnum::CryptographicLength(a) = x { Some(*a) } else {None}  ).unwrap();

            // key lengths are in bits
            let key = KmipCrypto::gen_rand_bytes((crypt_len / 8)  as usize);

            let id = rc.get_server_context().get_store().gen_id();
            let mo = store::ManagedObject {
                id: id.to_string(),
                payload: store::ManagedObjectEnum::SymmetricKey(
                    SymmetricKey {
                        key_block : KeyBlock {
                            key_format_type: KeyFormatTypeEnum::Raw,
                            key_value : KeyValue {
                                key_material: key,
                            },
                            key_compression_type: None,
                            cryptographic_algorithm: algo,
                            cryptographic_length: crypt_len,
                        }
                    }
                ),
                attributes: req.template_attribute.iter().map( |x| x.attribute.clone()).flatten().collect(),
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
    let doc_maybe = rc.get_server_context().get_store().get(&req.unique_identifier);
    if doc_maybe.is_none() {
            return Err(KmipResponseError::new("Thing not found"));
    }
    let doc = doc_maybe.unwrap();

    let mo : ManagedObject = bson::from_bson(bson::Bson::Document(doc)).unwrap();

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

fn create_ok_response(op: messages::ResponseOperationEnum) -> Vec<u8> {
    let r = messages::ResponseMessage {
        response_header: messages::ResponseHeader {
            protocol_version: messages::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            time_stamp: Utc::now(),
            batch_count: 1,
        },
        batch_item: messages::ResponseBatchItem {
            result_status: messages::ResultStatus::Success,
            result_reason: messages::ResultReason::GeneralFailure,
            result_message: None,
            response_payload: Some(op),
            // ResponseOperation: None,
        },
    };

    return ttlv::to_bytes(&r).unwrap();
}

// fn process_request(batchitem: &RequestBatchItem) -> {ResponseOperationEnum

// }

fn process_kmip_request(rc : &mut RequestContext, buf: &[u8]) -> Vec<u8> {
    let k: KmipEnumResolver = messages::KmipEnumResolver {};

    info!("Request Message: {:?}", buf.hex_dump());
    ttlv::to_print(buf);

    let request = ttlv::from_bytes::<RequestMessage>(&buf, &k).unwrap();

    // TODO - check protocol version
    info!(
        "Received message: {}.{}",
        request.request_header.protocol_version.protocol_version_major,
        request.request_header.protocol_version.protocol_version_minor
    );

    let result = match request.batch_item {
        RequestBatchItem::Create(x) => {
            info!("Got Create Request");
            process_create_request(&rc, &x).map(|r| ResponseOperationEnum::Create(r))
        }
        RequestBatchItem::Get(x) => {
            info!("Got Get Request");
            process_get_request(&rc, x).map(|r| ResponseOperationEnum::Get(r))
        } // _ => {
          //     unimplemented!();
          // }
    };

    let vr = match result {
        std::result::Result::Ok(t) => create_ok_response(t),
        std::result::Result::Err(e) => {
            let msg = format!("error: {}", e);
            create_error_response(Some(msg))
        }
    };

    info!("Response Message: {:?}", vr.hex_dump());

    ttlv::to_print(vr.as_slice());

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
    let mut poll = mio::Poll::new().unwrap();
    poll.register(
        &listener,
        LISTENER,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )
    .unwrap();

    let mut server_config = rustls::ServerConfig::new(NoClientAuth::new());

    let mut server_certs = load_certs(args.serverCertFile.as_ref());
    let privkey = load_private_key(args.serverKeyFile.as_ref());

    let mut ca_certs = load_certs(args.caCertFile.as_ref());

    server_certs.append(&mut ca_certs);

    server_config.set_single_cert(server_certs, privkey);


    let uri ="mongodb://localhost:27017/";

//    let store  = Arc::new(KmipMemoryStore::new());
    let store  = Arc::new(KmipMongoDBStore::new(uri));

    let server_context = ServerContext::new(store);

    let mut tlsserv = TlsServer::new(listener, server_context, Arc::new(server_config));

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    if !tlsserv.accept(&mut poll) {
                        break;
                    }
                }
                _ => tlsserv.conn_event(&mut poll, &event),
            }
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

    ttlv::to_print(bytes.as_slice());

    let k: KmipEnumResolver = KmipEnumResolver {};

    let a = ttlv::from_bytes::<RequestMessage>(&bytes, &k).unwrap();
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

    let store  = Arc::new(KmipMemoryStore::new());

    let server_context = ServerContext::new(store);

    let mut rc = RequestContext::new(&server_context);
    process_kmip_request(&mut rc, bytes.as_slice());

    //unimplemented!();
}
