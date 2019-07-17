#[macro_use]
extern crate num_derive;

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
use serde_enum::{Deserialize_enum, Serialize_enum};

use std::io::prelude::*;
use std::path::Path;
// use std::io::Cursor;

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

use std::sync::Arc;

use rustls;

use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, Session,
};

use mio;
use mio::tcp::{Shutdown, TcpListener, TcpStream};

use std::io;
use vecio::Rawv;

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net;
use std::string::ToString;

use strum::AsStaticRef;

use serde::ser::{Serialize, SerializeStruct, Serializer};

// mod git;
// mod watchman;

use ttlv::*;

#[derive(FromPrimitive, Serialize_enum, Deserialize_enum, Debug, AsStaticStr)]
#[repr(i32)]
pub enum Operation {
    Create = 0x00000001,
    CreateKeyPair = 0x00000002,
    Register = 0x00000003,
    ReKey = 0x00000004,
    DeriveKey = 0x00000005,
    Certify = 0x00000006,
    ReCertify = 0x00000007,
    Locate = 0x00000008,
    Check = 0x00000009,
    Get = 0x0000000A,
    GetAttributes = 0x0000000B,
    GetAttributeList = 0x0000000C,
    AddAttribute = 0x0000000D,
    ModifyAttribute = 0x0000000E,
    DeleteAttribute = 0x0000000F,
    ObtainLease = 0x00000010,
    GetUsageAllocation = 0x00000011,
    Activate = 0x00000012,
    Revoke = 0x00000013,
    Destroy = 0x00000014,
    Archive = 0x00000015,
    Recover = 0x00000016,
    Validate = 0x00000017,
    Query = 0x00000018,
    Cancel = 0x00000019,
    Poll = 0x0000001A,
    Notify = 0x0000001B,
    Put = 0x0000001C,
    ReKeyKeyPair = 0x0000001D,
    DiscoverVersions = 0x0000001E,
    Encrypt = 0x0000001F,
    Decrypt = 0x00000020,
    Sign = 0x00000021,
    SignatureVerify = 0x00000022,
    MAC = 0x00000023,
    MACVerify = 0x00000024,
    RNGRetrieve = 0x00000025,
    RNGSeed = 0x00000026,
    Hash = 0x00000027,
    CreateSplitKey = 0x00000028,
    JoinSplitKey = 0x00000029,
    Import = 0x0000002A,
    Export = 0x0000002B,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
enum ObjectTypeEnum {
    Certificate = 0x00000001,
    SymmetricKey = 0x00000002,
    PublicKey = 0x00000003,
    PrivateKey = 0x00000004,
    SplitKey = 0x00000005,
    Template = 0x00000006, //(deprecated)
    SecretData = 0x00000007,
    OpaqueObject = 0x00000008,
    PGPKey = 0x00000009,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
enum NameTypeEnum {
    UninterpretedTextString = 0x00000001,
    URI = 0x00000002,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
enum CryptographicAlgorithm {
    DES = 0x00000001,
    TripleDES = 0x00000002,
    AES = 0x00000003,
    RSA = 0x00000004,
    DSA = 0x00000005,
    ECDSA = 0x00000006,
    HMACSHA1 = 0x00000007,
    HMACSHA224 = 0x00000008,
    HMACSHA256 = 0x00000009,
    HMACSHA384 = 0x0000000A,
    HMACSHA512 = 0x0000000B,
    HMACMD5 = 0x0000000C,
    DH = 0x0000000D,
    ECDH = 0x0000000E,
    ECMQV = 0x0000000F,
    Blowfish = 0x00000010,
    Camellia = 0x00000011,
    CAST5 = 0x00000012,
    IDEA = 0x00000013,
    MARS = 0x00000014,
    RC2 = 0x00000015,
    RC4 = 0x00000016,
    RC5 = 0x00000017,
    SKIPJACK = 0x00000018,
    Twofish = 0x00000019,
    EC = 0x0000001A,
    OneTimePad = 0x0000001B,
    ChaCha20 = 0x0000001C,
    Poly1305 = 0x0000001D,
    ChaCha20Poly1305 = 0x0000001E,
    SHA3224 = 0x0000001F,
    SHA3256 = 0x00000020,
    SHA3384 = 0x00000021,
    SHA3512 = 0x00000022,
    HMACSHA3224 = 0x00000023,
    HMACSHA3256 = 0x00000024,
    HMACSHA3384 = 0x00000025,
    HMACSHA3512 = 0x00000026,
    SHAKE128 = 0x00000027,
    SHAKE256 = 0x00000028,
}

#[derive(Debug, Serialize, Deserialize)]
enum CryptographicUsageMask {
    Sign = 0x00000001,
    Verify = 0x00000002,
    Encrypt = 0x00000004,
    Decrypt = 0x00000008,
    WrapKey = 0x00000010,
    UnwrapKey = 0x00000020,
    Export = 0x00000040,
    MACGenerate = 0x00000080,
    MACVerify = 0x00000100,
    DeriveKey = 0x00000200,
    ContentCommitment = 0x00000400, // (NonRepudiation)
    KeyAgreement = 0x00000800,
    CertificateSign = 0x00001000,
    CRLSign = 0x00002000,
    GenerateCryptogram = 0x00004000,
    ValidateCryptogram = 0x00008000,
    TranslateEncrypt = 0x00010000,
    TranslateDecrypt = 0x00020000,
    TranslateWrap = 0x00040000,
    TranslateUnwrap = 0x00080000,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
enum KeyFormatTypeEnum {
    Raw = 0x00000001,
    Opaque = 0x00000002,
    PKCS1 = 0x00000003,
    PKCS8 = 0x00000004,
    X509 = 0x00000005,
    ECPrivateKey = 0x00000006,
    TransparentSymmetricKey = 0x00000007,
    TransparentDSAPrivateKey = 0x00000008,
    TransparentDSAPublicKey = 0x00000009,
    TransparentRSAPrivateKey = 0x0000000A,
    TransparentRSAPublicKey = 0x0000000B,
    TransparentDHPrivateKey = 0x0000000C,
    TransparentDHPublicKey = 0x0000000D,
    TransparentECDSAPrivateKey = 0x0000000E, //(deprecated),
    TransparentECDSAPublicKey = 0x0000000F,  //(deprecated),
    TransparentECDHPrivateKey = 0x00000010,  //(deprecated),
    TransparentECDHPublicKey = 0x00000011,   //(deprecated),
    TransparentECMQVPrivateKey = 0x00000012, //(deprecated),
    TransparentECMQVPublicKey = 0x00000013,  //(deprecated),
    TransparentECPrivateKey = 0x00000014,
    TransparentECPublicKey = 0x00000015,
    PKCS12 = 0x00000016,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x00000001,
    ECPublicKeyTypeX962CompressedPrime = 0x00000002,
    ECPublicKeyTypeX962CompressedChar2 = 0x00000003,
    ECPublicKeyTypeX962Hybrid = 0x00000004,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
enum ResultStatus {
    Success = 0x00000000,
    OperationFailed = 0x00000001,
    OperationPending = 0x00000002,
    OperationUndone = 0x00000003,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
enum ResultReason {
    ItemNotFound = 0x00000001,
    ResponseTooLarge = 0x00000002,
    AuthenticationNotSuccessful = 0x00000003,
    InvalidMessage = 0x00000004,
    OperationNotSupported = 0x00000005,
    MissingData = 0x00000006,
    InvalidField = 0x00000007,
    FeatureNotSupported = 0x00000008,
    OperationCanceledByRequester = 0x00000009,
    CryptographicFailure = 0x0000000A,
    IllegalOperation = 0x0000000B,
    PermissionDenied = 0x0000000C,
    Objectarchived = 0x0000000D,
    IndexOutofBounds = 0x0000000E,
    ApplicationNamespaceNotSupported = 0x0000000F,
    KeyFormatTypeNotSupported = 0x00000010,
    KeyCompressionTypeNotSupported = 0x00000011,
    EncodingOptionError = 0x00000012,
    KeyValueNotPresent = 0x00000013,
    AttestationRequired = 0x00000014,
    AttestationFailed = 0x00000015,
    Sensitive = 0x00000016,
    NotExtractable = 0x00000017,
    ObjectAlreadyExists = 0x00000018,
    GeneralFailure = 0x00000100,
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
}

impl TlsServer {
    fn new(server: TcpListener, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                debug!("Accepting new connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);

                let token = mio::Token(self.next_id);
                self.next_id += 1;

                self.connections
                    .insert(token, Connection::new(socket, token, tls_session));
                self.connections[&token].register(poll);
                true
            }
            Err(e) => {
                println!("encountered error while accepting connection; err={:?}", e);
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
    sent_http_response: bool,
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
    fn new(socket: TcpStream, token: mio::Token, tls_session: rustls::ServerSession) -> Connection {
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            tls_session,
            sent_http_response: false,
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
        let response = process_kmip_request(buf);

        self.tls_session.write_all(response.as_slice()).unwrap();
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

#[derive(Serialize, Deserialize, Debug)]
struct KeyBlock {
    KeyFormatType: KeyFormatTypeEnum,
    KeyCompressionType: Option<KeyCompressionType>,

    // TODO : this type is not just bytes all the time
    KeyValue: Vec<u8>,

    // TODO - omitted in some cases
    CryptographicAlgorithm: CryptographicAlgorithm,
    CryptographicLengh: i32,
    // TODO
    // KeyWrappingData  : KeyWrappingData
}

#[derive(Serialize, Deserialize, Debug)]
struct SymmetricKey {
    KeyBlock: KeyBlock,
}

#[derive(Serialize, Deserialize, Debug)]
struct AttributeStruct {
    AttributeName: String,
    AttributeIndex: Option<i32>,
    // AttributeValue type varies based on type
    //AttributeValue: ???
}

#[derive(Serialize, Deserialize, Debug)]
struct NameStruct {
    NameValue: String,
    NameType: NameTypeEnum,
}

// #[derive(Serialize, Deserialize, Debug)]
// struct TemplateAttribute {
//     Name : NameStruct,
//     Attribute : AttributeStruct,
// }

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "AttributeName", content = "AttributeValue")]
enum CreateRequestAttributes {
    #[serde(rename = "Cryptographic Algorithm")]
    // TODO - use CryptographicAlgorithm as the type but serde calls deserialize_identifier
    // and we do not have enough context to realize it is CryptographicAlgorithm, we think it is AttributeValue
    CryptographicAlgorithm(i32),

    #[serde(rename = "Cryptographic Length")]
    CryptographicLength(i32),

    #[serde(rename = "Cryptographic Usage Mask")]
    CryptographicUsageMask(i32),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct TemplateAttribute {
    Name: Option<NameStruct>,
    #[serde(rename = "Attribute")]
    Attribute: Vec<CreateRequestAttributes>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    ObjectType: ObjectTypeEnum,
    TemplateAttribute: Vec<TemplateAttribute>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
struct CreateResponse {
    ObjectType: ObjectTypeEnum,
    UniqueIdentifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct GetRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    UniqueIdentifier: String,
    KeyFormatType: Option<KeyFormatTypeEnum>,
    KeyWrapType: Option<KeyFormatTypeEnum>,
    KeyCompressionType: Option<KeyCompressionType>,
    // TODO KeyWrappingSpecification: KeyWrappingSpecification
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "Operation", content = "RequestPayload")]
enum RequestBatchItem {
    Create(CreateRequest),
    Get(GetRequest),
    // TODO - add support for: Unique Batch Item ID, will require custom deserializer, serializer
}

#[derive(Deserialize, Serialize, Debug)]
struct ProtocolVersion {
    ProtocolVersionMajor: i32,
    ProtocolVersionMinor: i32,
}

#[derive(Deserialize, Serialize, Debug)]
struct RequestHeader {
    ProtocolVersion: ProtocolVersion,
    // TODO: Other fields are optional
    BatchCount: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct RequestMessage {
    RequestHeader: RequestHeader,
    BatchItem: RequestBatchItem,
}

#[derive(Deserialize, Serialize, Debug)]
struct ResponseHeader {
    ProtocolVersion: ProtocolVersion,
    #[serde(with = "ttlv::my_date_format")]
    TimeStamp: chrono::DateTime<Utc>,
    // TODO: Other fields are optional
    BatchCount: i32,
}

#[derive(Serialize, Deserialize, Debug)]
//#[serde(tag = "Operation", content = "RequestPayload")]
enum ResponseOperationEnum {
    Create(CreateResponse),
    Empty,
    // TODO - add support for: Unique Batch Item ID
}

// TODO - remove Deserialize
#[derive(Deserialize, Debug)]
#[serde(rename = "BatchItem")]
struct ResponseBatchItem {
    //Operation: Option<String>,
    ResultStatus: ResultStatus,
    ResultReason: ResultReason,
    ResultMessage: Option<String>,
    ResponsePayload: Option<ResponseOperationEnum>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ResponseMessage {
    ResponseHeader: ResponseHeader,
    #[serde(rename = "BatchItem")]
    BatchItem: ResponseBatchItem,
}

impl Serialize for ResponseBatchItem {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut field_count = 1;
        let mut serialize_reason = false;
        let mut serialize_operation = false;
        let mut serialize_message = false;

        if self.ResultStatus == ResultStatus::OperationFailed {
            field_count += 1;
            serialize_reason = true;

            if self.ResultMessage.is_some() {
                field_count += 1;
                serialize_message = true;
            }
        }

        //         if self.Operation.is_some() {
        //             field_count += 2;
        //             serialize_operation = true;
        // //            assert_eq!(self.Operation.is_some(), self.ResponsePayload.is_some() );
        //         }

        if self.ResponsePayload.is_some() {
            field_count += 2;
            serialize_operation = true;
        }

        let mut ser_struct = serializer.serialize_struct("BatchItem", field_count)?;

        // if serialize_operation {
        //     let op = self.Operation.as_ref();
        //     ser_struct.serialize_field("Operation", &op)?;
        // }

        if serialize_operation {
            // TODO - use a macro to derive this stuff
            match self.ResponsePayload.as_ref().unwrap() {
                ResponseOperationEnum::Create(_) => {
                    ser_struct.serialize_field("Operation", &Operation::Create)?;
                }
                ResponseOperationEnum::Empty => unimplemented!(),
            }
        }

        ser_struct.serialize_field("ResultStatus", &self.ResultStatus)?;

        if serialize_reason {
            ser_struct.serialize_field("ResultReason", &self.ResultReason)?;
        }

        if serialize_message {
            ser_struct.serialize_field("ResultMessage", &self.ResultMessage)?;
        }

        if serialize_operation {
            // TODO - use a macro to derive this stuff
            //ser_struct.serialize_field("ResultPayload", &self.ResponsePayload.as_ref())?;
            match self.ResponsePayload.as_ref().unwrap() {
                ResponseOperationEnum::Create(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Empty => unimplemented!(),
            }
        }

        ser_struct.end()
    }
}

/////////////////////////////////

fn create_error_response(msg: Option<String>) -> Vec<u8> {
    let r = ResponseMessage {
        ResponseHeader: ResponseHeader {
            ProtocolVersion: ProtocolVersion {
                ProtocolVersionMajor: 1,
                ProtocolVersionMinor: 0,
            },
            TimeStamp: Utc::now(),
            BatchCount: 1,
        },
        BatchItem: ResponseBatchItem {
            //Operation: None,
            ResultStatus: ResultStatus::OperationFailed,
            ResultReason: ResultReason::GeneralFailure,
            ResultMessage: msg,
            ResponsePayload: None,
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

fn process_create_request(
    req: CreateRequest,
) -> std::result::Result<CreateResponse, KmipResponseError> {
    match req.ObjectType {
        ObjectTypeEnum::SymmetricKey => Ok(CreateResponse {
            ObjectType: ObjectTypeEnum::SymmetricKey,
            UniqueIdentifier: "Fpp".to_owned(),
        }),
        _ => Err(KmipResponseError::new("Foo")),
    }
}

fn create_ok_response(op: ResponseOperationEnum) -> Vec<u8> {
    let r = ResponseMessage {
        ResponseHeader: ResponseHeader {
            ProtocolVersion: ProtocolVersion {
                ProtocolVersionMajor: 1,
                ProtocolVersionMinor: 0,
            },
            TimeStamp: Utc::now(),
            BatchCount: 1,
        },
        BatchItem: ResponseBatchItem {
            ResultStatus: ResultStatus::Success,
            ResultReason: ResultReason::GeneralFailure,
            ResultMessage: None,
            ResponsePayload: Some(op),
            // ResponseOperation: None,
        },
    };

    return ttlv::to_bytes(&r).unwrap();
}

// fn process_request(batchitem: &RequestBatchItem) -> {ResponseOperationEnum

// }

fn process_kmip_request(buf: &[u8]) -> Vec<u8> {
    let k: KmipEnumResolver = KmipEnumResolver {};

    println!("Request Message: {:?}", buf.hex_dump());
    ttlv::to_print(buf);

    let request = ttlv::from_bytes::<RequestMessage>(&buf, &k).unwrap();

    // TODO - check protocol version
    println!(
        "Received message: {}.{}",
        request.RequestHeader.ProtocolVersion.ProtocolVersionMajor,
        request.RequestHeader.ProtocolVersion.ProtocolVersionMinor
    );

    let result = match request.BatchItem {
        RequestBatchItem::Create(x) => {
            println!("Got Create Request");
            process_create_request(x).map(|r| ResponseOperationEnum::Create(r))
        }
        _ => {
            unimplemented!();
        }
    };

    let vr = match result {
        std::result::Result::Ok(t) => create_ok_response(t),
        std::result::Result::Err(e) => {
            let msg = format!("error: {}", e);
            create_error_response(Some(msg))
        }
    };

    println!("Response Message: {:?}", vr.hex_dump());

    ttlv::to_print(vr.as_slice());

    return vr;
}

struct KmipEnumResolver;

impl ttlv::EnumResolver for KmipEnumResolver {
    fn resolve_enum(&self, name: &str, value: i32) -> String {
        match name {
            "Foo" => "Bar".to_owned(),
            "Operation" => {
                let o: Operation = num::FromPrimitive::from_i32(value).unwrap();
                return o.as_static().to_owned();
            }
            "ObjectType" => {
                let o: ObjectTypeEnum = num::FromPrimitive::from_i32(value).unwrap();
                return o.as_static().to_owned();
            }
            "CryptographicAlgorithm" => {
                let o: CryptographicAlgorithm = num::FromPrimitive::from_i32(value).unwrap();
                return o.as_static().to_owned();
            }
            _ => {
                println!("Not implemented: {:?}", name);
                unimplemented! {}
            }
        }
    }
}

fn main() {
    println!("Hello, world!");

    //    env_logger::init();

    let args = CmdLine::from_args();
    println!("{:?}", args);

    args.log.log_all(Option::Some(args.verbose.log_level()));

    info!("starting up");
    warn!("oops, nothing implemented!");

    // let cfg = confy::load::<MyConfig>("qrb").unwrap();

    // println!("cfg {:?}", cfg);

    // confy::store("qrb", cfg).expect("foooooo3124123");

    let mut addr: net::SocketAddr = "0.0.0.0:7000".parse().unwrap();
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

    let mut tlsserv = TlsServer::new(listener, Arc::new(server_config));

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

    process_kmip_request(bytes.as_slice());

    //unimplemented!();
}
