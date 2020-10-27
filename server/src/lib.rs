extern crate num_derive;

#[macro_use]
extern crate lazy_static;

#[allow(unused_imports)]
extern crate pretty_hex;
//extern crate serde_transcode;

extern crate log;
extern crate env_logger;
use log::{info};

#[macro_use]
extern crate serde_derive;

extern crate serde_enum;

use std::{io::Read, rc::Rc, io::Write};

extern crate structopt;
extern crate clap_log_flag;
extern crate clap_verbosity_flag;

extern crate strum;
extern crate strum_macros;

use pretty_hex::*;

extern crate confy;

extern crate chrono;

use chrono::Utc;
use chrono::{NaiveDateTime};

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use std::string::ToString;

#[macro_use(doc)]
extern crate bson;

extern crate ring;
use ring::rand::*;

pub mod store;

use protocol::*;

use store::KmipStore;
use store::ManagedAttributes;
use store::ManagedObject;
use store::ManagedObjectEnum;

/// Process some amount of received plaintext.
pub fn handle_client<T>(stream: &mut T, server_context: &ServerContext)
where
    T: Read + Write,
{
    let buf = read_msg(stream).unwrap();

    let mut rc = RequestContext::new(server_context);

    //rc.set_peer_addr(self.socket.peer_addr().unwrap());

    let response = process_kmip_request(&mut rc, buf.as_slice());

    stream.write_all(response.as_slice()).unwrap();
}

pub trait ClockSource {
    fn now(&self) -> chrono::DateTime<Utc>;
}

pub struct TestClockSource {}

impl TestClockSource {
    pub fn new() -> TestClockSource {
        TestClockSource {}
    }
}

impl ClockSource for TestClockSource {
    fn now(&self) -> chrono::DateTime<Utc> {
        chrono::DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(123, 0), Utc)
    }
}

struct ServerContextInner {
    count: i32,
}

#[derive(Clone)]
pub struct ServerContext {
    inner: Arc<Mutex<ServerContextInner>>,
    store: Arc<dyn KmipStore + Send + Sync>,
    clock_source: Arc<dyn ClockSource + Send + Sync>,
}

impl ServerContext {
    pub fn new(
        store: Arc<dyn KmipStore + Send + Sync>,
        clock_source: Arc<dyn ClockSource + Send + Sync>,
    ) -> ServerContext {
        ServerContext {
            inner: Arc::new(Mutex::new(ServerContextInner { count: 0 })),
            store: store,
            clock_source: clock_source,
        }
    }

    fn get_store(&self) -> &dyn KmipStore {
        return self.store.as_ref();
    }

    fn get_clock_source(&self) -> &dyn ClockSource {
        self.clock_source.as_ref()
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
        GLOBAL_RAND.fill(a.as_mut()).expect("Random number generator failed");

        return a;
    }
}

pub struct RequestContext<'a> {
    //store: &'a mut KmipStore,
    peer_addr: Option<SocketAddr>,
    server_context: &'a ServerContext,
}

impl<'a> RequestContext<'a> {
    pub fn new(server_context: &'a ServerContext) -> RequestContext<'a> {
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

fn create_error_response(
    msg: Option<String>,
    clock_source: &dyn ClockSource,
) -> protocol::ResponseMessage {
    let r = protocol::ResponseMessage {
        response_header: protocol::ResponseHeader {
            protocol_version: protocol::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            time_stamp: clock_source.now(),
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

    return r;
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
        initial_date: rc.get_server_context().get_clock_source().now(),

        activation_date: None,
        destroy_date: None,

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
                        cryptographic_algorithm: Some(algo),
                        cryptographic_length: Some(crypt_len),
                        key_wrapping_data : None,
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



fn process_register_request(
    rc: &RequestContext,
    req: &RegisterRequest,
) -> std::result::Result<RegisterResponse, KmipResponseError> {
    unimplemented!()
    // Err(KmipResponseError::new("Foo"))
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

fn process_destroy_request(
    rc: &RequestContext,
    req: DestroyRequest,
) -> std::result::Result<DestroyResponse, KmipResponseError> {
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
    if mo.attributes.state == ObjectStateEnum::PreActive
        || mo.attributes.state == ObjectStateEnum::Deactivated
    {
        mo.attributes.state = ObjectStateEnum::Destroyed;

        mo.attributes.destroy_date = Some(rc.get_server_context().clock_source.now());

        let d = bson::to_bson(&mo).unwrap();

        if let bson::Bson::Document(d1) = d {
            rc.get_server_context()
                .get_store()
                .update(&req.unique_identifier, d1);
        } else {
            return Err(KmipResponseError::new("Barff"));
        }
    }

    let resp = DestroyResponse {
        unique_identifier: req.unique_identifier,
    };

    Ok(resp)
}

fn create_ok_response(
    op: protocol::ResponseOperationEnum,
    clock_source: &dyn ClockSource,
) -> protocol::ResponseMessage {
    let r = protocol::ResponseMessage {
        response_header: protocol::ResponseHeader {
            protocol_version: protocol::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            time_stamp: clock_source.now(),
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

    return r;
}

// fn process_request(batchitem: &RequestBatchItem) -> {ResponseOperationEnum

// }

pub fn process_kmip_request(rc: &mut RequestContext, buf: &[u8]) -> Vec<u8> {
    let k = Rc::new(protocol::KmipEnumResolver {});

    info!("Request Message: {:?}", buf.hex_dump());
    protocol::to_print(buf);

    let request = protocol::from_bytes::<RequestMessage>(&buf, k.as_ref()).unwrap();

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
        RequestBatchItem::Register(x) => {
            info!("Got Register Request");
            process_register_request(&rc, &x).map(|r| ResponseOperationEnum::Register(r))
        }
        RequestBatchItem::Get(x) => {
            info!("Got Get Request");
            process_get_request(&rc, x).map(|r| ResponseOperationEnum::Get(r))
        }
        RequestBatchItem::Activate(x) => {
            info!("Got Activate Request");
            process_activate_request(&rc, x).map(|r| ResponseOperationEnum::Activate(r))
        }
        RequestBatchItem::Destroy(x) => {
            info!("Got Destroy Request");
            process_destroy_request(&rc, x).map(|r| ResponseOperationEnum::Destroy(r))
        }
    };

    let rm = match result {
        std::result::Result::Ok(t) => {
            create_ok_response(t, rc.get_server_context().get_clock_source())
        }
        std::result::Result::Err(e) => {
            let msg = format!("error: {}", e);
            create_error_response(Some(msg), rc.get_server_context().get_clock_source())
        }
    };

    let vr = protocol::to_bytes(&rm, k).unwrap();
    info!("Response Message: {:?}", vr.hex_dump());

    protocol::to_print(vr.as_slice());

    return vr;
}
#[cfg(test)]
mod tests {
        use std::sync::Arc;

use protocol::{KmipEnumResolver, RequestMessage};

    use crate::{RequestContext, ServerContext, TestClockSource, process_kmip_request, store::KmipMemoryStore};


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

    protocol::from_bytes::<RequestMessage>(&bytes, &k).unwrap();
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
    let clock_source = Arc::new(TestClockSource::new());
    let server_context = ServerContext::new(store, clock_source);

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

    let clock_source = Arc::new(TestClockSource::new());
    let server_context = ServerContext::new(store, clock_source);

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

}