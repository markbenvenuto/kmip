extern crate num_derive;

#[macro_use]
extern crate lazy_static;

extern crate pretty_hex;
//extern crate serde_transcode;

extern crate env_logger;
extern crate log;
use log::info;
use serde_bytes::ByteBuf;
use strum::AsStaticRef;

#[macro_use]
extern crate serde_derive;

extern crate serde_enum;

use std::{io::Read, io::Write, rc::Rc};

extern crate clap_log_flag;
extern crate clap_verbosity_flag;
extern crate structopt;

extern crate strum;
extern crate strum_macros;

use pretty_hex::*;

extern crate confy;

extern crate chrono;

use chrono::Utc;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use std::error::Error;
use std::fmt;
use std::string::ToString;

#[macro_use(doc)]
extern crate bson;

pub mod crypto;
pub mod store;
pub mod test_util;

use protocol::*;

use store::ManagedAttributes;
use store::ManagedObjectEnum;
use store::{KmipStore, SymmetricKeyStore};

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

pub trait RngSource {
    fn gen(&self, len: usize) -> Vec<u8>;
}

pub trait ClockSource {
    fn now(&self) -> chrono::DateTime<Utc>;
}

struct ServerContextInner {
    count: i32,
}

#[derive(Clone)]
pub struct ServerContext {
    inner: Arc<Mutex<ServerContextInner>>,
    store: Arc<KmipStore>,
    clock_source: Arc<dyn ClockSource + Send + Sync>,
    rng_source: Arc<dyn RngSource + Send + Sync>,
}

impl ServerContext {
    pub fn new(
        store: Arc<KmipStore>,
        clock_source: Arc<dyn ClockSource + Send + Sync>,
        rng_source: Arc<dyn RngSource + Send + Sync>,
    ) -> ServerContext {
        ServerContext {
            inner: Arc::new(Mutex::new(ServerContextInner { count: 0 })),
            store,
            clock_source,
            rng_source,
        }
    }

    fn get_store<'a>(&'a self) -> &'a KmipStore {
        self.store.as_ref()
    }

    fn get_clock_source(&self) -> &dyn ClockSource {
        self.clock_source.as_ref()
    }

    fn get_rng_source(&self) -> &dyn RngSource {
        self.rng_source.as_ref()
    }
}

pub struct RequestContext<'a> {
    //store: &'a mut KmipStore,
    peer_addr: Option<SocketAddr>,
    server_context: &'a ServerContext,
    // TODO - add support for  ID Placeholder value when processing batches of requests
}

impl<'a> RequestContext<'a> {
    pub fn new(server_context: &'a ServerContext) -> RequestContext<'a> {
        RequestContext {
            peer_addr: None,
            server_context,
        }
    }

    fn get_server_context(&self) -> &'a ServerContext {
        self.server_context
    }

    fn set_peer_addr(&mut self, addr: SocketAddr) {
        self.peer_addr = Some(addr);
    }

    fn get_id_placeholder<'b>(
        &self,
        id: &'b Option<String>,
    ) -> std::result::Result<&'b str, KmipResponseError> {
        match id {
            Some(s) => Ok(s),
            None => Err(KmipResponseError::new(
                "No support for ID Placeholder value",
            )),
        }
    }

    // fn get_store() -> std::sync::MutexGuard<KmipStore> + 'static {
    //     return GLOBAL_STORE.lock().unwrap();
    // }
}

#[derive(Debug)]
pub struct KmipResponseError {
    msg: String,
    reason: ResultReason,
}

impl KmipResponseError {
    fn new(msg: &str) -> KmipResponseError {
        KmipResponseError {
            msg: msg.to_owned(),
            reason: ResultReason::GeneralFailure,
        }
    }

    fn new_reason(reason: ResultReason, msg: &str) -> KmipResponseError {
        KmipResponseError {
            msg: msg.to_owned(),
            reason,
        }
    }
}

impl fmt::Display for KmipResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KMIP Response error ({}), : {}",
            self.reason.as_static(),
            self.msg
        )
    }
}

impl Error for KmipResponseError {
    fn description(&self) -> &str {
        "KMIP Response error"
    }
}

impl From<bson::de::Error> for KmipResponseError {
    fn from(e: bson::de::Error) -> Self {
        KmipResponseError::new(&format!("BSON error: {}", e))
    }
}

impl From<protocol::Error> for KmipResponseError {
    fn from(e: protocol::Error) -> Self {
        KmipResponseError::new(&format!("Protocol error: {}", e))
    }
}

fn create_permission_denied() -> KmipResponseError {
    KmipResponseError::new_reason(ResultReason::PermissionDenied, "DENIED")
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

fn merge_to_secret_data(
    ma: &mut ManagedAttributes,
    sd: &mut SecretData,
    tas: &[TemplateAttribute],
) -> std::result::Result<(), KmipResponseError> {
    for ta in tas {
        for attr in &ta.attribute {
            match attr {
                protocol::AttributesEnum::CryptographicAlgorithm(a) => {
                    sd.key_block.cryptographic_algorithm = Some(*a);
                }
                protocol::AttributesEnum::CryptographicLength(a) => {
                    // TODO - validate
                    sd.key_block.cryptographic_length = Some(*a);
                }
                _ => merge_to_managed_attribute(ma, attr)?,
            }
        }
    }
    Ok(())
}

fn merge_to_symmetric_key(
    ma: &mut ManagedAttributes,
    sks: &mut SymmetricKeyStore,
    tas: &[TemplateAttribute],
) -> std::result::Result<(), KmipResponseError> {
    for ta in tas {
        for attr in &ta.attribute {
            match attr {
                protocol::AttributesEnum::CryptographicAlgorithm(a) => {
                    sks.cryptographic_algorithm = *a;
                }
                protocol::AttributesEnum::CryptographicLength(a) => {
                    // TODO - validate
                    sks.cryptographic_length = *a
                }

                protocol::AttributesEnum::CryptographicParameters(a) => {
                    // TODO - validate
                    sks.cryptographic_parameters = Some(a.clone());
                }
                _ => merge_to_managed_attribute(ma, attr)?,
            }
        }
    }
    Ok(())
}

fn merge_to_managed_attribute(
    ma: &mut ManagedAttributes,
    attr: &AttributesEnum,
) -> std::result::Result<(), KmipResponseError> {
    match attr {
        protocol::AttributesEnum::CryptographicUsageMask(a) => {
            // TODO - validate
            ma.cryptographic_usage_mask = Some(*a);
        }
        protocol::AttributesEnum::ActivationDate(a) => {
            // TODO - validate
            ma.activation_date = Some(*a);
        }
        protocol::AttributesEnum::Name(a) => {
            // TODO - validate
            ma.names.push(a.clone());
        }
        protocol::AttributesEnum::State(_) => {
            return Err(KmipResponseError::new(
                "Cannot set 'State' via a client request",
            ));
        }
        protocol::AttributesEnum::InitialDate(_) => {
            return Err(KmipResponseError::new(
                "Cannot set 'Initial Date' via a client request",
            ));
        }
        protocol::AttributesEnum::LastChangeDate(_) => {
            return Err(KmipResponseError::new(
                "Cannot set 'Last Change Date' via a client request",
            ));
        }
        protocol::AttributesEnum::ObjectType(_) => {
            return Err(KmipResponseError::new(
                "Cannot set 'Object Type' via a client request",
            ));
        }
        protocol::AttributesEnum::UniqueIdentifier(_) => {
            return Err(KmipResponseError::new(
                "Cannot set 'Unique Identifier' via a client request",
            ));
        }
        _ => {
            return Err(KmipResponseError::new(&format!(
                "Attribute {:?} is not supported on object",
                attr
            )));
        }
    }
    Ok(())
}

fn process_create_request(
    rc: &RequestContext,
    req: &CreateRequest,
) -> std::result::Result<CreateResponse, KmipResponseError> {
    let mut ma = ManagedAttributes::new(rc.get_server_context().get_clock_source());

    match req.object_type {
        ObjectTypeEnum::SymmetricKey => {
            // let crypt_len = ma.cryptographic_length.unwrap();
            // let algo = num::FromPrimitive::from_i32(ma.cryptographic_algorithm.unwrap()).unwrap();
            // //                    ma.cryptographic_algorithm = Some(num::FromPrimitive::from_i32(*a).unwrap());

            // TODO - process activation date if set

            // key lengths are in bits

            let mut sks = SymmetricKeyStore {
                symmetric_key: SymmetricKey {
                    key_block: KeyBlock {
                        key_format_type: KeyFormatTypeEnum::Raw,
                        key_value: KeyValue {
                            key_material: Vec::new(),
                        },
                        key_compression_type: None,
                        cryptographic_algorithm: None,
                        cryptographic_length: None,
                        key_wrapping_data: None,
                    },
                },
                cryptographic_parameters: None,
                cryptographic_length: 0,
                cryptographic_algorithm: CryptographicAlgorithm::UNKNOWN,
            };

            merge_to_symmetric_key(&mut ma, &mut sks, &req.template_attribute)?;

            if sks.cryptographic_algorithm == CryptographicAlgorithm::UNKNOWN {
                return Err(KmipResponseError::new(
                    "Invalid value for cryptographic_algorithm",
                ));
            }

            if sks.cryptographic_length == 0 {
                return Err(KmipResponseError::new(
                    "Invalid value for cryptographic_length",
                ));
            }

            //let crypt_len = sks.symmetric_key.key_block.cryptographic_length.ok_or_else(|| KmipResponseError::new("Invalid value for cryptographic_length"))?;
            let crypt_len = sks.cryptographic_length;
            // TODO - validate crypt len

            let key = rc
                .get_server_context()
                .get_rng_source()
                .gen((crypt_len / 8) as usize);

            sks.symmetric_key.key_block.key_value.key_material = key;

            let id = rc.get_server_context().get_store().gen_id();
            let mo = store::ManagedObject {
                id: id.to_string(),
                payload: store::ManagedObjectEnum::SymmetricKey(sks),
                attributes: ma,
            };

            let d = bson::to_bson(&mo).unwrap();
            eprintln!("BSON {:?}", d);

            if let bson::Bson::Document(d1) = d {
                rc.get_server_context().get_store().add(id.as_ref(), d1);

                Ok(CreateResponse {
                    object_type: ObjectTypeEnum::SymmetricKey,
                    unique_identifier: id,
                })
            } else {
                Err(KmipResponseError::new("Barff"))
            }
        }
        _ => Err(KmipResponseError::new("Unsupported type for create")),
    }
}

fn process_register_request(
    rc: &RequestContext,
    req: &RegisterRequest,
) -> std::result::Result<RegisterResponse, KmipResponseError> {
    let mut ma = ManagedAttributes::new(rc.get_server_context().get_clock_source());

    match req.object_type {
        ObjectTypeEnum::SecretData => {
            let mut secret_data = req
                .secret_data
                .as_ref()
                .ok_or_else(|| KmipResponseError::new("Missing secret_data"))?
                .clone();

            merge_to_secret_data(&mut ma, &mut secret_data, &req.template_attribute)?;

            // TODO - validate message

            // TODO - process activation date if set

            // key lengths are in bits

            let id = rc.get_server_context().get_store().gen_id();
            let mo = store::ManagedObject {
                id: id.to_string(),
                payload: store::ManagedObjectEnum::SecretData(SecretData {
                    secret_data_type: secret_data.secret_data_type,
                    key_block: secret_data.key_block,
                }),
                attributes: ma,
            };

            eprintln!("Storing Secret Data");
            let d = bson::to_bson(&mo).unwrap();

            if let bson::Bson::Document(d1) = d {
                rc.get_server_context().get_store().add(id.as_ref(), d1);

                Ok(RegisterResponse {
                    unique_identifier: id,
                    template_attribute: None,
                })
            } else {
                Err(KmipResponseError::new("Barff"))
            }
        }
        ObjectTypeEnum::SymmetricKey => {
            // TODO - validate message
            eprintln!("Storing Symmetric Key");

            // TODO - process activation date if set

            // key lengths are in bits
            let symmetric_key = req
                .symmetric_key
                .as_ref()
                .ok_or_else(|| KmipResponseError::new("Missing symmetric_key"))?;

            let mut sks = SymmetricKeyStore {
                symmetric_key: symmetric_key.clone(),
                cryptographic_parameters: None,
                cryptographic_algorithm: CryptographicAlgorithm::UNKNOWN,
                cryptographic_length: 0,
            };

            merge_to_symmetric_key(&mut ma, &mut sks, &req.template_attribute)?;

            if sks.cryptographic_algorithm == CryptographicAlgorithm::UNKNOWN {
                sks.cryptographic_algorithm = sks
                    .symmetric_key
                    .key_block
                    .cryptographic_algorithm
                    .ok_or_else(|| {
                    KmipResponseError::new("cryptographic_algorithm was not set")
                })?;
            }
            if sks.cryptographic_length == 0 {
                sks.cryptographic_length = sks
                    .symmetric_key
                    .key_block
                    .cryptographic_length
                    .ok_or_else(|| KmipResponseError::new("cryptographic_length was not set"))?;
            }

            let id = rc.get_server_context().get_store().gen_id();
            let mo = store::ManagedObject {
                id: id.to_string(),
                payload: store::ManagedObjectEnum::SymmetricKey(sks),
                attributes: ma,
            };

            println!("MO: {:?}", mo);
            let d = bson::to_bson(&mo).unwrap();
            eprintln!("BSON {:?}", d);
            if let bson::Bson::Document(d1) = d {
                rc.get_server_context().get_store().add(id.as_ref(), d1);

                Ok(RegisterResponse {
                    unique_identifier: id,
                    template_attribute: None,
                })
            } else {
                Err(KmipResponseError::new("Barff"))
            }
        }
        _ => Err(KmipResponseError::new("Unsupported type for register")),
    }
}

fn process_get_request(
    rc: &RequestContext,
    req: GetRequest,
) -> std::result::Result<GetResponse, KmipResponseError> {
    let mo = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier)?;

    let mut resp = GetResponse {
        object_type: ObjectTypeEnum::SymmetricKey,
        unique_identifier: req.unique_identifier,
        symmetric_key: None,
        secret_data: None,
    };

    match mo.payload {
        ManagedObjectEnum::SymmetricKey(x) => {
            let mut key = x.symmetric_key;
            // TODO - check this merge logic
            key.key_block.cryptographic_algorithm = Some(x.cryptographic_algorithm);
            key.key_block.cryptographic_length = Some(x.cryptographic_length);

            resp.object_type = ObjectTypeEnum::SymmetricKey;
            resp.symmetric_key = Some(key);
        }
        ManagedObjectEnum::SecretData(x) => {
            resp.object_type = ObjectTypeEnum::SecretData;
            resp.secret_data = Some(x);
        }
    }

    Ok(resp)
}

fn process_get_attributes_request(
    rc: &RequestContext,
    req: GetAttributesRequest,
) -> std::result::Result<GetAttributesResponse, KmipResponseError> {
    let mo = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier)?;

    let attributes = if req.attribute.is_none() {
        // Get all the attributes
        mo.attributes.get_all_attributes()
    } else {
        let mut attrs: Vec<AttributesEnum> = Vec::new();
        for name in req.attribute.unwrap() {
            let ga = mo.get_attribute(&name);
            if let Some(attr1) = ga {
                attrs.push(attr1);
            }
        }

        attrs
    };

    let resp = GetAttributesResponse {
        unique_identifier: req.unique_identifier,
        attribute: attributes,
    };

    Ok(resp)
}

fn process_get_attribute_list_request(
    rc: &RequestContext,
    req: GetAttributeListRequest,
) -> std::result::Result<GetAttributeListResponse, KmipResponseError> {
    let mo = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier)?;

    let attribute_names = mo.get_attribute_list();

    let resp = GetAttributeListResponse {
        unique_identifier: req.unique_identifier,
        attribute: attribute_names,
    };

    Ok(resp)
}

fn process_activate_request<'a>(
    rc: &'a RequestContext<'a>,
    req: ActivateRequest,
) -> std::result::Result<ActivateResponse, KmipResponseError> {
    let mut mo = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier)?;

    // TODO - throw an error on illegal state transition??
    if mo.attributes.state == ObjectStateEnum::PreActive {
        mo.attributes.state = ObjectStateEnum::Active;

        mo.attributes.activation_date = Some(rc.get_server_context().get_clock_source().now());

        rc.get_server_context()
            .get_store()
            .update(&req.unique_identifier, &mut mo)?;
    }

    let resp = ActivateResponse {
        unique_identifier: req.unique_identifier,
    };

    Ok(resp)
}

fn process_revoke_request<'a>(
    rc: &'a RequestContext,
    req: RevokeRequest,
) -> std::result::Result<RevokeResponse, KmipResponseError> {
    let mut mo = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier)?;

    // TODO - record revocation code and reason text
    if req.revocation_reason.revocation_reason_code == RevocationReasonCode::KeyCompromise {
        mo.attributes.state = ObjectStateEnum::Compromised;
        mo.attributes.compromise_date = req
            .compromise_occurrence_date
            .or(Some(rc.get_server_context().get_clock_source().now()));
    } else {
        mo.attributes.state = ObjectStateEnum::Deactivated;
        mo.attributes.deactivation_date = Some(rc.get_server_context().get_clock_source().now());
    }

    rc.get_server_context()
        .get_store()
        .update(&req.unique_identifier, &mut mo)?;

    let resp = RevokeResponse {
        unique_identifier: req.unique_identifier,
    };

    Ok(resp)
}

fn process_destroy_request<'a>(
    rc: &'a RequestContext,
    req: DestroyRequest,
) -> std::result::Result<DestroyResponse, KmipResponseError> {
    let mut mo = rc
        .get_server_context()
        .get_store()
        .get(&req.unique_identifier)?;

    if mo.attributes.state == ObjectStateEnum::PreActive
        || mo.attributes.state == ObjectStateEnum::Deactivated
        || mo.attributes.state == ObjectStateEnum::Compromised
    {
        if mo.attributes.state == ObjectStateEnum::Compromised {
            mo.attributes.state = ObjectStateEnum::DestroyedCompromised;
        } else {
            mo.attributes.state = ObjectStateEnum::Destroyed;
        }

        mo.attributes.destroy_date = Some(rc.get_server_context().clock_source.now());

        rc.get_server_context()
            .get_store()
            .update(&req.unique_identifier, &mut mo)?;
    } else {
        return Err(create_permission_denied());
    }

    let resp = DestroyResponse {
        unique_identifier: req.unique_identifier,
    };

    Ok(resp)
}

fn process_encrypt_request<'a>(
    rc: &'a RequestContext,
    req: &EncryptRequest,
) -> std::result::Result<EncryptResponse, KmipResponseError> {
    let id = rc.get_id_placeholder(&req.unique_identifier)?;

    let mo = rc.get_server_context().get_store().get(id)?;

    let sks = mo.get_symmetric_key()?;

    let key = &sks.symmetric_key.key_block.key_value.key_material;

    let algo = sks.cryptographic_algorithm;

    let mut block_cipher_mode: Option<BlockCipherMode> = None;
    let mut padding_method: Option<PaddingMethod> = None;
    let mut random_iv: Option<bool> = None;

    // Default to the on disk information
    if let Some(disk_params) = &sks.cryptographic_parameters {
        block_cipher_mode = disk_params.block_cipher_mode;
        padding_method = disk_params.padding_method;
        random_iv = disk_params.random_iv;
    }

    // Defer to the passed in information
    if let Some(params) = &req.cryptographic_parameters {
        block_cipher_mode = params.block_cipher_mode.or(block_cipher_mode);
        padding_method = params.padding_method.or(padding_method);
        random_iv = params.random_iv.or(random_iv);
    }

    // TODO
    // We only support block ciphers for now, if we support streaming ciphers we will have to do something
    let block_cipher_mode =
        block_cipher_mode.ok_or_else(|| KmipResponseError::new("Block Cipher Mode is required"))?;
    // let padding_method = padding_method.ok_or_else(|| KmipResponseError::new("Padding Method Mode is required"))?;
    let padding_method = padding_method.unwrap_or(PaddingMethod::None);

    // TODO - what to do about random_iv? For now, always generate a random iv unless passed a nonce
    //req.iv_counter_nonce.map(|x| x.as_ref()))?;
    let ret = crypto::encrypt_block_cipher(
        algo,
        block_cipher_mode,
        padding_method,
        key,
        &req.data,
        &req.iv_counter_nonce,
        random_iv.unwrap_or(false),
        rc.get_server_context().get_rng_source(),
    )?;

    let resp = EncryptResponse {
        unique_identifier: id.to_owned(),
        data: ret.0,
        iv_counter_nonce: ret.1.map(ByteBuf::from),
    };

    Ok(resp)
}

fn process_decrypt_request(
    rc: &RequestContext,
    req: &DecryptRequest,
) -> std::result::Result<DecryptResponse, KmipResponseError> {
    let id = rc.get_id_placeholder(&req.unique_identifier)?;

    let mo = rc.get_server_context().get_store().get(id)?;

    let sks = mo.get_symmetric_key()?;

    let key = &sks.symmetric_key.key_block.key_value.key_material;

    let algo = sks.cryptographic_algorithm;

    let mut block_cipher_mode: Option<BlockCipherMode> = None;
    let mut padding_method: Option<PaddingMethod> = None;

    // Default to the on disk information
    if let Some(disk_params) = &sks.cryptographic_parameters {
        block_cipher_mode = disk_params.block_cipher_mode;
        padding_method = disk_params.padding_method;
    }

    // Defer to the passed in information
    if let Some(params) = &req.cryptographic_parameters {
        block_cipher_mode = params.block_cipher_mode.or(block_cipher_mode);
        padding_method = params.padding_method.or(padding_method);
    }

    // TODO
    // We only support block ciphers for now, if we support streaming ciphers we will have to do something
    let block_cipher_mode =
        block_cipher_mode.ok_or_else(|| KmipResponseError::new("Block Cipher Mode is required"))?;
    // let padding_method = padding_method.ok_or_else(|| KmipResponseError::new("Padding Method Mode is required"))?;
    let padding_method = padding_method.unwrap_or(PaddingMethod::None);

    // TODO - what to do about random_iv? For now, always generate a random iv unless passed a nonce
    //req.iv_counter_nonce.map(|x| x.as_ref()))?;
    let ret = crypto::decrypt_block_cipher(
        algo,
        block_cipher_mode,
        padding_method,
        key,
        &req.data,
        &req.iv_counter_nonce,
    )?;

    let resp = DecryptResponse {
        unique_identifier: id.to_owned(),
        data: ret,
    };

    Ok(resp)
}

fn process_mac_request(
    rc: &RequestContext,
    req: &MACRequest,
) -> std::result::Result<MACResponse, KmipResponseError> {
    let id = rc.get_id_placeholder(&req.unique_identifier)?;

    let mo = rc.get_server_context().get_store().get(id)?;

    let sks = mo.get_symmetric_key()?;

    let key = &sks.symmetric_key.key_block.key_value.key_material;

    let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
    // Default to the on disk information
    if let Some(disk_params) = &sks.cryptographic_parameters {
        cryptographic_algorithm = disk_params.cryptographic_algorithm;
    }

    // Defer to the passed in information
    if let Some(params) = &req.cryptographic_parameters {
        cryptographic_algorithm = params.cryptographic_algorithm.or(cryptographic_algorithm);
    }

    let algo =
        cryptographic_algorithm.ok_or_else(|| KmipResponseError::new("Algorithm is required"))?;

    // TODO - what to do about random_iv? For now, always generate a random iv unless passed a nonce
    //req.iv_counter_nonce.map(|x| x.as_ref()))?;
    let ret = crypto::hmac(algo, key, &req.data)?;

    let resp = MACResponse {
        unique_identifier: id.to_owned(),
        mac_data: ret,
    };

    Ok(resp)
}

fn process_mac_verify_request(
    rc: &RequestContext,
    req: &MACVerifyRequest,
) -> std::result::Result<MACVerifyResponse, KmipResponseError> {
    let id = rc.get_id_placeholder(&req.unique_identifier)?;

    let mo = rc.get_server_context().get_store().get(id)?;

    let sks = mo.get_symmetric_key()?;

    let key = &sks.symmetric_key.key_block.key_value.key_material;

    let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
    // Default to the on disk information
    if let Some(disk_params) = &sks.cryptographic_parameters {
        cryptographic_algorithm = disk_params.cryptographic_algorithm;
    }

    // Defer to the passed in information
    if let Some(params) = &req.cryptographic_parameters {
        cryptographic_algorithm = params.cryptographic_algorithm.or(cryptographic_algorithm);
    }

    let algo =
        cryptographic_algorithm.ok_or_else(|| KmipResponseError::new("Algorithm is required"))?;

    // TODO - what to do about random_iv? For now, always generate a random iv unless passed a nonce
    //req.iv_counter_nonce.map(|x| x.as_ref()))?;
    let ret = crypto::hmac_verify(algo, key, &req.data, &req.mac_data)?;

    let resp = MACVerifyResponse {
        unique_identifier: id.to_owned(),
        validity_indicator: ret,
    };

    Ok(resp)
}

////////////////////////////////////////////////////////////////////////////////////////////////////

fn create_ok_response(
    op: protocol::ResponseOperationEnum,
    clock_source: &dyn ClockSource,
) -> protocol::ResponseMessage {
    protocol::ResponseMessage {
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
            result_response_enum: None,
        },
    }
}

fn create_error_response(
    e: &KmipResponseError,
    request_operation: Operation,
    clock_source: &dyn ClockSource,
) -> protocol::ResponseMessage {
    protocol::ResponseMessage {
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
            result_reason: Some(e.reason),
            result_message: Some(e.msg.to_owned()),
            response_payload: None,
            result_response_enum: Some(request_operation),
        },
    }
}

// fn process_request(batchitem: &RequestBatchItem) -> {ResponseOperationEnum

// }

pub fn process_kmip_request(rc: &mut RequestContext, buf: &[u8]) -> Vec<u8> {
    let k = Rc::new(protocol::KmipEnumResolver {});

    info!("Request Message: {:?}", buf.hex_dump());
    protocol::to_print(buf);

    let request_ret = protocol::from_bytes::<RequestMessage>(&buf, k.as_ref());

    if let Err(e) = request_ret {
        // If we fail to decode, we just return a very generic error
        let rm = create_error_response(
            &KmipResponseError::from(e),
            Operation::Cancel,
            rc.get_server_context().get_clock_source(),
        );

        let vr = protocol::to_bytes(&rm, k).unwrap();
        info!("Response Message: {:?}", vr.hex_dump());

        protocol::to_print(vr.as_slice());

        return vr;
    }

    let request = request_ret.expect("Already checked");

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

    let request_operation = get_operation_for_request(&request.batch_item);

    let result = match request.batch_item {
        RequestBatchItem::Create(x) => {
            info!("Got Create Request");
            process_create_request(&rc, &x).map(ResponseOperationEnum::Create)
        }
        RequestBatchItem::Register(x) => {
            info!("Got Register Request");
            process_register_request(&rc, &x).map(ResponseOperationEnum::Register)
        }
        RequestBatchItem::Get(x) => {
            info!("Got Get Request");
            process_get_request(&rc, x).map(ResponseOperationEnum::Get)
        }
        RequestBatchItem::GetAttributes(x) => {
            info!("Got Get Request");
            process_get_attributes_request(&rc, x).map(ResponseOperationEnum::GetAttributes)
        }
        RequestBatchItem::GetAttributeList(x) => {
            info!("Got Get Request");
            process_get_attribute_list_request(&rc, x).map(ResponseOperationEnum::GetAttributeList)
        }
        RequestBatchItem::Activate(x) => {
            info!("Got Activate Request");
            process_activate_request(&rc, x).map(ResponseOperationEnum::Activate)
        }
        RequestBatchItem::Destroy(x) => {
            info!("Got Destroy Request");
            process_destroy_request(&rc, x).map(ResponseOperationEnum::Destroy)
        }
        RequestBatchItem::Encrypt(x) => {
            info!("Got Encrypt Request");
            process_encrypt_request(&rc, &x).map(ResponseOperationEnum::Encrypt)
        }
        RequestBatchItem::Decrypt(x) => {
            info!("Got Decrypt Request");
            process_decrypt_request(&rc, &x).map(ResponseOperationEnum::Decrypt)
        }
        RequestBatchItem::MAC(x) => {
            info!("Got MAC Request");
            process_mac_request(&rc, &x).map(ResponseOperationEnum::MAC)
        }
        RequestBatchItem::MACVerify(x) => {
            info!("Got MACVerify Request");
            process_mac_verify_request(&rc, &x).map(ResponseOperationEnum::MACVerify)
        }
        RequestBatchItem::Revoke(x) => {
            info!("Got Revoke Request");
            process_revoke_request(&rc, x).map(ResponseOperationEnum::Revoke)
        }
    };

    let mut rm = match result {
        std::result::Result::Ok(t) => {
            create_ok_response(t, rc.get_server_context().get_clock_source())
        }
        std::result::Result::Err(e) => create_error_response(
            &e,
            request_operation,
            rc.get_server_context().get_clock_source(),
        ),
    };

    rm.response_header.protocol_version.protocol_version_major = request
        .request_header
        .protocol_version
        .protocol_version_major;
    rm.response_header.protocol_version.protocol_version_minor = request
        .request_header
        .protocol_version
        .protocol_version_minor;

    let vr = protocol::to_bytes(&rm, k).unwrap();
    info!("Response Message: {:?}", vr.hex_dump());

    protocol::to_print(vr.as_slice());

    vr
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use protocol::{KmipEnumResolver, RequestMessage};

    use crate::{
        process_kmip_request, store::KmipStore, test_util::TestClockSource,
        test_util::TestRngSource, RequestContext, ServerContext,
    };

    #[test]
    fn test_create_request() {
        let bytes = vec![
            0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x01, 0x20, 0x42, 0x00, 0x77, 0x01, 0x00, 0x00,
            0x00, 0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0xd8, 0x42, 0x00, 0x5c, 0x05,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x79, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x42, 0x00, 0x57, 0x05, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x91, 0x01, 0x00, 0x00,
            0x00, 0xa8, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x17, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x00,
            0x42, 0x00, 0x0b, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x14, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x18, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x4d, 0x61, 0x73, 0x6b,
            0x42, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
            0x00, 0x00,
        ];

        protocol::to_print(bytes.as_slice());

        let k: KmipEnumResolver = KmipEnumResolver {};

        protocol::from_bytes::<RequestMessage>(&bytes, &k).unwrap();
    }

    #[test]
    fn test_create_request2() {
        let bytes = vec![
            0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x01, 0x20, 0x42, 0x00, 0x77, 0x01, 0x00, 0x00,
            0x00, 0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0xd8, 0x42, 0x00, 0x5c, 0x05,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x79, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x42, 0x00, 0x57, 0x05, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x91, 0x01, 0x00, 0x00,
            0x00, 0xa8, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x17, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x00,
            0x42, 0x00, 0x0b, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x14, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x18, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x4d, 0x61, 0x73, 0x6b,
            0x42, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
            0x00, 0x00,
        ];

        let clock_source = Arc::new(TestClockSource::new());
        let rng_source = Arc::new(TestRngSource::new());
        let store = Arc::new(KmipStore::new_mem(clock_source.clone()));
        let server_context = ServerContext::new(store, clock_source, rng_source);

        let mut rc = RequestContext::new(&server_context);
        process_kmip_request(&mut rc, bytes.as_slice());

        //unimplemented!();
    }

    #[test]
    fn test_create_request3() {
        let bytes = vec![
            0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x01, 0x20, 0x42, 0x00, 0x77, 0x01, 0x00, 0x00,
            0x00, 0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0xd8, 0x42, 0x00, 0x5c, 0x05,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x79, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x42, 0x00, 0x57, 0x05, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x91, 0x01, 0x00, 0x00,
            0x00, 0xa8, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x17, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x00,
            0x42, 0x00, 0x0b, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x14, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x0a, 0x07,
            0x00, 0x00, 0x00, 0x18, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70,
            0x68, 0x69, 0x63, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x4d, 0x61, 0x73, 0x6b,
            0x42, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
            0x00, 0x00,
        ];

        let clock_source = Arc::new(TestClockSource::new());
        let rng_source = Arc::new(TestRngSource::new());
        let store = Arc::new(KmipStore::new_mem(clock_source.clone()));
        let server_context = ServerContext::new(store, clock_source, rng_source);

        let mut rc = RequestContext::new(&server_context);
        process_kmip_request(&mut rc, bytes.as_slice());

        let get_bytes = vec![
            0x42, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x70, 0x42, 0x00, 0x77, 0x01, 0x00, 0x00,
            0x00, 0x38, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x6a, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x28, 0x42, 0x00, 0x5c, 0x05,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x79, 0x01, 0x00, 0x00, 0x00, 0x10, 0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x01,
            0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        process_kmip_request(&mut rc, get_bytes.as_slice());

        //unimplemented!();
    }
}
