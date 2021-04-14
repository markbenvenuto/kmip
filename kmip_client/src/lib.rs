#[macro_use]
extern crate log;

extern crate num_derive;

use std::{
    io::{Read, Write},
    rc::Rc,
};

use pretty_hex::*;

// use protocol::{CryptographicAlgorithm, KmipEnumResolver, ProtocolVersion, RequestBatchItem, RequestHeader, RequestMessage};

use protocol::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    // #[error("data store disconnected")]
    // Disconnect(#[from] io::Error),
    #[error("protocol serialization error")]
    Protocol(#[from] protocol::Error),

    #[error("ttlv protocol serialization error")]
    TTLVProtocol(String),

    #[error("operation pending, reason {0}")]
    OperationPending(ResultReason),

    #[error("operation undone, reason {0}")]
    OperationUndone(ResultReason),

    #[error("operation failed, reason {0}, message '{1}'")]
    OperationFailed(ResultReason, String),

    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },
    #[error("unknown client error")]
    Unknown,
}

// TODO - convert TTLVError to thiserror
impl From<protocol::TTLVError> for ClientError {
    fn from(e: protocol::TTLVError) -> Self {
        ClientError::TTLVProtocol(format!("TTLV error: {}", e))
    }
}

pub struct Client<'a, T: 'a + Read + Write + ?Sized> {
    stream: &'a mut T,
}

fn create_ok_request(op: RequestBatchItem) -> std::result::Result<Vec<u8>, ClientError> {
    let r = RequestMessage {
        request_header: RequestHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            client_correlation_value: None,
            batch_count: 1,
        },
        batch_item: op,
    };

    let k = Rc::new(KmipEnumResolver {});

    Ok(protocol::to_bytes(&r, k)?)
}

//fn get_response<R> ()

impl<'a, T> Client<'a, T>
where
    T: 'a + Read + Write,
{
    pub fn create_from_stream(stream: &'a mut T) -> Client<'a, T> {
        Client { stream }
    }

    pub fn create_symmetric_key(
        &mut self,
        algo: CryptographicAlgorithm,
        len: i32,
    ) -> std::result::Result<CreateResponse, ClientError> {
        let attributes = vec![
            AttributesEnum::CryptographicAlgorithm(algo),
            AttributesEnum::CryptographicLength(len),
        ];

        self.create(ObjectTypeEnum::SymmetricKey, attributes)
    }

    pub fn create(
        &mut self,
        object_type: ObjectTypeEnum,
        attributes: Vec<AttributesEnum>,
    ) -> std::result::Result<CreateResponse, ClientError> {
        let req = RequestBatchItem::Create(CreateRequest {
            object_type,
            template_attribute: vec![TemplateAttribute {
                name: None,
                attribute: attributes,
            }],
        });

        let mut bytes = create_ok_request(req)?;

        let rsp = self.make_request(&mut bytes)?;
        if let ResponseOperationEnum::Create(x) = rsp {
            return Ok(x);
        } else {
            panic!();
        }
    }

    pub fn get(&mut self, id: &str) -> std::result::Result<GetResponse, ClientError> {
        let req = RequestBatchItem::Get(GetRequest {
            unique_identifier: id.to_owned(),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
        });

        let mut bytes = create_ok_request(req)?;

        let rsp = self.make_request(&mut bytes)?;
        if let ResponseOperationEnum::Get(x) = rsp {
            return Ok(x);
        } else {
            panic!();
        }
    }

    pub fn activate(&mut self, id: &str) -> std::result::Result<ActivateResponse, ClientError> {
        let req = RequestBatchItem::Activate(ActivateRequest {
            unique_identifier: id.to_owned(),
        });

        let mut bytes = create_ok_request(req)?;

        let rsp = self.make_request(&mut bytes)?;
        if let ResponseOperationEnum::Activate(x) = rsp {
            return Ok(x);
        } else {
            panic!();
        }
    }

    pub fn revoke(
        &mut self,
        id: &str,
        revocation_reason: RevocationReason,
    ) -> std::result::Result<RevokeResponse, ClientError> {
        let req = RequestBatchItem::Revoke(RevokeRequest {
            unique_identifier: id.to_owned(),
            revocation_reason: revocation_reason,
            compromise_occurrence_date: None,
        });

        let mut bytes = create_ok_request(req)?;

        let rsp = self.make_request(&mut bytes)?;
        if let ResponseOperationEnum::Revoke(x) = rsp {
            return Ok(x);
        } else {
            panic!();
        }
    }

    pub fn destroy(&mut self, id: &str) -> std::result::Result<DestroyResponse, ClientError> {
        let req = RequestBatchItem::Destroy(DestroyRequest {
            unique_identifier: id.to_owned(),
        });

        let mut bytes = create_ok_request(req)?;

        let rsp = self.make_request(&mut bytes)?;
        if let ResponseOperationEnum::Destroy(x) = rsp {
            return Ok(x);
        } else {
            panic!();
        }
    }

    pub fn make_request(
        &mut self,
        bytes: &mut [u8],
    ) -> std::result::Result<ResponseOperationEnum, ClientError> {
        self.stream.write_all(bytes).unwrap();

        debug!("Waiting for data....");

        let msg = read_msg(&mut self.stream)?;

        info!("Response Message: {:?}", msg.hex_dump());

        protocol::to_print(&msg);

        let k: KmipEnumResolver = KmipEnumResolver {};

        let response = protocol::from_bytes::<ResponseMessage>(&msg, &k)?;

        //println!("Response: {:?} ", response);

        if let Some(payload) = response.batch_item.response_payload {
            return Ok(payload);
        } else {
            let reason = response
                .batch_item
                .result_reason
                .unwrap_or(ResultReason::InvalidMessage);
            return match response.batch_item.result_status {
                ResultStatus::Success => {
                    unimplemented!("Something is wrong")
                }
                ResultStatus::OperationUndone => Err(ClientError::OperationUndone(reason)),
                ResultStatus::OperationPending => Err(ClientError::OperationPending(reason)),
                ResultStatus::OperationFailed => Err(ClientError::OperationFailed(
                    reason,
                    response
                        .batch_item
                        .result_message
                        .unwrap_or_else(|| String::new()),
                )),
            };
        }
    }

    pub fn make_xml_request(&mut self, xml_str: &str) -> String {
        let k = Rc::new(KmipEnumResolver {});

        let request =
            protocol::from_xml_bytes::<RequestMessage>(xml_str.as_bytes(), k.as_ref()).unwrap();

        let bytes = protocol::to_bytes(&request, k.clone()).unwrap();

        let bytes2 = protocol::to_xml_bytes(&request, k.clone()).unwrap();
        eprint!("xml bytes {:?}", std::str::from_utf8(&bytes2));

        self.stream.write_all(bytes.as_slice()).unwrap();

        debug!("Waiting for data....");

        let msg = read_msg(&mut self.stream).unwrap();

        info!("Response Message: {:?}", msg.hex_dump());

        protocol::to_print(&msg);

        // TODO validate request
        let response = protocol::from_bytes::<ResponseMessage>(&msg, k.as_ref()).unwrap();

        //println!("Response: {:?} ", response);

        // TODO check response

        std::str::from_utf8(&protocol::to_xml_bytes(&response, k).unwrap())
            .unwrap()
            .to_string()
    }

    //     fn create_ok_response(op: ResponseOperationEnum) -> Vec<u8> {
    //         let r = ResponseMessage {
    //             response_header: ResponseHeader {
    //                 protocol_version: ProtocolVersion {
    //                     protocol_version_major: 1,
    //                     protocol_version_minor: 0,
    //                 },
    //                 time_stamp: Utc::now(),
    //                 batch_count: 1,
    //             },
    //             batch_item: ResponseBatchItem {
    //                 result_status: ResultStatus::Success,
    //                 result_reason: ResultReason::GeneralFailure,
    //                 result_message: None,
    //                 response_payload: Some(op),
    //                 // ResponseOperation: None,
    //             },
    //         };

    //         return ttlv::to_bytes(&r).unwrap();
    //     }
}

// pub trait Stream: Read + Write {}

// pub struct Client<'a> {
//     stream: &'a mut dyn Stream,
// }

// impl<'a> Client<'a> {

//     pub fn create_from_stream(stream : &'a mut dyn Stream) -> Client<'a>
//         {
//             Client {
//                 stream : stream,
//             }
//     }

//     pub fn create( object_type: ObjectTypeEnum, attributes: Vec<AttributesEnum>) {

//     }
// }
