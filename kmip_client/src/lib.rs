#[macro_use]
extern crate log;

#[macro_use]
extern crate num_derive;

use std::io::{Read,Write};

use pretty_hex::*;

use protocol::*;

pub struct Client<'a, T: 'a + Read + Write + ?Sized> {
    stream: &'a mut T,
}

  fn create_ok_request(op: RequestBatchItem) -> Vec<u8> {
        let r = RequestMessage {
            request_header: RequestHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 0,
                },
                batch_count: 1,
            },
            batch_item: op,
        };

        return ttlv::to_bytes(&r).unwrap();
    }

impl<'a, T> Client<'a, T> where T : 'a + Read + Write {

    pub fn create_from_stream(stream : &'a mut T) -> Client<'a, T>
        {
            Client {
                stream : stream,
            }
    }

    pub fn create_symmetric_key(&mut self, algo: CryptographicAlgorithm, len: i32 ) -> CreateResponse {

        let algo2 = num::ToPrimitive::to_i32(&algo).unwrap();

        let attributes = vec![
            AttributesEnum::CryptographicAlgorithm(algo2),
            AttributesEnum::CryptographicLength(len),
        ];

        return self.create(ObjectTypeEnum::SymmetricKey, attributes);
    }


    pub fn create(&mut self, object_type: ObjectTypeEnum, attributes: Vec<AttributesEnum>) -> CreateResponse {

        let req = RequestBatchItem::Create(CreateRequest {
            object_type : object_type,
            template_attribute : vec!{
                TemplateAttribute{
                    name : None,
                    attribute : attributes,
                }
            }
        });

        let mut bytes = create_ok_request(req);
        // TODO - validate
        // let req = match object_type {
        //     ObjectTypeEnum::SymmetricKey => {

        //     }
        //     _ => { unimplemented!() }
        // };

        let rsp = self.make_request(&mut bytes);
        if let ResponseOperationEnum::Create(x) = rsp {
            return x;
        } else {
            panic!();
        }
    }

    pub fn get(&mut self, id : &str) -> GetResponse {

        let req = RequestBatchItem::Get(GetRequest {
            unique_identifier : id.to_owned(),
key_format_type : None,
key_wrap_type : None,
key_compression_type : None,
        });

        let mut bytes = create_ok_request(req);

        let rsp = self.make_request(&mut bytes);
        if let ResponseOperationEnum::Get(x) = rsp {
            return x;
        } else {
            panic!();
        }
    }


    fn make_request(&mut self, bytes: &mut [u8]) -> ResponseOperationEnum {
        self.stream.write_all(bytes);

        debug!("Waiting for data....");

        let msg = read_msg(&mut self.stream);

        info!("Response Message: {:?}", msg.hex_dump());

        ttlv::to_print(&msg);

        let k: KmipEnumResolver = KmipEnumResolver {};

        // TODO validate request
        let response = ttlv::from_bytes::<ResponseMessage>(&msg, &k).unwrap();

        //println!("Response: {:?} ", response);

        // TODO check response

        return response.batch_item.response_payload.unwrap();

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