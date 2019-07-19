#[macro_use]
extern crate log;

use std::io::{Read,Write};

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



    pub fn create(&mut self, object_type: ObjectTypeEnum, attributes: Vec<AttributesEnum>) -> ResponseOperationEnum {

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

        self.stream.write_all(&mut bytes);

        let msg = read_msg(&mut self.stream);

        // TODO validate request
        let response = ttlv::from_bytes::<ResponseMessage>(&buf, &k).unwrap();

        // TODO check response

        return response.batch_item.response_payload;

        // TODO - validate
        // let req = match object_type {
        //     ObjectTypeEnum::SymmetricKey => {

        //     }
        //     _ => { unimplemented!() }
        // };



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