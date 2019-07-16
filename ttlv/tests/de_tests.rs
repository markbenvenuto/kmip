use std::io::Cursor;
use std::io::Read;

use std::string::ToString;

use std::ops::{AddAssign, MulAssign, Neg};

use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};
use serde::Deserialize;
use serde::Serialize;

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

use num_traits::FromPrimitive;

extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt};
use pretty_hex::*;
//use self::enums;

//use ttlv::kmip_enums::*;
use ttlv::to_print;
use ttlv::from_bytes;


// #[derive(Serialize, Deserialize, Debug)]
// struct RequestHeader {
//     ProtocolVersionMajor: i32,
//     BatchCount: i32,
// }

// #[derive(Serialize, Deserialize, Debug)]
// struct RequestMessage {
//     RequestHeader: RequestHeader,
//     UniqueIdentifier: String,
// }

// #[test]
// fn test_struct_nested() {

//     let good = vec![
//         66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0, 0, 0,
//         3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7, 0, 0, 0, 0,
//     ];

//     to_print(good.as_ref());
//     let a = from_bytes::<RequestHeader>(&good).unwrap();
// }
