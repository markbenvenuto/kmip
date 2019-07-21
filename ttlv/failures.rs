use failure::Error;

use crate::kmip_enums::ItemType;

#[derive(Debug, Fail)]
pub enum TTLVError {
    #[fail(display = "invalid ttlv type: {}", byte)]
    InvalidType {
        byte: u8,
    },
    #[fail(display = "invalid ttlv tag: {}", tag)]
    InvalidTag {
        tag: u32,
    },
    #[fail(display = "invalid ttlv tag name: {}", name)]
    InvalidTagName {
        name: String,
    },
    #[fail(display = "invalid write {}, {}", count, error)]
    BadWrite
     {
        count : usize,
        error: std::io::Error,
    },
    #[fail(display = "invalid read {}, {}", count, error)]
    BadRead
     {
        count : usize,
        error: std::io::Error,
    },
    #[fail(display = "invalid ttlv string")]
    BadString,
    #[fail(display = "unexpected type, expected {:?}, actual {:?}", expected, actual)]
    UnexpectedType
     {
         expected: ItemType,
         actual: ItemType,
    },
}