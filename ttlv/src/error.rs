use std;

use thiserror::Error;

use crate::{
    __private::ValueType,
    kmip_enums::{ItemType, Tag},
};

pub type Result<T> = std::result::Result<T, Error>;

// This is a bare-bones implementation. A real library would provide additional
// information in its error type, for example the line and column at which the
// error occurred, the byte offset into the input, or the current key being
// processed.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    // One or more variants that can be created by data structures through the
    // `ser::Error` and `de::Error` traits. For example the Serialize impl for
    // Mutex<T> might return an error because the mutex is poisoned, or the
    // Deserialize impl for a struct may return an error because a required
    // field is missing.
    Message(String),

    TTLVError(String),
    // Zero or more variants that can be created directly by the Serializer and
    // Deserializer without going through `ser::Error` and `de::Error`. These
    // are specific to the format, in this case JSON.
    Eof,
    UnsupportedType, // Syntax,
                     // ExpectedBoolean,
                     // ExpectedInteger,
                     // ExpectedString,
                     // ExpectedNull,
                     // ExpectedArray,
                     // ExpectedArrayComma,
                     // ExpectedArrayEnd,
                     // ExpectedMap,
                     // ExpectedMapColon,
                     // ExpectedMapComma,
                     // ExpectedMapEnd,
                     // ExpectedEnum,
                     // TrailingCharacters
}

impl std::convert::From<TTLVError> for Error {
    fn from(e: TTLVError) -> Self {
        Error::TTLVError(format!("ttlv error: {}", e))
    }
}

// TODO - switch TTLVError to thiserror
#[derive(Debug, Error)]
pub enum TTLVError {
    #[error("invalid ttlv type: {}", byte)]
    InvalidType { byte: u8 },

    #[error("invalid ttlv tag prefix: {}", byte)]
    InvalidTagPrefix { byte: u8 },

    #[error("invalid ttlv tag: {}", tag)]
    InvalidTag { tag: u32 },

    #[error("invalid ttlv len {}, expected {} for {}", actual, expected, context)]
    InvalidTypeLength {
        actual: u32,
        expected: u32,
        context: String,
    },

    #[error("invalid ttlv tag name: {}", name)]
    InvalidTagName { name: String },

    #[error("invalid write {}, {}", count, error)]
    BadWrite { count: usize, error: std::io::Error },

    #[error("invalid read {}, {}", count, error)]
    BadRead { count: usize, error: std::io::Error },

    #[error("invalid ttlv string")]
    BadString,

    #[error("invalid xml write")]
    XmlError,

    #[error("unexpected type, expected {:?}, actual {:?}", expected, actual)]
    UnexpectedType {
        expected: ItemType,
        actual: ItemType,
    },

    #[error("unexpected tag: expected {:?}, got {:?}", expected, actual)]
    UnexpectedTag { expected: Tag, actual: Tag },

    #[error(
        "unexpected value type for tag {:?}, expected {:?}, actual {:?}",
        tag,
        expected,
        actual
    )]
    WrongValueType {
        tag: Tag,
        expected: ItemType,
        actual: ValueType,
    },

    #[error("unexpected end of token stream")]
    EndOfTokenStream,

    #[error("invalid enum value for tag {:?}: {}", tag, value)]
    InvalidEnumValue { tag: Tag, value: u32 },

    #[error("unresolved enumeration: tag {:?}, value {}", tag, value)]
    UnresolvedEnumeration { tag: Tag, value: String },

    #[error("invalid xml read {}", message)]
    XmlReadError { message: String },

    #[error("enum variant for tag {:?} cannot be converted to u32", tag)]
    EnumConvertFailed { tag: Tag },
}
