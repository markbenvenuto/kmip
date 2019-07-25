use std;
use std::fmt::{self, Display};

use crate::failures::TTLVError;
use serde::{de, ser};

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

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(std::error::Error::description(self))
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Message(ref msg) => msg,
            Error::Eof => "unexpected end of input",
            Error::UnsupportedType => "unsupported type",
            Error::TTLVError(ref err) => "ttlv error",
            /* and so forth */
        }
    }
}

impl std::convert::From<TTLVError> for Error {
    fn from(e: TTLVError) -> Self {
        Error::TTLVError(format!("ttlv error: {}", e))
    }
}
