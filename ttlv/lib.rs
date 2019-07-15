mod de;
mod error;
mod ser;
mod kmip_enums;
mod ttlv;

pub use de::{from_bytes, Deserializer};
pub use error::{Error, Result};
pub use ser::{to_bytes, Serializer};

pub use ttlv::to_print;

#[derive(FromPrimitive, Debug)]
enum ItemType {
 Structure = 0x01,
 Integer = 0x02,
 LongInteger = 0x03,
 BigInteger = 0x04,
 Enumeration = 0x05,
 Boolean = 0x06,
 TextString = 0x07,
 ByteString = 0x08,
 DateTime = 0x09,
 Interval = 0x0A,
}