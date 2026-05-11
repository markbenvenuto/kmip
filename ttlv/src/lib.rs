mod de;
pub mod de_xml;
mod error;
mod kmip_enums;
pub mod ser;
mod ser_xml;

pub use de::{Reader, TtlvDeserialize};
pub use error::TTLVError;
pub use ser::{NestedWriter, TtlvSerialize};
pub use ttlv_derive::TtlvDeserialize;
pub use ttlv_derive::TtlvSerialize;

#[doc(hidden)]
pub mod __private {
    pub use crate::de::{
        Reader, TtlvDeserialize, expect_boolean, expect_byte_string, expect_datetime,
        expect_enumeration, expect_integer, expect_long_integer, expect_structure_begin,
        expect_structure_end, expect_text_string,
    };
    pub use crate::error::TTLVError;
    pub use crate::kmip_enums::Tag;
    pub use crate::ser::{
        EncodedWriter, TtlvSerialize,
        ser_write_boolean, ser_write_byte_string, ser_write_datetime,
        ser_write_enumeration, ser_write_integer, ser_write_long_integer,
        ser_write_structure_begin, ser_write_structure_end, ser_write_text_string,
    };
}
