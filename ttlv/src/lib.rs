mod de;
pub mod de_xml;
mod error;
mod kmip_enums;
mod ser;
mod ser_xml;

pub use de::{Reader, TtlvDeserialize};
pub use error::TTLVError;
pub use ttlv_derive::TtlvDeserialize;

#[doc(hidden)]
pub mod __private {
    pub use crate::de::{
        Reader, TtlvDeserialize, expect_boolean, expect_byte_string, expect_datetime,
        expect_enumeration, expect_integer, expect_long_integer, expect_structure_begin,
        expect_structure_end, expect_text_string,
    };
    pub use crate::error::TTLVError;
    pub use crate::kmip_enums::Tag;
}
