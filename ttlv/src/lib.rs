mod de;
pub mod de_xml;
mod error;
pub mod kmip_enums;
pub mod ser;
mod ser_xml;

use std::io::{Cursor, Read};

pub use de::to_print;
pub use de::{Reader, TtlvDeserialize};
pub use error::TTLVError;
pub use kmip_enums::Tag;
pub use ser::{NestedWriter, TtlvSerialize};
pub use ttlv_derive::{
    TtlvDeserialize, TtlvEnumDeserialize, TtlvEnumSerialize, TtlvSerialize,
    TtlvTaggedEnumDeserialize, TtlvTaggedEnumSerialize,
};

use crate::{
    de::{read_len, read_tag, read_type},
    kmip_enums::ItemType,
};

#[doc(hidden)]
pub mod __private {
    pub use crate::de::{
        Reader, TtlvDeserialize, expect_boolean, expect_byte_string, expect_datetime,
        expect_enumeration, expect_integer, expect_long_integer, expect_structure_begin,
        expect_structure_end, expect_text_string,
    };
    pub use crate::error::TTLVError;
    pub use crate::kmip_enums::{Tag, ValueType};
    pub use crate::ser::{
        EncodedWriter, TtlvSerialize, ser_write_boolean, ser_write_byte_string, ser_write_datetime,
        ser_write_enumeration, ser_write_integer, ser_write_long_integer,
        ser_write_structure_begin, ser_write_structure_end, ser_write_text_string,
    };
    pub use ::num::ToPrimitive;
}

pub fn read_msg(reader: &mut dyn Read) -> std::result::Result<Vec<u8>, TTLVError> {
    let mut msg: Vec<u8> = Vec::new();
    msg.resize(8, 0);

    // TODO -assert item type in buffer
    reader
        .read_exact(msg.as_mut())
        .map_err(|error| TTLVError::BadRead { count: 8, error })?;

    // Check length
    let len: usize;
    {
        let mut cur = Cursor::new(msg);
        read_tag(&mut cur)?;
        let t = read_type(&mut cur)?;
        if t != ItemType::Structure {
            return Err(TTLVError::UnexpectedType {
                expected: ItemType::Structure,
                actual: t,
            });
        }

        len = read_len(&mut cur)? as usize;

        msg = cur.into_inner();
    }

    msg.resize(msg.len() + len, 0);

    let slice: &mut [u8] = msg.as_mut();
    reader
        .read_exact(&mut slice[8..])
        .map_err(|error| TTLVError::BadRead { count: len, error })?;

    Ok(msg)
}
