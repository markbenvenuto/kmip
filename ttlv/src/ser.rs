use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};
use num::ToPrimitive;

//use self::enums;
use crate::{error::TTLVError, kmip_enums::*};

type TTLVResult<T> = std::result::Result<T, TTLVError>;

// fn write_tag(writer: &mut dyn Write, tag: u16) {
//     // println!("write_tag");
//     // 0x42 for tags built into the protocol
//     // 0x54 for extension tags
//     writer.write_u8(0x42).unwrap();
//     writer.write_u16::<BigEndian>(tag).unwrap();
// }

fn write_tag_enum(writer: &mut dyn Write, tag: Tag) -> TTLVResult<()> {
    // println!("write_Tag");
    // 0x42 for tags built into the protocol
    // 0x54 for extension tags
    let tag_u32 = num::ToPrimitive::to_u32(&tag).unwrap();
    writer
        .write_u8(0x42)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;
    writer
        .write_u16::<BigEndian>(tag_u32 as u16)
        .map_err(|error| TTLVError::BadWrite { count: 2, error })
}

fn compute_padding(len: usize) -> usize {
    if len % 8 == 0 {
        return len;
    }

    let padding = 8 - (len % 8);
    len + padding
}

pub fn write_string(writer: &mut dyn Write, value: &str) -> TTLVResult<()> {
    // println!("write_string");
    writer
        .write_u8(ItemType::TextString as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(value.len() as u32)
        .map_err(|error| TTLVError::BadWrite { count: 2, error })?;

    writer
        .write(value.as_bytes())
        .map_err(|error| TTLVError::BadWrite {
            count: value.len(),
            error,
        })?;

    let padded_length = compute_padding(value.len());
    for _ in 0..(padded_length - value.len()) {
        writer
            .write_u8(0)
            .map_err(|error| TTLVError::BadWrite { count: 1, error })?;
    }

    Ok(())
}

pub fn write_bytes(writer: &mut dyn Write, value: &[u8]) -> TTLVResult<()> {
    // println!("write_bytes");
    writer
        .write_u8(ItemType::ByteString as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(value.len() as u32)
        .map_err(|error| TTLVError::BadWrite { count: 2, error })?;

    writer.write(value).map_err(|error| TTLVError::BadWrite {
        count: value.len(),
        error,
    })?;

    let padded_length = compute_padding(value.len());
    for _ in 0..(padded_length - value.len()) {
        writer
            .write_u8(0)
            .map_err(|error| TTLVError::BadWrite { count: 1, error })?;
    }

    Ok(())
}

pub fn write_i32(writer: &mut dyn Write, value: i32) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::Integer as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(4)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    writer
        .write_i32::<BigEndian>(value)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    // Add 4 bytes of padding
    // TODO - make faster
    writer
        .write_u32::<BigEndian>(0)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })
}

pub fn write_i64(writer: &mut dyn Write, value: i64) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::LongInteger as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(8)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    writer
        .write_i64::<BigEndian>(value)
        .map_err(|error| TTLVError::BadWrite { count: 8, error })
}

pub fn write_enumeration(writer: &mut dyn Write, value: u32) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::Enumeration as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(4)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    writer
        .write_u32::<BigEndian>(value)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    // Add 4 bytes of padding
    // TODO - make faster
    writer
        .write_u32::<BigEndian>(0)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })
}

// fn write_datetime(writer: &mut dyn Write, value: chrono::NaiveDateTime) {
//     write_i64_datetime(writer, value.timestamp_millis());
// }

pub fn write_i64_datetime(writer: &mut dyn Write, value: i64) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::DateTime as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(8)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    writer
        .write_i64::<BigEndian>(value)
        .map_err(|error| TTLVError::BadWrite { count: 8, error })
}

pub fn write_boolean(writer: &mut dyn Write, value: bool) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::Boolean as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })?;

    writer
        .write_u32::<BigEndian>(8)
        .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

    writer
        .write_i64::<BigEndian>(value as i64)
        .map_err(|error| TTLVError::BadWrite { count: 8, error })
}

pub fn write_struct_start(writer: &mut dyn Write) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::Structure as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })
}

pub trait EncodedWriter {
    fn get_vector(self) -> Vec<u8>
    where
        Self: Sized;

    fn write_tag(&mut self, tag: Tag) -> TTLVResult<()>;

    fn set_attribute_tag(&mut self, tag: Tag) -> TTLVResult<()>;

    // fn get_tag(&self) -> Option<Tag>;
    // fn set_tag(&mut self, tag: Tag);

    // fn write_optional_tag(&mut self) -> TTLVResult<()>;

    fn write_boolean(&mut self, v: bool) -> TTLVResult<()>;
    fn write_i32(&mut self, v: i32) -> TTLVResult<()>;

    fn write_u32_enumeration(&mut self, v: u32) -> TTLVResult<()>;

    fn write_i64(&mut self, v: i64) -> TTLVResult<()>;
    fn write_i64_datetime(&mut self, v: i64) -> TTLVResult<()>;

    fn write_string(&mut self, v: &str) -> TTLVResult<()>;

    fn write_bytes(&mut self, v: &[u8]) -> TTLVResult<()>;

    // fn write_tag_enum(&mut self, t: Tag) -> TTLVResult<()>;

    fn write_struct_start(&mut self) -> TTLVResult<()>;

    fn begin_inner(&mut self) -> TTLVResult<()>;

    fn close_inner(&mut self) -> TTLVResult<()>;
}

pub trait TtlvSerialize {
    fn serialize(&self, writer: &mut dyn EncodedWriter) -> TTLVResult<()>;
}

pub fn ser_write_integer(writer: &mut dyn EncodedWriter, tag: Tag, v: i32) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_i32(v)
}

pub fn ser_write_integer_attribute(
    writer: &mut dyn EncodedWriter,
    tag: Tag,
    v: i32,
) -> TTLVResult<()> {
    writer.write_tag(Tag::AttributeValue)?;
    writer.set_attribute_tag(tag)?;
    writer.write_i32(v)
}

pub fn ser_write_long_integer(writer: &mut dyn EncodedWriter, tag: Tag, v: i64) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_i64(v)
}

pub fn ser_write_enumeration(writer: &mut dyn EncodedWriter, tag: Tag, v: u32) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    // FIXME: KMIP enumerations are unsigned 4-byte integers but write_i32_enumeration takes i32;
    // values >= 0x8000_0000 will be written sign-extended. All current KMIP enum values fit in
    // the lower 31 bits so this is benign today, but will need fixing when high-value enums land.
    writer.write_u32_enumeration(v)
}

pub fn ser_write_enumeration_typed<T>(
    writer: &mut dyn EncodedWriter,
    tag: Tag,
    v: &T,
) -> TTLVResult<()>
where
    T: ToPrimitive,
{
    ser_write_enumeration(
        writer,
        tag,
        num::ToPrimitive::to_u32(v).ok_or(TTLVError::EnumConvertFailed { tag })?,
    )
}

pub fn ser_write_enumeration_attribute_typed<T>(
    writer: &mut dyn EncodedWriter,
    tag: Tag,
    v: &T,
) -> TTLVResult<()>
where
    T: ToPrimitive,
{
    writer.write_tag(Tag::AttributeValue)?;
    writer.set_attribute_tag(tag)?;
    writer.write_u32_enumeration(
        num::ToPrimitive::to_u32(v).ok_or(TTLVError::EnumConvertFailed { tag })?,
    )
}

pub fn ser_write_boolean(writer: &mut dyn EncodedWriter, tag: Tag, v: bool) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_boolean(v)
}

pub fn ser_write_text_string(writer: &mut dyn EncodedWriter, tag: Tag, v: &str) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_string(v)
}

pub fn ser_write_byte_string(writer: &mut dyn EncodedWriter, tag: Tag, v: &[u8]) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_bytes(v)
}

pub fn ser_write_datetime(
    writer: &mut dyn EncodedWriter,
    tag: Tag,
    v: &chrono::DateTime<chrono::Utc>,
) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_i64_datetime(v.timestamp())
}

pub fn ser_write_structure_begin(writer: &mut dyn EncodedWriter, tag: Tag) -> TTLVResult<()> {
    writer.write_tag(tag)?;
    writer.write_struct_start()?;
    writer.begin_inner()
}

pub fn ser_write_structure_end(writer: &mut dyn EncodedWriter) -> TTLVResult<()> {
    writer.close_inner()
}

#[derive(Debug, PartialEq)]
enum TagWriteState {
    Needed,
    Written,
}

pub struct NestedWriter {
    start_positions: Vec<usize>,
    vec: Vec<u8>,
    state: TagWriteState,
    // tag: Option<Tag>,
}

impl NestedWriter {
    pub fn new() -> NestedWriter {
        NestedWriter {
            start_positions: Vec::new(),
            vec: Vec::new(),
            state: TagWriteState::Needed,
            // tag: None,
        }
    }

    fn assert_tag_written(&mut self) {
        assert_eq!(self.state, TagWriteState::Written);
        self.state = TagWriteState::Needed;
    }
}

impl EncodedWriter for NestedWriter {
    fn get_vector(self) -> Vec<u8> {
        self.vec
    }

    // fn get_tag(&self) -> Option<Tag> {
    //     self.tag
    // }

    // fn set_tag(&mut self, tag: Tag) {
    //     self.tag = Some(tag)
    // }

    // fn write_optional_tag(&mut self) -> TTLVResult<()> {
    //     if let Some(t) = &self.tag {
    //         write_tag_enum(&mut self.vec, *t)?;
    //     }

    //     Ok(())
    // }

    fn write_tag(&mut self, tag: Tag) -> TTLVResult<()> {
        assert_eq!(self.state, TagWriteState::Needed);
        write_tag_enum(&mut self.vec, tag)?;

        self.state = TagWriteState::Written;

        Ok(())
    }

    fn set_attribute_tag(&mut self, _tag: Tag) -> TTLVResult<()> {
        // Ignore, only for xml writer
        Ok(())
    }

    // fn flush_tag(&mut self) {
    //     if let Some(t) = &self.tag {
    //         write_tag_enum(&mut self.vec, *t);
    //     }
    //     self.tag = None;
    // }

    fn begin_inner(&mut self) -> TTLVResult<()> {
        //println!("write_innter");
        // println!(" begin inner");
        let pos = self.vec.len();
        self.vec
            .write_u32::<BigEndian>(0)
            .map_err(|error| TTLVError::BadWrite { count: 4, error })?;
        self.start_positions.push(pos);

        // self.tag = None;
        Ok(())
    }

    fn close_inner(&mut self) -> TTLVResult<()> {
        // println!(" close inner");
        let current_pos = self.vec.len();
        let start_pos = self.start_positions.pop().unwrap();
        // offset by 4
        let len = current_pos - start_pos - 4;

        let mut v1: Vec<u8> = Vec::new();
        v1.write_u32::<BigEndian>(len as u32)
            .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

        // for i in 0..4 {
        //     self.vec[start_pos + i] = v1[i];
        // }
        self.vec[start_pos..(4 + start_pos)].clone_from_slice(&v1[..4]);

        // self.tag = None;

        Ok(())
    }

    fn write_boolean(&mut self, v: bool) -> TTLVResult<()> {
        self.assert_tag_written();
        write_boolean(&mut self.vec, v)
    }

    fn write_i32(&mut self, v: i32) -> TTLVResult<()> {
        self.assert_tag_written();

        write_i32(&mut self.vec, v)
    }

    fn write_u32_enumeration(&mut self, v: u32) -> TTLVResult<()> {
        self.assert_tag_written();
        write_enumeration(&mut self.vec, v)
    }

    fn write_i64(&mut self, v: i64) -> TTLVResult<()> {
        self.assert_tag_written();
        write_i64(&mut self.vec, v)
    }

    fn write_i64_datetime(&mut self, v: i64) -> TTLVResult<()> {
        self.assert_tag_written();
        write_i64_datetime(&mut self.vec, v)
    }

    fn write_string(&mut self, v: &str) -> TTLVResult<()> {
        self.assert_tag_written();
        write_string(&mut self.vec, v)
    }

    fn write_bytes(&mut self, v: &[u8]) -> TTLVResult<()> {
        self.assert_tag_written();
        write_bytes(&mut self.vec, v)
    }

    // fn write_tag_enum(&mut self, t: Tag) -> TTLVResult<()> {
    //     self.tag = None;
    //     write_tag_enum(&mut self.vec, t)
    // }

    fn write_struct_start(&mut self) -> TTLVResult<()> {
        self.assert_tag_written();
        write_struct_start(&mut self.vec)
    }
}

impl Write for NestedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.vec.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use chrono::{TimeZone, Utc};

    use crate::{
        kmip_enums::Tag,
        ser::{EncodedWriter, NestedWriter},
    };

    #[test]
    fn test_primitive_serialize() {
        // An Integer containing the decimal value 8:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_i32(8).unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        // A Long Integer containing the decimal value 123456789000000000:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_i64(123456789000000000).unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x08, 0x01, 0xB6, 0x9B, 0x4B, 0xA5, 0x74,
                0x92, 0x00,
            ]
        );

        // A Big Integer containing the decimal value 1234567890000000000000000000:
        // let bytes = [
        //     0x42, 0x00, 0x20, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFD,
        //     0x35, 0xEB, 0x6B, 0xC2, 0xDF, 0x46, 0x18, 0x08, 0x00, 0x00,
        // ];
        // to_print(&bytes);

        // An Enumeration with value 255:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_u32_enumeration(255).unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        // A Boolean with the value True:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_boolean(true).unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        );

        // A Text String with the value "Hello World":
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_string("Hello World").unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x0B, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
                0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );

        // A Byte String with the value { 0x01, 0x02, 0x03 }:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_bytes(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x08, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        // A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer
            .write_i64_datetime(
                Utc.with_ymd_and_hms(2008, 3, 14, 11, 56, 40)
                    .unwrap()
                    .timestamp(),
            )
            .unwrap();
        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x47, 0xDA,
                0x67, 0xF8,
            ]
        );

        // An Interval, containing the value for 10 days:
        // let mut writer = NestedWriter::new();
        // writer.write_tag(Tag::CompromiseDate).unwrap();
        // writer.write_i64(123456789000000000).unwrap();
        // assert_eq!(
        //     writer.get_vector(),
        //     [
        //         0x42, 0x00, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0D, 0x2F, 0x00, 0x00,
        // 0x00,         0x00, 0x00,
        //     ]
        // );
        //

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255,
        // having tags 420004 and 420005 respectively:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_struct_start().unwrap();
        writer.begin_inner().unwrap();
        writer
            .write_tag(Tag::ApplicationSpecificInformation)
            .unwrap();
        writer.write_u32_enumeration(254).unwrap();
        writer.write_tag(Tag::ArchiveDate).unwrap();
        writer.write_i32(255).unwrap();
        writer.close_inner().unwrap();

        assert_eq!(
            writer.get_vector(),
            [
                0x42, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x04, 0x05, 0x00, 0x00,
                0x00, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x05, 0x02,
                0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }
}
