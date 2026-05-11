use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

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

pub fn write_enumeration(writer: &mut dyn Write, value: i32) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::Enumeration as u8)
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

// struct CountingWriter<'a> {
//     //&Writer : writer,
//     count : usize,
//     writer : &'a mut dyn Write,
// }

// impl<'a, W : EncodedWriter> Write for CountingWriter<'a, W> {

//    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//        let ret = self.writer.write(buf);

//         if let Ok(s) = ret  {
//             self.count += s;
//         }

//        return ret;
//    }

//     fn flush(&mut self) -> std::io::Result<()> {
//         return Ok(())
//     }
// }

// pub struct StructWriter<'a> {
//     vec : Vec<u8>,
//     orig_writer : &'a mut dyn Write,
// }

// impl<'a, W : EncodedWriter>  StructWriter<'a, W> {
//     pub fn new(writer : &'a mut dyn Write) -> StructWriter {
//         StructWriter {
//             vec :  Vec::new(),
//             orig_writer : writer,
//         }
//     }

//     fn get_writer(&mut self) -> &dyn Write {
//         return &self.vec;
//     }
// }

// impl<'a, W : EncodedWriter> Drop for StructWriter<'a, W> {

//     fn drop(&mut self) {
//         self.orig_writer.write_u32::<BigEndian>(self.vec.len() as u32).unwrap();

//         self.orig_writer.write(self.vec.as_slice()).unwrap();
//     }
// }

// fn begin_struct(writer : &mut dyn Write, value: i32 ) -> StructWriter {
//     //write_tag(writer, tag);
//     writer.write_u8(ItemType::Structure as u8).unwrap();

//     return StructWriter::new(writer);
// }

pub fn write_struct_start(writer: &mut dyn Write) -> TTLVResult<()> {
    writer
        .write_u8(ItemType::Structure as u8)
        .map_err(|error| TTLVError::BadWrite { count: 1, error })
}

pub trait EncodedWriter {
    fn new() -> Self;

    fn get_vector(self) -> Vec<u8>;

    fn write_tag(&mut self, tag: Tag) -> TTLVResult<()>;

    // fn get_tag(&self) -> Option<Tag>;
    // fn set_tag(&mut self, tag: Tag);

    // fn write_optional_tag(&mut self) -> TTLVResult<()>;

    fn write_boolean(&mut self, v: bool) -> TTLVResult<()>;
    fn write_i32(&mut self, v: i32) -> TTLVResult<()>;

    fn write_i32_enumeration(&mut self, v: i32) -> TTLVResult<()>;

    fn write_i64(&mut self, v: i64) -> TTLVResult<()>;
    fn write_i64_datetime(&mut self, v: i64) -> TTLVResult<()>;

    fn write_string(&mut self, v: &str) -> TTLVResult<()>;

    fn write_bytes(&mut self, v: &[u8]) -> TTLVResult<()>;

    // fn write_tag_enum(&mut self, t: Tag) -> TTLVResult<()>;

    fn write_struct_start(&mut self) -> TTLVResult<()>;

    fn begin_inner(&mut self) -> TTLVResult<()>;

    fn close_inner(&mut self) -> TTLVResult<()>;
}

#[derive(Debug, PartialEq)]
enum TagWriteState {
    Needed,
    Written,
}

struct NestedWriter {
    start_positions: Vec<usize>,
    vec: Vec<u8>,
    state: TagWriteState,
    // tag: Option<Tag>,
}

impl NestedWriter {
    fn assert_tag_written(&mut self) {
        assert_eq!(self.state, TagWriteState::Written);
        self.state = TagWriteState::Needed;
    }
}
impl EncodedWriter for NestedWriter {
    fn new() -> NestedWriter {
        NestedWriter {
            start_positions: Vec::new(),
            vec: Vec::new(),
            state: TagWriteState::Needed,
            // tag: None,
        }
    }

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

    fn write_i32_enumeration(&mut self, v: i32) -> TTLVResult<()> {
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
    use std::io::Write;

    use chrono::{DateTime, TimeZone, Utc};

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
        writer.write_i32_enumeration(255).unwrap();
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
        //         0x42, 0x00, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0D, 0x2F, 0x00, 0x00, 0x00,
        //         0x00, 0x00,
        //     ]
        // );
        //

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags 420004 and 420005 respectively:
        let mut writer = NestedWriter::new();
        writer.write_tag(Tag::CompromiseDate).unwrap();
        writer.write_struct_start().unwrap();
        writer.begin_inner().unwrap();
        writer
            .write_tag(Tag::ApplicationSpecificInformation)
            .unwrap();
        writer.write_i32_enumeration(254).unwrap();
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

        // to_print(&bytes);
    }

    // use std::rc::Rc;

    // use crate::{EnumResolver, TTLVError, Tag, chrono::TimeZone};
    // use chrono::Utc;

    // //use pretty_hex::hex_dump;
    // use crate::de::to_print;
    // use pretty_hex::PrettyHex;

    // use crate::my_date_format;
    // use crate::ser::to_bytes;

    // struct TestEnumResolver;

    // impl EnumResolver for TestEnumResolver {
    //     fn resolve_enum(&self, _name: &str, _value: i32) -> Result<String, TTLVError> {
    //         unimplemented! {}
    //     }
    //     fn resolve_enum_str(
    //         &self,
    //         _tag: crate::kmip_enums::Tag,
    //         _value: &str,
    //     ) -> std::result::Result<i32, TTLVError> {
    //         unimplemented! {}
    //     }

    //     fn to_string(&self, _tag: Tag, _value: i32) -> std::result::Result<String, TTLVError> {
    //         unimplemented!();
    //     }
    // }

    // #[test]
    // fn test_struct() {
    //     #[derive(Debug)]
    //     struct RequestHeader {
    //         pub protocol_version_major: i32,

    //         pub protocol_version_minor: i32,

    //         batch_order_option: Option<i32>,
    //         // Option::None - serializes as serialize_none()
    //         // TODO: Other fields are optional
    //         batch_count: i32,
    //     }

    //     let a = RequestHeader {
    //         protocol_version_major: 1,
    //         protocol_version_minor: 2,
    //         batch_order_option: None,
    //         batch_count: 3,
    //     };

    //     // let v = to_bytes(&a, r).unwrap();

    //     // print!("Dump of bytes {:?}", v.hex_dump());

    //     // to_print(v.as_slice());

    //     let good = vec![
    //         0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00,
    //         0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02,
    //         0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
    //         0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    //     ];

    //     assert_eq!(v.len(), 56);

    //     assert_eq!(v, good);
    // }

    // #[test]
    // fn test_struct_nested() {
    //     #[derive(Serialize, Debug)]
    //     struct RequestHeader {
    //         #[serde(rename = "ProtocolVersionMajor")]
    //         protocol_version_major: i32,
    //         #[serde(rename = "BatchCount")]
    //         batch_count: i32,
    //     }

    //     #[derive(Serialize, Debug)]
    //     struct RequestMessage {
    //         #[serde(rename = "RequestHeader")]
    //         request_header: RequestHeader,

    //         #[serde(rename = "UniqueIdentifier")]
    //         unique_identifier: String,
    //     }

    //     let a = RequestMessage {
    //         request_header: RequestHeader {
    //             protocol_version_major: 3,
    //             batch_count: 4,
    //         },
    //         unique_identifier: String::new(),
    //     };

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", v.hex_dump());

    //     to_print(v.as_slice());

    //     let good = vec![
    //         66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0,
    //         0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7,
    //         0, 0, 0, 0,
    //     ];

    //     assert_eq!(v.len(), 56);

    //     assert_eq!(v, good);
    // }

    // #[test]
    // fn test_struct_nested2() {
    //     #[derive(Serialize, Debug)]
    //     struct ObjectType {
    //         #[serde(rename = "UniqueIdentifier")]
    //         unique_identifier: String,
    //     }

    //     #[derive(Serialize, Debug)]
    //     struct RequestHeader {
    //         #[serde(rename = "ProtocolVersionMinor")]
    //         protocol_version_minor: ObjectType,

    //         #[serde(rename = "BatchCount")]
    //         batch_count: i32,
    //     }

    //     let a = RequestHeader {
    //         protocol_version_minor: ObjectType {
    //             unique_identifier: String::new(),
    //         },
    //         batch_count: 3,
    //     };

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", v.hex_dump());

    //     to_print(v.as_slice());

    //     let good = vec![
    //         66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 107, 1, 0, 0, 0, 8, 66, 0, 148, 7, 0, 0, 0, 0, 66,
    //         0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0,
    //     ];

    //     assert_eq!(v.len(), 40);

    //     assert_eq!(v, good);
    // }

    // #[test]
    // fn test_struct_types() {
    //     #[derive(Serialize, Debug)]
    //     struct RequestHeader<'a> {
    //         #[serde(rename = "ProtocolVersionMajor")]
    //         protocol_version_major: String,

    //         #[serde(with = "serde_bytes", rename = "ProtocolVersionMinor")]
    //         protocol_version_minor: &'a [u8],

    //         #[serde(rename = "BatchCount")]
    //         batch_count: i64,
    //     }

    //     let v = vec![0x55, 0x66, 0x77];
    //     let a = RequestHeader {
    //         protocol_version_major: String::new(),
    //         protocol_version_minor: v.as_slice(),
    //         batch_count: 3,
    //     };

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", v.hex_dump());

    //     to_print(v.as_slice());
    //     assert_eq!(v.len(), 48);
    // }

    // #[test]
    // fn test_struct2() {
    //     #[derive(Serialize, Debug)]
    //     #[serde(tag = "Operation", content = "BatchItem")]
    //     enum CRTCoefficient {
    //         Attribute(Vec<u8>),
    //         CertificateRequest(String),
    //     }

    //     let a = CRTCoefficient::CertificateRequest(String::new());
    //     let _b = CRTCoefficient::Attribute(vec![0x1]);

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", v.hex_dump());

    //     to_print(v.as_slice());

    //     let good = vec![
    //         66, 0, 39, 1, 0, 0, 0, 40, 66, 0, 92, 7, 0, 0, 0, 18, 67, 101, 114, 116, 105, 102, 105,
    //         99, 97, 116, 101, 82, 101, 113, 117, 101, 115, 116, 0, 0, 0, 0, 0, 0, 66, 0, 15, 7, 0,
    //         0, 0, 0,
    //     ];

    //     assert_eq!(v.len(), 48);

    //     assert_eq!(v, good);
    // }

    // #[test]
    // fn test_struct3() {
    //     #[derive(Serialize, Debug)]
    //     struct CRTCoefficient {
    //         #[serde(rename = "BatchCount")]
    //         batch_count: Vec<i32>,
    //     }

    //     let a = CRTCoefficient {
    //         batch_count: vec![0x66, 0x77, 0x88],
    //     };

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", v.hex_dump());

    //     to_print(v.as_slice());

    //     let good = vec![
    //         66, 0, 39, 1, 0, 0, 0, 48, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 102, 0, 0, 0, 0, 66, 0,
    //         13, 2, 0, 0, 0, 4, 0, 0, 0, 119, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 136, 0,
    //         0, 0, 0,
    //     ];

    //     assert_eq!(v.len(), 56);

    //     assert_eq!(v, good);
    // }

    // #[test]
    // fn test_datetime() {
    //     #[derive(Serialize, Debug)]
    //     struct CRTCoefficient {
    //         #[serde(with = "my_date_format", rename = "BatchCount")]
    //         batch_count: chrono::DateTime<Utc>,
    //     }

    //     let a = CRTCoefficient {
    //         batch_count: chrono::Utc.timestamp(123456, 0),
    //     };

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", v.hex_dump());

    //     to_print(v.as_slice());

    //     let good = vec![
    //         66, 0, 39, 1, 0, 0, 0, 16, 66, 0, 13, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 1, 226, 64,
    //     ];

    //     assert_eq!(v.len(), 24);

    //     assert_eq!(v, good);
    // }
}
