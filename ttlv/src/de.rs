use std::io::Cursor;
use std::io::Read;

use std::string::ToString;

use byteorder::{BigEndian, ReadBytesExt};
use pretty_hex::*;

use crate::error::TTLVError;
use crate::kmip_enums::*;

type TTLVResult<T> = std::result::Result<T, TTLVError>;

fn compute_padding(len: usize) -> usize {
    if len % 8 == 0 {
        return len;
    }

    let padding = 8 - (len % 8);
    len + padding
}

pub fn read_tag(reader: &mut dyn Read) -> TTLVResult<u32> {
    let v = reader
        .read_u8()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    // println!("Read Tag: {v}");

    if v != 0x42 {
        return Err(TTLVError::InvalidTagPrefix { byte: v });
    }

    let tag = reader
        .read_u16::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 2, error })?;

    Ok(0x420000 + tag as u32)
}

fn read_tag_enum(reader: &mut dyn Read) -> TTLVResult<Tag> {
    let tag_u32 = read_tag(reader)?;

    if let Some(t) = num::FromPrimitive::from_u32(tag_u32) {
        return Ok(t);
    }

    Err(TTLVError::InvalidTag { tag: tag_u32 })
}

pub fn read_len(reader: &mut dyn Read) -> TTLVResult<u32> {
    reader
        .read_u32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 4, error })
}

pub fn read_type(reader: &mut dyn Read) -> TTLVResult<ItemType> {
    let i = reader
        .read_u8()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    // println!("Read Type {:?}", i);

    if let Some(t) = num::FromPrimitive::from_u8(i) {
        return Ok(t);
    }

    Err(TTLVError::InvalidType { byte: i })
}

fn check_type_len(actual: u32, expected: u32, context: &str) -> TTLVResult<()> {
    if actual != expected {
        return Err(TTLVError::InvalidTypeLength {
            actual,
            expected,
            context: context.to_string(),
        });
    }

    Ok(())
}

fn read_enumeration(reader: &mut dyn Read) -> TTLVResult<u32> {
    let len = read_len(reader)?;

    // Work around a bug in a particular implementation that is serializing Enumeration as 8 bytes, sigh. They are otherwise writing it correctly though
    if len == 8 {
        // Ignore incorrect length for now, sadness
    } else {
        check_type_len(len, 4, "Enumeration")?;
    }

    let v = reader
        .read_u32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 4, error })?;

    // swallow the padding
    // TODO - speed up
    reader
        .read_i32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 4, error })?;

    //println!("Read i32: {:?}", v);
    Ok(v)
}

fn read_i32(reader: &mut dyn Read) -> TTLVResult<i32> {
    let len = read_len(reader)?;

    // Work around a bug in a particular implementation that is serializing Integer as 8 bytes, sigh. They are otherwise writing it correctly though
    if len == 8 {
        // Ignore incorrect length for now, sadness
    } else {
        check_type_len(len, 4, "Integer")?;
    }

    let v = reader
        .read_i32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    // swallow the padding
    // TODO - speed up
    reader
        .read_i32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    //println!("Read i32: {:?}", v);
    Ok(v)
}

fn read_boolean(reader: &mut dyn Read) -> TTLVResult<bool> {
    let len = read_len(reader)?;

    check_type_len(len, 8, "boolean")?;

    let v = reader
        .read_u64::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    Ok(v != 0)
}

fn read_u32_interval(reader: &mut dyn Read) -> TTLVResult<u32> {
    let len = read_len(reader)?;

    check_type_len(len, 4, "Interval")?;

    let v = reader
        .read_u32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    // swallow the padding
    // TODO - speed up
    reader
        .read_i32::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;

    //println!("Read i32: {:?}", v);
    Ok(v)
}

fn read_i64(reader: &mut dyn Read) -> TTLVResult<i64> {
    let len = read_len(reader)?;
    check_type_len(len, 8, "LongInteger")?;

    let v = reader
        .read_i64::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;
    //println!("Read i64: {:?}", v);
    Ok(v)
}

fn read_datetime_i64(reader: &mut dyn Read) -> TTLVResult<i64> {
    let len = read_len(reader)?;
    check_type_len(len, 8, "DateTime")?;

    let v = reader
        .read_i64::<BigEndian>()
        .map_err(|error| TTLVError::BadRead { count: 1, error })?;
    //println!("Read DateTime: {:?}", v);
    Ok(v)
}

fn read_string(reader: &mut dyn Read) -> TTLVResult<String> {
    let len = read_len(reader)?;

    let padding = compute_padding(len as usize);

    // TODO - better protection against bogus sizes
    assert!(padding < 32 * 1024);

    let mut v: Vec<u8> = Vec::new();
    v.resize(padding as usize, 0);

    reader
        .read(v.as_mut_slice())
        .map_err(|error| TTLVError::BadRead {
            count: v.len(),
            error,
        })?;

    v.resize(len as usize, 0);

    let s = String::from_utf8(v).map_err(|_| TTLVError::BadString)?;

    //println!("Read string: {:?}", s);

    Ok(s)
}

fn read_bytes(reader: &mut dyn Read) -> TTLVResult<Vec<u8>> {
    let len = read_len(reader)?;

    let padding = compute_padding(len as usize);

    // TODO - better protection against bogus sizes
    assert!(padding < 32 * 1024);

    let mut v: Vec<u8> = Vec::new();
    v.resize(padding as usize, 0);

    reader
        .read(v.as_mut_slice())
        .map_err(|error| TTLVError::BadRead {
            count: v.len(),
            error,
        })?;

    v.resize(len as usize, 0);

    Ok(v)
}

fn read_big_integer(reader: &mut dyn Read) -> TTLVResult<BigInteger> {
    let len = read_len(reader)?;

    let padding = compute_padding(len as usize);

    // TODO - better protection against bogus sizes
    assert!(padding < 32 * 1024);

    let mut v: Vec<u8> = Vec::new();
    v.resize(padding as usize, 0);

    reader
        .read(v.as_mut_slice())
        .map_err(|error| TTLVError::BadRead {
            count: v.len(),
            error,
        })?;

    v.resize(len as usize, 0);

    Ok(BigInteger { bytes: v })
}

pub fn read_struct(reader: &mut dyn Read) -> TTLVResult<Vec<u8>> {
    let len = read_len(reader)?;

    let mut v: Vec<u8> = Vec::new();
    v.resize(len as usize, 0);

    reader
        .read(v.as_mut_slice())
        .map_err(|error| TTLVError::BadRead {
            count: v.len(),
            error,
        })?;

    Ok(v)
}

fn read_value(reader: &mut dyn Read) -> TTLVResult<Value> {
    let tag = read_tag_enum(reader)?;
    let ttlv_type = read_type(reader)?;
    Ok(Value {
        tag,
        value: match ttlv_type {
            ItemType::Structure => {
                // TODO - figure out where to finish
                let length = read_len(reader)?;
                ValueType::StructureBegin(length)
            }
            ItemType::Integer => ValueType::Integer(read_i32(reader)?),
            ItemType::LongInteger => ValueType::LongInteger(read_i64(reader)?),
            ItemType::BigInteger => todo!(),
            ItemType::Enumeration => ValueType::Enumeration(read_enumeration(reader)?),
            ItemType::Boolean => ValueType::Boolean(read_boolean(reader)?),
            ItemType::TextString => ValueType::TextString(read_string(reader)?),
            ItemType::ByteString => ValueType::ByteString(read_bytes(reader)?),
            ItemType::DateTime => ValueType::DateTime(read_datetime_i64(reader)?),
            ItemType::Interval => ValueType::Interval(read_u32_interval(reader)?),
        },
    })
}

/////////////////////////////
struct IndentPrinter {
    indent: usize,
}

impl IndentPrinter {
    fn new() -> IndentPrinter {
        IndentPrinter { indent: 0 }
    }

    fn indent(&mut self) {
        self.indent += 1;
    }

    fn unindent(&mut self) {
        self.indent -= 1;
    }

    fn print(&self, msg: &str) {
        // for _ in 0..self.indent {
        //     std::io::stdout().write(" ".as_bytes());
        // }
        // std::io::stdout().write(msg.as_bytes());
        let space = " ".repeat(self.indent * 4);
        // Use println! to play nicely with unit tests
        println!("{}{}", space, msg);
    }
}

pub fn to_print(buf: &[u8]) {
    let mut printer: IndentPrinter = IndentPrinter::new();
    if let Err(r) = to_print_int(&mut printer, buf) {
        println!("Erroring in to_print: {:?}", r);
    }
}

fn to_print_int(printer: &mut IndentPrinter, buf: &[u8]) -> TTLVResult<()> {
    let mut cur = Cursor::new(buf);

    while cur.position() < buf.len() as u64 {
        let tag = read_tag_enum(&mut cur)?;

        let item_type = read_type(&mut cur)?;

        match item_type {
            ItemType::Integer => {
                let v = read_i32(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
            ItemType::LongInteger => {
                let v = read_i64(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
            ItemType::DateTime => {
                // TODO:
                let v = read_i64(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
            ItemType::Enumeration => {
                let v = read_i32(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
            ItemType::TextString => {
                let v = read_string(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
            ItemType::ByteString => {
                let v = read_bytes(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag,
                    item_type,
                    v.hex_dump()
                ));
            }
            ItemType::Structure => {
                let v = read_struct(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Structure {{",
                    tag, item_type
                ));
                printer.indent();
                to_print_int(printer, v.as_slice())?;
                printer.unindent();
                printer.print("}}");
            }
            ItemType::Boolean => {
                let v = read_i64(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag,
                    item_type,
                    v != 0
                ));
            }
            ItemType::Interval => {
                let v = read_u32_interval(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
            ItemType::BigInteger => {
                let v = read_big_integer(&mut cur)?;
                printer.print(&format!(
                    "Tag {:?} - Type {:?} - Value {:?}",
                    tag, item_type, v
                ));
            }
        }
    }

    Ok(())
}

//////////////////

pub struct Reader<'a> {
    len: u64,
    cur: Cursor<&'a [u8]>,
    end_positions: Vec<(Tag, u64)>,
    // buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            len: buf.len() as u64,
            cur: Cursor::new(buf),
            end_positions: Vec::new(),
        }
    }

    pub fn read(&mut self) -> Option<TTLVResult<Value>> {
        let position = self.cur.position();
        // println!("position: {position}");

        // Check if the current position would be the end of a structure
        // If it is the end, generate a Value that indicates the struct has ended
        if !self.end_positions.is_empty()
            && self.end_positions[self.end_positions.len() - 1].1 == position
        {
            let end = self.end_positions[self.end_positions.len() - 1];
            self.end_positions.pop();

            return Some(Ok(Value {
                tag: end.0,
                value: ValueType::StructureEnd,
            }));
        }

        // If we hit EOF, return None
        if position == self.len {
            return None;
        }

        let value = read_value(&mut self.cur);
        match value {
            Err(_) => Some(value),
            Ok(x) => {
                if let ValueType::StructureBegin(struct_length) = x.value {
                    let position = self.cur.position();

                    // println!("end position: {0}", position + struct_length as u64);

                    self.end_positions
                        .push((x.tag, position + struct_length as u64));
                };

                Some(Ok(x))
            }
        }
    }
}

pub fn expect_structure_begin(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<()> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag { expected: expected_tag, actual: token.tag });
    }
    match token.value {
        ValueType::StructureBegin(_) => Ok(()),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_structure_end(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<()> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag { expected: expected_tag, actual: token.tag });
    }
    match token.value {
        ValueType::StructureEnd => Ok(()),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_integer(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<i32> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag { expected: expected_tag, actual: token.tag });
    }
    match token.value {
        ValueType::Integer(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_text_string(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<String> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag { expected: expected_tag, actual: token.tag });
    }
    match token.value {
        ValueType::TextString(s) => Ok(s),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

fn read_to_end(buf: &[u8]) -> TTLVResult<Vec<Value>> {
    let mut reader = Reader::new(buf);

    let mut tokens = Vec::new();

    loop {
        let token_opt = reader.read();
        match token_opt {
            None => break,
            Some(token) => {
                tokens.push(token?);
            }
        }
    }

    Ok(tokens)
}

// pub trait EnumResolver {
//     fn resolve_enum(&self, name: &str, value: i32) -> TTLVResult<String>;
//     fn resolve_enum_str(&self, tag: Tag, value: &str) -> std::result::Result<i32, TTLVError>;
//     fn to_string(&self, tag: Tag, value: i32) -> std::result::Result<String, TTLVError>;
// }

// pub trait EncodingReader<'a> {
//     fn new(buf: &'a [u8]) -> Self;

//     fn begin_inner_or_more(&mut self) -> TTLVResult<()>;

//     fn begin_inner_skip(&mut self) -> TTLVResult<()>;

//     fn close_inner(&mut self);

//     fn is_empty(&mut self) -> TTLVResult<bool>;

//     fn is_level_empty(&self) -> bool;

//     fn read_type(&mut self) -> TTLVResult<ItemType>;

//     fn read_type_and_check(&mut self, expected: ItemType) -> TTLVResult<()>;

//     fn is_tag(&self) -> bool;

//     fn get_tag(&self) -> Tag;

//     fn read_tag(&mut self) -> TTLVResult<Tag>;

//     fn peek_tag(&mut self) -> TTLVResult<Tag>;

//     fn reverse_tag(&mut self);

//     fn read_i32(&mut self, enum_resolver: &'a dyn EnumResolver) -> TTLVResult<i32>;

//     fn read_enumeration(&mut self, enum_resolver: &'a dyn EnumResolver) -> TTLVResult<i32>;

//     fn read_i64(&mut self) -> TTLVResult<i64>;

//     fn read_datetime_i64(&mut self) -> TTLVResult<i64>;

//     fn read_string(&mut self) -> TTLVResult<String>;

//     fn read_bytes(&mut self) -> TTLVResult<Vec<u8>>;
// }

// #[derive(PartialEq, Debug)]
// enum ReaderState {
//     Tag,
//     Type,
//     LengthValue,
// }

// struct NestedReader<'a> {
//     end_positions: Vec<u64>,
//     cur: Cursor<&'a [u8]>,
//     state: ReaderState,
//     tag: Option<Tag>,
// }

// impl<'a> EncodingReader<'a> for NestedReader<'a> {
//     fn new(buf: &'a [u8]) -> NestedReader<'a> {
//         NestedReader {
//             end_positions: Vec::new(),
//             cur: Cursor::new(buf),
//             state: ReaderState::Tag,
//             tag: None,
//         }
//     }

//     fn begin_inner_or_more(&mut self) -> TTLVResult<()> {
//         if self.state == ReaderState::Tag {
//             let _t = read_tag_enum(&mut self.cur)?;

//             //println!("read_inner: {:?} - {:?}", t, self.cur.position());
//             self.state = ReaderState::Type;
//         }

//         if self.state == ReaderState::Type {
//             self.read_type_and_check(ItemType::Structure)?;
//             self.state = ReaderState::LengthValue;
//         }

//         self.begin_inner_skip()
//     }

//     fn begin_inner_skip(&mut self) -> TTLVResult<()> {
//         assert_eq!(self.state, ReaderState::LengthValue);

//         let len = read_len(&mut self.cur)? as u64;
//         //println!(" read_inner_skip: {:?} - {:?}", len, self.cur.position());
//         self.end_positions.push(self.cur.position() + len);
//         self.state = ReaderState::Tag;
//         Ok(())
//     }

//     fn close_inner(&mut self) {
//         //println!(" close_inner");
//         self.end_positions.pop().unwrap();
//     }

//     fn is_empty(&mut self) -> TTLVResult<bool> {
//         if self.end_positions.is_empty() {
//             return Ok(true);
//         }
//         // println!(
//         //     "cmp1 {:?} == {:?}",
//         //     *(self.end_positions.last().unwrap()),
//         //     self.cur.position()
//         // );
//         Ok(self.is_level_empty())
//     }

//     fn is_level_empty(&self) -> bool {
//         *(self.end_positions.last().unwrap()) == self.cur.position()
//     }

//     fn read_type(&mut self) -> TTLVResult<ItemType> {
//         assert_eq!(self.state, ReaderState::Type);
//         self.state = ReaderState::LengthValue;
//         read_type(&mut self.cur)
//     }

//     fn read_type_and_check(&mut self, expected: ItemType) -> TTLVResult<()> {
//         assert_eq!(self.state, ReaderState::Type);
//         self.state = ReaderState::LengthValue;
//         let t = read_type(&mut self.cur)?;
//         if t != expected {
//             return Err(TTLVError::UnexpectedType {
//                 actual: t,
//                 expected,
//             });
//         }

//         Ok(())
//     }

//     fn is_tag(&self) -> bool {
//         self.state == ReaderState::Tag
//     }

//     fn get_tag(&self) -> Tag {
//         self.tag.unwrap()
//     }

//     fn read_tag(&mut self) -> TTLVResult<Tag> {
//         assert_eq!(self.state, ReaderState::Tag);
//         self.state = ReaderState::Type;
//         let t = read_tag_enum(&mut self.cur)?;
//         self.tag = Some(t);
//         Ok(t)
//     }

//     fn peek_tag(&mut self) -> TTLVResult<Tag> {
//         assert_eq!(self.state, ReaderState::Tag);
//         let pos = self.cur.position();
//         let tag = read_tag_enum(&mut self.cur)?;
//         self.cur.set_position(pos);
//         Ok(tag)
//     }

//     fn reverse_tag(&mut self) {
//         assert_eq!(self.state, ReaderState::Type);
//         self.state = ReaderState::Tag;
//         let pos = self.cur.position();
//         self.cur.set_position(pos - 3);
//     }

//     fn read_i32(&mut self, _enum_resolver: &'a dyn EnumResolver) -> TTLVResult<i32> {
//         assert_eq!(self.state, ReaderState::LengthValue);
//         self.state = ReaderState::Tag;
//         read_i32(&mut self.cur)
//     }

//     fn read_enumeration(&mut self, _enum_resolver: &'a dyn EnumResolver) -> TTLVResult<i32> {
//         assert_eq!(self.state, ReaderState::LengthValue);
//         self.state = ReaderState::Tag;
//         read_enumeration(&mut self.cur)
//     }

//     fn read_i64(&mut self) -> TTLVResult<i64> {
//         assert_eq!(self.state, ReaderState::LengthValue);
//         self.state = ReaderState::Tag;
//         read_i64(&mut self.cur)
//     }

//     fn read_datetime_i64(&mut self) -> TTLVResult<i64> {
//         assert_eq!(self.state, ReaderState::LengthValue);
//         self.state = ReaderState::Tag;
//         read_datetime_i64(&mut self.cur)
//     }

//     // fn read_string_and_more(&mut self) -> TTLVResult<String> {
//     //     if self.state == ReaderState::Tag {
//     //         self.read_tag();
//     //     }
//     //     assert_eq!(self.read_type(), ItemType::TextString);
//     //     assert_eq!(self.state, ReaderState::LengthValue);
//     //     self.state = ReaderState::Tag;
//     //     read_string(&mut self.cur)
//     // }

//     fn read_string(&mut self) -> TTLVResult<String> {
//         assert_eq!(self.state, ReaderState::LengthValue);
//         self.state = ReaderState::Tag;
//         read_string(&mut self.cur)
//     }

//     fn read_bytes(&mut self) -> TTLVResult<Vec<u8>> {
//         assert_eq!(self.state, ReaderState::LengthValue);
//         self.state = ReaderState::Tag;
//         read_bytes(&mut self.cur)
//     }
// }

// impl<'a> Read for NestedReader<'a> {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         self.cur.read(buf)
//     }
// }

////////////////////

#[cfg(test)]
mod tests {
    use crate::{
        de::{expect_integer, expect_structure_begin, expect_structure_end, expect_text_string, read_to_end, to_print, Reader},
        error::TTLVError,
        kmip_enums::{Tag, Value, ValueType},
    };

    struct RequestHeader {
        protocol_version_major: i32,
        batch_count: i32,
    }

    struct RequestMessage {
        request_header: RequestHeader,
        unique_identifier: String,
    }

    fn parse_request_header(reader: &mut Reader<'_>) -> Result<RequestHeader, TTLVError> {
        expect_structure_begin(reader, Tag::RequestHeader)?;
        let protocol_version_major = expect_integer(reader, Tag::ProtocolVersionMajor)?;
        let batch_count = expect_integer(reader, Tag::BatchCount)?;
        expect_structure_end(reader, Tag::RequestHeader)?;
        Ok(RequestHeader { protocol_version_major, batch_count })
    }

    fn parse_request_message(reader: &mut Reader<'_>) -> Result<RequestMessage, TTLVError> {
        expect_structure_begin(reader, Tag::RequestMessage)?;
        let request_header = parse_request_header(reader)?;
        let unique_identifier = expect_text_string(reader, Tag::UniqueIdentifier)?;
        expect_structure_end(reader, Tag::RequestMessage)?;
        Ok(RequestMessage { request_header, unique_identifier })
    }

    #[test]
    fn test_primitive_to_print() {
        // An Integer containing the decimal value 8:
        let bytes = [
            0x42, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x00,
        ];
        to_print(&bytes);

        // A Long Integer containing the decimal value 123456789000000000:
        let bytes = [
            0x42, 0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x08, 0x01, 0xB6, 0x9B, 0x4B, 0xA5, 0x74,
            0x92, 0x00,
        ];
        to_print(&bytes);

        // A Big Integer containing the decimal value 1234567890000000000000000000:
        let bytes = [
            0x42, 0x00, 0x20, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFD,
            0x35, 0xEB, 0x6B, 0xC2, 0xDF, 0x46, 0x18, 0x08, 0x00, 0x00,
        ];
        to_print(&bytes);

        // An Enumeration with value 255:
        let bytes = [
            0x42, 0x00, 0x20, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00,
            0x00, 0x00,
        ];
        to_print(&bytes);

        // A Boolean with the value True:
        let bytes = [
            0x42, 0x00, 0x20, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        to_print(&bytes);

        // A Text String with the value "Hello World":
        let bytes = [
            0x42, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x0B, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
            0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        to_print(&bytes);

        // A Byte String with the value { 0x01, 0x02, 0x03 }:
        let bytes = [
            0x42, 0x00, 0x20, 0x08, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        to_print(&bytes);

        // A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        let bytes = [
            0x42, 0x00, 0x20, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x47, 0xDA,
            0x67, 0xF8,
        ];
        to_print(&bytes);

        // An Interval, containing the value for 10 days:
        let bytes = [
            0x42, 0x00, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0D, 0x2F, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        to_print(&bytes);

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags 420004 and 420005 respectively:
        let bytes = [
            0x42, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x04, 0x05, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x05, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ];

        to_print(&bytes);
    }

    #[test]
    fn test_primitive_to_tokens() {
        // An Integer containing the decimal value 8:
        let bytes = [
            0x42, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::Integer(8)
            }]
        );

        // A Long Integer containing the decimal value 123456789000000000:
        let bytes = [
            0x42, 0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x08, 0x01, 0xB6, 0x9B, 0x4B, 0xA5, 0x74,
            0x92, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::LongInteger(123456789000000000)
            }]
        );

        // A Big Integer containing the decimal value 1234567890000000000000000000:
        // let bytes = [
        //     0x42, 0x00, 0x20, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFD,
        //     0x35, 0xEB, 0x6B, 0xC2, 0xDF, 0x46, 0x18, 0x08, 0x00, 0x00,
        // ];
        // assert_eq!(
        //     read_to_end(&bytes).unwrap(),
        //     [Value {
        //         tag: Tag::CompromiseDate,
        //         value: ValueType::Integer(8)
        //     }]
        // );

        // An Enumeration with value 255:
        let bytes = [
            0x42, 0x00, 0x20, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::Enumeration(255)
            }]
        );

        // A Boolean with the value True:
        let bytes = [
            0x42, 0x00, 0x20, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::Boolean(true)
            }]
        );

        // A Text String with the value "Hello World":
        let bytes = [
            0x42, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x0B, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
            0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::TextString("Hello World".into())
            }]
        );

        // A Byte String with the value { 0x01, 0x02, 0x03 }:
        let bytes = [
            0x42, 0x00, 0x20, 0x08, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::ByteString(vec![1, 2, 3])
            }]
        );

        // A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        let bytes = [
            0x42, 0x00, 0x20, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x47, 0xDA,
            0x67, 0xF8,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::DateTime(1205495800)
            }]
        );

        // An Interval, containing the value for 10 days:
        let bytes = [
            0x42, 0x00, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0D, 0x2F, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [Value {
                tag: Tag::CompromiseDate,
                value: ValueType::Interval(864000)
            }]
        );

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags 420004 and 420005 respectively:
        let bytes = [
            0x42, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x20, 0x42, 0x00, 0x04, 0x05, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x05, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [
                Value {
                    tag: Tag::CompromiseDate,
                    value: ValueType::StructureBegin(32)
                },
                Value {
                    tag: Tag::ApplicationSpecificInformation,
                    value: ValueType::Enumeration(254)
                },
                Value {
                    tag: Tag::ArchiveDate,
                    value: ValueType::Integer(255)
                },
                Value {
                    tag: Tag::CompromiseDate,
                    value: ValueType::StructureEnd
                }
            ]
        );

        // to_print(&bytes);
    }

    #[test]
    fn test_de_struct() {
        let bytes = [
            0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [
                Value {
                    tag: Tag::RequestHeader,
                    value: ValueType::StructureBegin(48)
                },
                Value {
                    tag: Tag::ProtocolVersionMajor,
                    value: ValueType::Integer(1)
                },
                Value {
                    tag: Tag::ProtocolVersionMinor,
                    value: ValueType::Integer(2)
                },
                Value {
                    tag: Tag::BatchCount,
                    value: ValueType::Integer(3)
                },
                Value {
                    tag: Tag::RequestHeader,
                    value: ValueType::StructureEnd
                }
            ]
        );
    }

    #[test]
    fn test_de_struct2() {
        let bytes = [
            66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0,
            0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7,
            0, 0, 0, 0,
        ];
        assert_eq!(
            read_to_end(&bytes).unwrap(),
            [
                Value {
                    tag: Tag::RequestMessage,
                    value: ValueType::StructureBegin(48)
                },
                Value {
                    tag: Tag::RequestHeader,
                    value: ValueType::StructureBegin(32)
                },
                Value {
                    tag: Tag::ProtocolVersionMajor,
                    value: ValueType::Integer(3)
                },
                Value {
                    tag: Tag::BatchCount,
                    value: ValueType::Integer(4)
                },
                Value {
                    tag: Tag::RequestHeader,
                    value: ValueType::StructureEnd
                },
                Value {
                    tag: Tag::UniqueIdentifier,
                    value: ValueType::TextString("".into())
                },
                Value {
                    tag: Tag::RequestMessage,
                    value: ValueType::StructureEnd
                }
            ]
        );
    }

    // #[test]
    // fn test_de_struct() {
    //     #[derive(Deserialize, Debug)]
    //     struct RequestHeader {
    //         #[serde(rename = "ProtocolVersionMajor")]
    //         pub protocol_version_major: i32,

    //         #[serde(rename = "ProtocolVersionMinor")]
    //         pub protocol_version_minor: i32,

    //         // #[serde(skip_serializing_if = "Option::is_none")]
    //         // BatchOrderOption : Option<i32>,
    //         // Option::None - serializes as serialize_none()
    //         // TODO: Other fields are optional
    //         #[serde(rename = "BatchCount")]
    //         pub batch_count: i32,
    //     }

    //     let good = vec![
    //         0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00,
    //         0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02,
    //         0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
    //         0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    //     ];

    //     //    to_print(good.as_ref());

    //     let r: TestEnumResolver = TestEnumResolver {};
    //     let a = from_bytes::<RequestHeader>(&good, &r).unwrap();

    //     assert_eq!(a.protocol_version_major, 1);
    //     assert_eq!(a.protocol_version_minor, 2);
    //     assert_eq!(a.batch_count, 3);
    // }

    // #[test]
    // fn test_struct2() {
    //     #[derive(Deserialize, Debug)]
    //     #[serde(tag = "Operation", content = "BatchItem")]
    //     enum CRTCoefficient {
    //         Attribute(Vec<u8>),
    //         CertificateRequest(String),
    //     }

    //     let good = vec![
    //         66, 0, 39, 1, 0, 0, 0, 40, 66, 0, 92, 7, 0, 0, 0, 18, 67, 101, 114, 116, 105, 102, 105,
    //         99, 97, 116, 101, 82, 101, 113, 117, 101, 115, 116, 0, 0, 0, 0, 0, 0, 66, 0, 15, 7, 0,
    //         0, 0, 0,
    //     ];
    //     to_print(good.as_ref());

    //     let r: TestEnumResolver = TestEnumResolver {};
    //     let _a = from_bytes::<CRTCoefficient>(&good, &r).unwrap();
    // }

    // #[test]
    // fn test_struct3() {
    //     #[derive(Deserialize, Debug)]
    //     struct CRTCoefficient {
    //         #[serde(rename = "BatchCount")]
    //         pub _batch_count: Vec<i32>,
    //     }

    //     let good = vec![
    //         66, 0, 39, 1, 0, 0, 0, 48, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 102, 0, 0, 0, 0, 66, 0,
    //         13, 2, 0, 0, 0, 4, 0, 0, 0, 119, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 136, 0,
    //         0, 0, 0,
    //     ];

    //     to_print(good.as_ref());

    //     let r: TestEnumResolver = TestEnumResolver {};
    //     let _a = from_bytes::<CRTCoefficient>(&good, &r).unwrap();
    // }

    // #[test]
    // fn test_datetime() {
    //     #[derive(Deserialize, Debug)]
    //     struct CRTCoefficient {
    //         #[serde(with = "my_date_format", rename = "BatchCount")]
    //         batch_count: chrono::DateTime<Utc>,
    //     }

    //     let good = vec![
    //         66, 0, 39, 1, 0, 0, 0, 16, 66, 0, 13, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 1, 226, 64,
    //     ];

    //     to_print(good.as_slice());

    //     let r: TestEnumResolver = TestEnumResolver {};
    //     let a = from_bytes::<CRTCoefficient>(&good, &r).unwrap();
    //     assert_eq! {a.batch_count.timestamp(), 123456};
    // }

    // #[test]
    // fn test_struct_nested() {
    //     #[derive(Deserialize, Debug)]
    //     struct RequestHeader {
    //         #[serde(rename = "ProtocolVersionMajor")]
    //         pub _protocol_version_major: i32,
    //         #[serde(rename = "BatchCount")]
    //         pub _batch_count: i32,
    //     }

    //     #[derive(Deserialize, Debug)]
    //     struct RequestMessage {
    //         #[serde(rename = "RequestHeader")]
    //         _request_header: RequestHeader,
    //         #[serde(rename = "UniqueIdentifier")]
    //         _unique_identifier: String,
    //     }

    //     let good = vec![
    //         66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0,
    //         0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7,
    //         0, 0, 0, 0,
    //     ];

    //     to_print(good.as_slice());

    //     let r: TestEnumResolver = TestEnumResolver {};
    //     let _a = from_bytes::<RequestMessage>(&good, &r).unwrap();
    // }

    #[test]
    fn test_parse_request_message() {
        let bytes = [
            66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4,
            0, 0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0,
            148, 7, 0, 0, 0, 0,
        ];
        let mut reader = Reader::new(&bytes);
        let msg = parse_request_message(&mut reader).unwrap();
        assert_eq!(msg.request_header.protocol_version_major, 3);
        assert_eq!(msg.request_header.batch_count, 4);
        assert_eq!(msg.unique_identifier, "");
    }
}
