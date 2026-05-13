use std::{
    io::{Cursor, Read},
    string::ToString,
};

use byteorder::{BigEndian, ReadBytesExt};
use pretty_hex::*;

use crate::{error::TTLVError, kmip_enums::*};

type TTLVResult<T> = std::result::Result<T, TTLVError>;

pub trait Reader {
    fn read(&mut self) -> Option<TTLVResult<Value>>;
    fn peek_tag(&mut self) -> Option<Tag>;
}

pub trait TtlvDeserialize: Sized {
    fn parse(reader: &mut dyn Reader) -> TTLVResult<Self>;
}

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

    // Work around a bug in a particular implementation that is serializing Enumeration as 8 bytes,
    // sigh. They are otherwise writing it correctly though
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

    // Work around a bug in a particular implementation that is serializing Integer as 8 bytes,
    // sigh. They are otherwise writing it correctly though
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
    buf: Vec<u8>,
}

impl IndentPrinter {
    fn new() -> IndentPrinter {
        IndentPrinter {
            indent: 0,
            buf: Vec::new(),
        }
    }

    fn indent(&mut self) {
        self.indent += 1;
    }

    fn unindent(&mut self) {
        self.indent -= 1;
    }

    fn print(&mut self, msg: &str) {
        let space = " ".repeat(self.indent * 4);
        // Use println! to play nicely with unit tests
        println!("{}{}", space, msg);
    }

    fn print_to_stdout(&self) {
        println!("{}", str::from_utf8(&self.buf).unwrap());
    }

    fn to_string(&self) -> String {
        str::from_utf8(&self.buf).unwrap().to_string()
    }
}

pub fn to_print(buf: &[u8]) {
    let mut printer: IndentPrinter = IndentPrinter::new();

    if let Err(r) = to_print_int(&mut printer, buf) {
        println!("Erroring in to_print: {:?}", r);
    }

    printer.print_to_stdout();
}

pub fn to_print_str(buf: &[u8]) -> String {
    let mut printer: IndentPrinter = IndentPrinter::new();

    if let Err(r) = to_print_int(&mut printer, buf) {
        println!("Erroring in to_print: {:?}", r);
    }

    printer.to_string()
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

pub struct TtlvReader<'a> {
    len: u64,
    cur: Cursor<&'a [u8]>,
    end_positions: Vec<(Tag, u64)>,
    peeked: Option<TTLVResult<Value>>,
}

impl<'a> TtlvReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            len: buf.len() as u64,
            cur: Cursor::new(buf),
            end_positions: Vec::new(),
            peeked: None,
        }
    }

    fn read_inner(&mut self) -> Option<TTLVResult<Value>> {
        let position = self.cur.position();

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

        if position == self.len {
            return None;
        }

        let value = read_value(&mut self.cur);
        match value {
            Err(_) => Some(value),
            Ok(x) => {
                if let ValueType::StructureBegin(struct_length) = x.value {
                    let position = self.cur.position();
                    self.end_positions
                        .push((x.tag, position + struct_length as u64));
                };

                Some(Ok(x))
            }
        }
    }
}

impl<'a> Reader for TtlvReader<'a> {
    fn read(&mut self) -> Option<TTLVResult<Value>> {
        if self.peeked.is_some() {
            return self.peeked.take();
        }
        self.read_inner()
    }

    fn peek_tag(&mut self) -> Option<Tag> {
        if self.peeked.is_none() {
            self.peeked = self.read_inner();
        }
        self.peeked.as_ref()?.as_ref().ok().map(|v| v.tag)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        de::{Reader, TTLVResult, TtlvReader, to_print},
        error::TTLVError,
        kmip_enums::{Tag, Value, ValueType},
        parser::{
            expect_integer,
            expect_structure_begin,
            expect_structure_end,
            expect_text_string,
        },
    };

    fn read_to_end(buf: &[u8]) -> TTLVResult<Vec<Value>> {
        let mut reader = TtlvReader::new(buf);

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

    struct RequestHeader {
        protocol_version_major: i32,
        batch_count: i32,
    }

    struct RequestMessage {
        request_header: RequestHeader,
        unique_identifier: String,
    }

    fn parse_request_header(reader: &mut dyn Reader) -> Result<RequestHeader, TTLVError> {
        expect_structure_begin(reader, Tag::RequestHeader)?;
        let protocol_version_major = expect_integer(reader, Tag::ProtocolVersionMajor)?;
        let batch_count = expect_integer(reader, Tag::BatchCount)?;
        expect_structure_end(reader, Tag::RequestHeader)?;
        Ok(RequestHeader {
            protocol_version_major,
            batch_count,
        })
    }

    fn parse_request_message(reader: &mut dyn Reader) -> Result<RequestMessage, TTLVError> {
        expect_structure_begin(reader, Tag::RequestMessage)?;
        let request_header = parse_request_header(reader)?;
        let unique_identifier = expect_text_string(reader, Tag::UniqueIdentifier)?;
        expect_structure_end(reader, Tag::RequestMessage)?;
        Ok(RequestMessage {
            request_header,
            unique_identifier,
        })
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

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255,
        // having tags 420004 and 420005 respectively:
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

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255,
        // having tags 420004 and 420005 respectively:
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

    #[test]
    fn test_parse_request_message() {
        let bytes = [
            66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0,
            0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7,
            0, 0, 0, 0,
        ];
        let mut reader = TtlvReader::new(&bytes);
        let msg = parse_request_message(&mut reader).unwrap();
        assert_eq!(msg.request_header.protocol_version_major, 3);
        assert_eq!(msg.request_header.batch_count, 4);
        assert_eq!(msg.unique_identifier, "");
    }
}
