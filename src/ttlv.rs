use {Error, Result}

use std::io;
use std::io::Read;
use std::io::Write;
use std::io::Cursor;

use serde::{ser, Serialize};

//use error::{Error, Result};


extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

use num_traits::FromPrimitive;

use pretty_hex::*;

extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

//use self::enums;
use crate::kmip_enums;

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



fn write_tag(writer: &mut dyn Write, tag: u16) {
    // 0x42 for tags built into the protocol
    // 0x54 for extension tags
    writer.write_u8(0x42).unwrap();
    writer.write_u16::<BigEndian>(tag).unwrap();
}

fn compute_padding(len: usize) -> usize {
    if len % 8 == 0 {
        return len;
    }

    let padding = 8 - (len % 8);
    return len + padding;
}


pub fn write_string(writer : &mut dyn Write, tag : u16, value: &str ) {
    write_tag(writer, tag);

    writer.write_u8(ItemType::TextString as u8).unwrap();

    writer.write_u32::<BigEndian>(value.len() as u32).unwrap();

    writer.write(value.as_bytes()).unwrap();

    let padded_length = compute_padding(value.len());
    assert_eq!{ padded_length, value.len()};
}

pub fn write_bytes(writer : &mut dyn Write, tag : u16, value: &[u8] ) {
    write_tag(writer, tag);

    writer.write_u8(ItemType::ByteString as u8).unwrap();

    writer.write_u32::<BigEndian>(value.len() as u32).unwrap();

    writer.write(value).unwrap();

    let padded_length = compute_padding(value.len());
    assert_eq!{ padded_length, value.len()};
}

pub fn write_i32(writer : &mut dyn Write, tag : u16, value: i32 ) {
    write_tag(writer, tag);

    writer.write_u8(ItemType::Integer as u8).unwrap();

    writer.write_u32::<BigEndian>(4).unwrap();

    // Add 4 bytes of padding
    // TODO - make faster
    writer.write_u32::<BigEndian>(0).unwrap();

    writer.write_i32::<BigEndian>(value).unwrap();
}


pub fn write_i64(writer : &mut dyn Write, tag : u16, value: i64 ) {
    write_tag(writer, tag);

    writer.write_u8(ItemType::LongInteger as u8).unwrap();

    writer.write_u32::<BigEndian>(8).unwrap();

    writer.write_i64::<BigEndian>(value).unwrap();
}


pub fn write_enumeration(writer : &mut dyn Write, tag : u16, value: i32 ) {
    write_tag(writer, tag);

    writer.write_u8(ItemType::Enumeration as u8).unwrap();

    writer.write_u32::<BigEndian>(4).unwrap();

    // Add 4 bytes of padding
    // TODO - make faster
    writer.write_u32::<BigEndian>(0).unwrap();

    writer.write_i32::<BigEndian>(value).unwrap();
}

struct CountingWriter<'a> {
    //&Writer : writer,
    count : usize,
    writer : &'a mut dyn Write,
}

impl<'a> Write for CountingWriter<'a> {

   fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
       let ret = self.writer.write(buf);

        if let Ok(s) = ret  {
            self.count += s;
        }

       return ret;
   }


    fn flush(&mut self) -> io::Result<()> {
        return Ok(())
    }
}



pub struct StructWriter<'a> {
    vec : Vec<u8>,
    orig_writer : &'a mut dyn Write,
}

impl<'a>  StructWriter<'a> {
    pub fn new(writer : &'a mut dyn Write) -> StructWriter {
        StructWriter {
            vec :  Vec::new(),
            orig_writer : writer,
        }
    }

    fn get_writer(&mut self) -> &dyn Write {
        return &self.vec;
    }
}

impl<'a> Drop for StructWriter<'a> {

    fn drop(&mut self) {
        self.orig_writer.write_u32::<BigEndian>(self.vec.len() as u32).unwrap();

        self.orig_writer.write(self.vec.as_slice()).unwrap();
    }
}



pub fn begin_struct(writer : &mut dyn Write, tag : u16, value: i32 ) -> StructWriter {
    write_tag(writer, tag);

    writer.write_u8(ItemType::Structure as u8).unwrap();

    return StructWriter::new(writer);
}



///////////////////////////////

fn read_tag(reader: &mut dyn Read) -> u32 {
    let v = reader.read_u8().unwrap();
    assert_eq!(v, 0x42);
    let tag = reader.read_u16::<BigEndian>().unwrap();

    return 0x420000 + tag as u32;
}

fn read_len(reader: &mut dyn Read) -> u32 {
    return reader.read_u32::<BigEndian>().unwrap();
}

fn read_type(reader: &mut dyn Read) -> ItemType {
    let i = reader.read_u8().unwrap();
    return num::FromPrimitive::from_u8(i).unwrap();
}


fn read_i32(reader: &mut dyn Read) -> i32 {
    let len = read_len(reader);
    assert_eq !(len, 4);
    let v = reader.read_i32::<BigEndian>().unwrap();

    // swallow the padding
    // TODO - speed up
    reader.read_i32::<BigEndian>().unwrap();

    return v;
}

fn read_i64(reader: &mut dyn Read) -> i64 {
    let len = read_len(reader);
    assert_eq !(len, 8);

    let v = reader.read_i64::<BigEndian>().unwrap();
    return v;
}

fn read_string(reader: &mut dyn Read) -> String {
    let len = read_len(reader);

    let padding = compute_padding(len as usize);

    let mut v : Vec<u8> = Vec::new();
    v.resize(padding as usize, 0);

    reader.read(v.as_mut_slice()).unwrap();

    v.resize(len as usize, 0);

    return String::from_utf8(v).unwrap();
}

fn read_bytes(reader: &mut dyn Read) -> Vec<u8> {
    let len = read_len(reader);

    let padding = compute_padding(len as usize);

    let mut v : Vec<u8> = Vec::new();
    v.resize(padding as usize, 0);

    reader.read(v.as_mut_slice()).unwrap();

    v.resize(len as usize, 0);

    return v;
}

pub fn read_struct(reader : &mut dyn Read) -> Vec<u8> {
    let len = read_len(reader);


    let mut v : Vec<u8> = Vec::new();
    v.resize(len as usize, 0);

    reader.read(v.as_mut_slice()).unwrap();

    return v;
}


/////////////////////////////
pub fn to_print(buf: &[u8]) {

    let mut cur = Cursor::new(buf);

    while cur.position() < buf.len() as u64 {

        let tag_u32 = read_tag(&mut cur);

        let tag : kmip_enums::Tag = num::FromPrimitive::from_u32(tag_u32).unwrap();

        let item_type = read_type(&mut cur);

        match item_type {
            ItemType::Integer => {
                let v = read_i32(&mut cur);
                println!("Tag {:?} - Type {:?} - Value {:?}", tag, item_type, v);
            }
            ItemType::LongInteger => {
                let v = read_i64(&mut cur);
                println!("Tag {:?} - Type {:?} - Value {:?}", tag, item_type, v);
            }
            ItemType::Enumeration => {
                let v = read_i32(&mut cur);
                println!("Tag {:?} - Type {:?} - Value {:?}", tag, item_type, v);
            }
            ItemType::TextString => {
                let v = read_string(&mut cur);
                println!("Tag {:?} - Type {:?} - Value {:?}", tag, item_type, v);
            }

            ItemType::Structure => {
                let v = read_struct(&mut cur);
                println!("Tag {:?} - Type {:?} - Structure {{", tag, item_type);
                to_print(v.as_slice());
                println!("}}");
            }

            _ => {
                panic!{};
            }
        }
    }

}


//////////////////


// impl<'de> Deserialize<'de> for i32 {
//     fn deserialize<D>(deserializer: D) -> Result<i32, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         deserializer.deserialize_i32(I32Visitor)
//     }
// }


pub struct Serializer {
    // This string starts empty and JSON is appended as values are serialized.
    output: Vec<u8>,
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: Vec::new(),
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}


impl<'a> ser::Serializer for &'a mut Serializer {
    // The output type produced by this `Serializer` during successful
    // serialization. Most serializers that produce text or binary output should
    // set `Ok = ()` and serialize into an `io::Write` or buffer contained
    // within the `Serializer` instance, as happens here. Serializers that build
    // in-memory data structures may be simplified by using `Ok` to propagate
    // the data structure around.
    type Ok = ();

    // The error type when some error occurs during serialization.
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    // Here we go with the simple methods. The following 12 methods receive one
    // of the primitive types of the data model and map it to JSON by appending
    // into the output string.
    fn serialize_bool(self, v: bool) -> Result<()> {
        self.output += if v { "true" } else { "false" };
        Ok(())
    }

    // JSON does not distinguish between different sizes of integers, so all
    // signed integers will be serialized the same and all unsigned integers
    // will be serialized the same. Other formats, especially compact binary
    // formats, may need independent logic for the different sizes.
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i64(i64::from(v))
    }

    // Not particularly efficient but this is example code anyway. A more
    // performant approach would be to use the `itoa` crate.
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.output += &v.to_string();
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.output += &v.to_string();
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        self.output += &v.to_string();
        Ok(())
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, v: &str) -> Result<()> {
        self.output += "\"";
        self.output += v;
        self.output += "\"";
        Ok(())
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        use serde::ser::SerializeSeq;
        let mut seq = self.serialize_seq(Some(v.len()))?;
        for byte in v {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        self.serialize_unit()
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both serialize as just `null`. Unfortunately this is typically
    // what people expect when working with JSON. Other formats are encouraged
    // to behave more intelligently if possible.
    fn serialize_some<T>(self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // In Serde, unit means an anonymous value containing no data. Map this to
    // JSON as `null`.
    fn serialize_unit(self) -> Result<()> {
        self.output += "null";
        Ok(())
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(variant)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to JSON in externally tagged form as `{ NAME: VALUE }`.
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.output += "{";
        variant.serialize(&mut *self)?;
        self.output += ":";
        value.serialize(&mut *self)?;
        self.output += "}";
        Ok(())
    }

    // Now we get to the serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start,
    // which in JSON is `[`.
    //
    // The length of the sequence may or may not be known ahead of time. This
    // doesn't make a difference in JSON because the length is not represented
    // explicitly in the serialized form. Some serializers may only be able to
    // support sequences for which the length is known up front.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        self.output += "[";
        Ok(self)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.output += "{";
        variant.serialize(&mut *self)?;
        self.output += ":[";
        Ok(self)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        self.output += "{";
        Ok(self)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct> {
        self.serialize_map(Some(len))
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.output += "{";
        variant.serialize(&mut *self)?;
        self.output += ":{";
        Ok(self)
    }
}
