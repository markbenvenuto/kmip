use std::io::Read;
use std::io::Cursor;

use std::string::ToString;

use std::ops::{AddAssign, MulAssign, Neg};

use serde::Deserialize;
use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};

use crate::error::{Error, Result};

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

use num_traits::FromPrimitive;

extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt};

//use self::enums;
use crate::kmip_enums::*;


fn compute_padding(len: usize) -> usize {
    if len % 8 == 0 {
        return len;
    }

    let padding = 8 - (len % 8);
    return len + padding;
}


fn read_tag(reader: &mut dyn Read) -> u32 {
    println!("Read Tag");
    let v = reader.read_u8().unwrap();
    assert_eq!(v, 0x42);
    let tag = reader.read_u16::<BigEndian>().unwrap();

    return 0x420000 + tag as u32;
}

fn read_tag_enum(reader: &mut dyn Read) -> Tag {
    let tag_u32 = read_tag(reader);

    return num::FromPrimitive::from_u32(tag_u32).unwrap();
}

fn read_len(reader: &mut dyn Read) -> u32 {
    println!("Read Len");
    return reader.read_u32::<BigEndian>().unwrap();
}

fn read_type(reader: &mut dyn Read) -> ItemType {
    println!("Read Type");
    let i = reader.read_u8().unwrap();
    return num::FromPrimitive::from_u8(i).unwrap();
}


fn read_i32(reader: &mut dyn Read) -> i32 {
    println!("Read i32");
    let len = read_len(reader);
    assert_eq !(len, 4);
    let v = reader.read_i32::<BigEndian>().unwrap();

    // swallow the padding
    // TODO - speed up
    reader.read_i32::<BigEndian>().unwrap();

    return v;
}

fn read_i64(reader: &mut dyn Read) -> i64 {
    println!("Read i64");
    let len = read_len(reader);
    assert_eq !(len, 8);

    let v = reader.read_i64::<BigEndian>().unwrap();
    return v;
}

fn read_string(reader: &mut dyn Read) -> String {
    println!("Read string");
    let len = read_len(reader);

    let padding = compute_padding(len as usize);

    // TODO - better protection against bogus sizes
    assert!(padding < 32 * 1024);

    let mut v : Vec<u8> = Vec::new();
    v.resize(padding as usize, 0);

    reader.read(v.as_mut_slice()).unwrap();

    v.resize(len as usize, 0);

    return String::from_utf8(v).unwrap();
}

fn read_bytes(reader: &mut dyn Read) -> Vec<u8> {
    let len = read_len(reader);

    let padding = compute_padding(len as usize);

    // TODO - better protection against bogus sizes
    assert!(padding < 32 * 1024);

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

        let tag : Tag = num::FromPrimitive::from_u32(tag_u32).unwrap();

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

#[derive(PartialEq, Debug)]
enum ReaderState {
    Tag,
    TypeLengthValue,
}

struct NestedReader<'a> {
    end_positions : Vec<u64>,
    cur : Cursor< &'a [u8]>,
    state : ReaderState,
}

impl<'a> NestedReader<'a> {
    fn new(buf: &'a [u8]) -> NestedReader {
        return NestedReader {
            end_positions: Vec::new(),
            cur: Cursor::new( buf ),
            state: ReaderState::Tag,
        }
    }

    fn begin_inner(&mut self) {
        read_tag(&mut self.cur);

        println!("read_inner: {}", self.cur.position());
        let t = read_type(&mut self.cur);
        assert_eq!(t, ItemType::Structure);

        let len = read_len(&mut self.cur) as u64;
        self.end_positions.push(self.cur.position() + len);
        self.state = ReaderState::Tag;
    }

    fn close_inner(&mut self) {
        self.end_positions.pop().unwrap();
    }

    fn is_empty(&self)  -> bool {
        if self.end_positions.is_empty() {
            return true;
        }
        println!("cmp1 {:?} == {:?}", *(self.end_positions.last().unwrap()) , self.cur.position());
        return *(self.end_positions.last().unwrap()) == self.cur.position();
    }

    fn read_type(&mut self) -> ItemType {
        assert_eq!(self.state, ReaderState::TypeLengthValue);
        return read_type(&mut self.cur);
    }

    fn is_tag(&self) -> bool {
        self.state == ReaderState::Tag
    }

    fn read_tag(&mut self) -> Tag  {
        assert_eq!(self.state, ReaderState::Tag);
        self.state = ReaderState::TypeLengthValue;
        return read_tag_enum(&mut self.cur);
    }

    fn read_i32(&mut self) -> i32 {
        assert_eq!(self.state, ReaderState::TypeLengthValue);
        self.state = ReaderState::Tag;
        return read_i32(&mut self.cur);
    }

    fn read_i64(&mut self) -> i64 {
        assert_eq!(self.state, ReaderState::TypeLengthValue);
        self.state = ReaderState::Tag;
        return read_i64(&mut self.cur);
    }

    fn read_string_and_more(&mut self) -> String {
        if self.state == ReaderState::Tag {
            self.read_tag();
        }
        assert_eq!(self.read_type(), ItemType::TextString);
        assert_eq!(self.state, ReaderState::TypeLengthValue);
        self.state = ReaderState::Tag;
        return read_string(&mut self.cur);
    }

    fn read_string(&mut self) -> String {
        assert_eq!(self.state, ReaderState::TypeLengthValue);
        self.state = ReaderState::Tag;
        return read_string(&mut self.cur);
    }
}

// impl<'a> Read for NestedReader<'a> {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         self.cur.read(buf)
//     }
// }


////////////////////

pub struct Deserializer<'de> {
    // This string starts with the input data and characters are truncated off
    // the beginning as data is parsed.
    //pub input: &'de [u8],

    input : NestedReader<'de>,
}

impl<'de> Deserializer<'de> {
    // By convention, `Deserializer` constructors are named like `from_xyz`.
    // That way basic use cases are satisfied by something like
    // `serde_json::from_str(...)` while advanced use cases that require a
    // deserializer can make one with `serde_json::Deserializer::from_str(...)`.
    pub fn from_bytes(input: &'de [u8]) -> Self {
        //Deserializer { input }
        Deserializer { input : NestedReader::new(input) }
    }
}

// By convention, the public API of a Serde deserializer is one or more
// `from_xyz` methods such as `from_str`, `from_bytes`, or `from_reader`
// depending on what Rust types the deserializer is able to consume as input.
//
// This basic deserializer supports only `from_str`.
pub fn from_bytes<'a, T>(s: &'a [u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = Deserializer::from_bytes(s);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(Error::Eof)
    }
}



impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    // Look at the input data to decide what Serde data model type to
    // deserialize as. Not all data formats are able to support this operation.
    // Formats that support `deserialize_any` are known as self-describing.
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        println!("read_any");
        // if self.input.is_empty() {
        //     return Ok(None);
        // }
        if self.input.is_tag() {
            let tag = self.input.read_tag();
            return visitor.visit_string(tag.as_ref().to_string());
        }
         //self.input.read_tag();

        let t = self.input.read_type();
        match t {
            ItemType::Integer => {
                let v = self.input.read_i32();
                visitor.visit_i32(v)
            }
            ItemType::TextString  => {
                let v = self.input.read_string();
                visitor.visit_string(v)
            }
            _ => { unimplemented!(); }
        }

    }

    // Uses the `parse_bool` parsing function defined above to read the JSON
    // identifier `true` or `false` from the input.
    //
    // Parsing refers to looking at the input and deciding that it contains the
    // JSON value `true` or `false`.
    //
    // Deserialization refers to mapping that JSON value into Serde's data
    // model by invoking one of the `Visitor` methods. In the case of JSON and
    // bool that mapping is straightforward so the distinction may seem silly,
    // but in other cases Deserializers sometimes perform non-obvious mappings.
    // For example the TOML format has a Datetime type and Serde's data model
    // does not. In the `toml` crate, a Datetime in the input is deserialized by
    // mapping it to a Serde data model "struct" type with a special name and a
    // single field containing the Datetime represented as a string.
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
//        visitor.visit_bool(self.parse_bool()?)
    }

    // The `parse_signed` function is generic over the integer type `T` so here
    // it is invoked with `T=i8`. The next 8 methods are similar.
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::Integer);
        visitor.visit_i8(self.input.read_i32() as i8)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::Integer);
        visitor.visit_i16(self.input.read_i32() as i16)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::Integer);
        visitor.visit_i32(self.input.read_i32())
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::LongInteger);
        visitor.visit_i64(self.input.read_i64())
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::Integer);
        visitor.visit_u8(self.input.read_i32() as u8)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::Integer);
        visitor.visit_u16(self.input.read_i32() as u16)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::Integer);
        visitor.visit_u32(self.input.read_i32() as u32)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        assert_eq!(self.input.read_type(), ItemType::LongInteger);
        visitor.visit_u64(self.input.read_i64() as u64)
    }

    // Float parsing is stupidly hard.
    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // Float parsing is stupidly hard.
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // The `Serializer` implementation on the previous page serialized chars as
    // single-character strings so handle that representation here.
    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Parse a string, check that it is one character, call `visit_char`.
        unimplemented!()
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // TODO
        //visitor.visit_borrowed_str(read_string(&mut self.input).as_ref())
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if self.input.is_tag() {
            let tag = self.input.read_tag();
            return visitor.visit_string(tag.as_ref().to_string());
        }

        assert_eq!(self.input.read_type(), ItemType::TextString);
        visitor.visit_string(self.input.read_string())
        //self.deserialize_str(visitor)
    }

    // The `Serializer` implementation on the previous page serialized byte
    // arrays as JSON arrays of bytes. Handle that representation here.
    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // An absent optional is represented as the JSON `null` and a present
    // optional is represented as just the contained value.
    //
    // As commented in `Serializer` implementation, this is a lossy
    // representation. For example the values `Some(())` and `None` both
    // serialize as just `null`. Unfortunately this is typically what people
    // expect when working with JSON. Other formats are encouraged to behave
    // more intelligently if possible.
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    // In Serde, unit means an anonymous value containing no data.
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    // Unit struct means a named value containing no data.
    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    // Deserialization of compound types like sequences and maps happens by
    // passing the visitor an "Access" object that gives it the ability to
    // iterate through the data contained in the sequence.
    fn deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently.
    //
    // As indicated by the length parameter, the `Deserialize` implementation
    // for a tuple in the Serde data model is required to know the length of the
    // tuple before even looking at the input data.
    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    // Tuple structs look just like sequences in JSON.
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    // Much like `deserialize_seq` but calls the visitors `visit_map` method
    // with a `MapAccess` implementation, rather than the visitor's `visit_seq`
    // method with a `SeqAccess` implementation.
    fn deserialize_map<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.input.begin_inner();

        visitor.visit_map(MapParser::new(&mut self))
    }

    // Structs look just like maps in JSON.
    //
    // Notice the `fields` parameter - a "struct" in the Serde data model means
    // that the `Deserialize` implementation is required to know what the fields
    // are before even looking at the input data. Any key-value pairing in which
    // the fields cannot be known ahead of time is probably a map.
    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
                unimplemented!()

        // if self.peek_char()? == '"' {
        //     // Visit a unit variant.
        //     visitor.visit_enum(self.parse_string()?.into_deserializer())
        // } else if self.next_char()? == '{' {
        //     // Visit a newtype variant, tuple variant, or struct variant.
        //     let value = visitor.visit_enum(Enum::new(self))?;
        //     // Parse the matching close brace.
        //     if self.next_char()? == '}' {
        //         Ok(value)
        //     } else {
        //         Err(Error::ExpectedMapEnd)
        //     }
        // } else {
        //     Err(Error::ExpectedEnum)
        // }
    }

    // An identifier in Serde is the type that identifies a field of a struct or
    // the variant of an enum. In JSON, struct fields and enum variants are
    // represented as strings. In other formats they may be represented as
    // numeric indices.
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    // Like `deserialize_any` but indicates to the `Deserializer` that it makes
    // no difference which `Visitor` method is called because the data is
    // ignored.
    //
    // Some deserializers are able to implement this more efficiently than
    // `deserialize_any`, for example by rapidly skipping over matched
    // delimiters without paying close attention to the data in between.
    //
    // Some formats are not able to implement this at all. Formats that can
    // implement `deserialize_any` and `deserialize_ignored_any` are known as
    // self-describing.
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}


struct MapParser<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
}

impl<'a, 'de> MapParser<'a, 'de> {
    fn new(de: &'a mut Deserializer<'de>) -> Self {
        MapParser {
            de,
        }
    }
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, 'a> MapAccess<'de> for MapParser<'a, 'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        if self.de.input.is_empty() {
            self.de.input.close_inner();
            return Ok(None);
        }

        println!("next key==");
        let a = seed.deserialize(&mut *self.de).map(Some);
        //Ok(Some(tag))
        println!("==");
        return a;
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        println!("next seed--");
        // Deserialize a map value.
        let a = seed.deserialize(&mut *self.de);
        println!("--");
        return a;
    }
}


#[test]
fn test_de_struct() {
    #[derive(Deserialize, Debug)]
    struct RequestHeader {
        ProtocolVersionMajor : i32,
        ProtocolVersionMinor : i32,

        // #[serde(skip_serializing_if = "Option::is_none")]
        // BatchOrderOption : Option<i32>,
        // Option::None - serializes as serialize_none()
        // TODO: Other fields are optional
        BatchCount: i32,
    }

    let good = vec!{0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04,
0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04,
0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04,
0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};

//    to_print(good.as_ref());

    let a = from_bytes::<RequestHeader>(&good).unwrap();

    assert_eq!(a.ProtocolVersionMajor, 1);
    assert_eq!(a.ProtocolVersionMinor, 2);
    assert_eq!(a.BatchCount, 3);

    }



#[test]
fn test_struct2() {
    #[derive(Deserialize, Debug)]
    #[serde(tag = "Operation", content = "BatchItem")]
    enum CRTCoefficient {
        Attribute(Vec<u8>),
        CertificateRequest(String)
    }

    let good = vec!{66, 0, 39, 1, 0, 0, 0, 40, 66, 0, 92, 7, 0, 0, 0, 18, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 82, 101, 113, 117, 101, 115, 116, 0, 0, 0, 0, 0, 0, 66, 0, 15, 7, 0, 0, 0, 0};
    to_print(good.as_ref());

    let a = from_bytes::<CRTCoefficient>(&good).unwrap();
}