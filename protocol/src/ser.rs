use serde::{ser, Serialize};
use std::{io::Write, rc::Rc};

use std::str::FromStr;

use crate::{
    error::{Error, Result},
    EnumResolver,
};

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};

//use self::enums;
use crate::kmip_enums::*;

use crate::TTLVError;

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

    fn get_tag(&self) -> Option<Tag>;
    fn set_tag(&mut self, tag: Tag);

    fn write_optional_tag(&mut self) -> TTLVResult<()>;

    fn write_i32(&mut self, v: i32) -> TTLVResult<()>;

    fn write_i32_enumeration(
        &mut self,
        enum_name: &str,
        v: i32,
        enum_resolver: &dyn EnumResolver,
    ) -> TTLVResult<()>;
    fn write_i64(&mut self, v: i64) -> TTLVResult<()>;
    fn write_i64_datetime(&mut self, v: i64) -> TTLVResult<()>;

    fn write_string(&mut self, v: &str) -> TTLVResult<()>;

    fn write_bytes(&mut self, v: &[u8]) -> TTLVResult<()>;

    fn write_tag_enum(&mut self, t: Tag) -> TTLVResult<()>;

    fn write_struct_start(&mut self) -> TTLVResult<()>;

    fn begin_inner(&mut self) -> TTLVResult<()>;

    fn close_inner(&mut self) -> TTLVResult<()>;
}

struct NestedWriter {
    start_positions: Vec<usize>,
    vec: Vec<u8>,
    tag: Option<Tag>,
}

impl EncodedWriter for NestedWriter {
    fn new() -> NestedWriter {
        NestedWriter {
            start_positions: Vec::new(),
            vec: Vec::new(),
            tag: None,
        }
    }

    fn get_vector(self) -> Vec<u8> {
        self.vec
    }

    fn get_tag(&self) -> Option<Tag> {
        self.tag
    }

    fn set_tag(&mut self, tag: Tag) {
        self.tag = Some(tag)
    }

    fn write_optional_tag(&mut self) -> TTLVResult<()> {
        if let Some(t) = &self.tag {
            write_tag_enum(&mut self.vec, *t)?;
        }

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

        self.tag = None;
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

        self.tag = None;

        Ok(())
    }

    fn write_i32(&mut self, v: i32) -> TTLVResult<()> {
        write_i32(&mut self.vec, v)
    }

    fn write_i32_enumeration(
        &mut self,
        _enum_name: &str,
        v: i32,
        _enum_resolver: &dyn EnumResolver,
    ) -> TTLVResult<()> {
        write_enumeration(&mut self.vec, v)
    }
    fn write_i64(&mut self, v: i64) -> TTLVResult<()> {
        write_i64(&mut self.vec, v)
    }
    fn write_i64_datetime(&mut self, v: i64) -> TTLVResult<()> {
        write_i64_datetime(&mut self.vec, v)
    }

    fn write_string(&mut self, v: &str) -> TTLVResult<()> {
        write_string(&mut self.vec, v)
    }

    fn write_bytes(&mut self, v: &[u8]) -> TTLVResult<()> {
        write_bytes(&mut self.vec, v)
    }

    fn write_tag_enum(&mut self, t: Tag) -> TTLVResult<()> {
        self.tag = None;
        write_tag_enum(&mut self.vec, t)
    }

    fn write_struct_start(&mut self) -> TTLVResult<()> {
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

pub struct Serializer<W>
where
    W: EncodedWriter,
{
    // This string starts empty and JSON is appended as values are serialized.
    pub output: W,
    pub enum_resolver: Rc<dyn EnumResolver>,
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
pub fn to_bytes<'b, T>(value: &T, enum_resolver: Rc<dyn EnumResolver>) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: NestedWriter::new(),
        enum_resolver,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output.get_vector())
}

impl<'a, W: EncodedWriter> ser::Serializer for &'a mut Serializer<W> {
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
    fn serialize_bool(self, _v: bool) -> Result<()> {
        unimplemented!();
    }

    // JSON does not distinguish between different sizes of integers, so all
    // signed integers will be serialized the same and all unsigned integers
    // will be serialized the same. Other formats, especially compact binary
    // formats, may need independent logic for the different sizes.
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i32(i32::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i32(i32::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.output.write_optional_tag()?;
        self.output.write_i32(v)?;
        Ok(())
    }

    // Not particularly efficient but this is example code anyway. A more
    // performant approach would be to use the `itoa` crate.
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.output.write_optional_tag()?;
        self.output.write_i64(v)?;
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_u32(u32::from(v))
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_u32(u32::from(v))
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_i32(v as i32)
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        unimplemented!();
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    fn serialize_char(self, _v: char) -> Result<()> {
        unimplemented!();
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, v: &str) -> Result<()> {
        self.output.write_optional_tag()?;
        self.output.write_string(v)?;
        Ok(())
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.output.write_optional_tag()?;
        self.output.write_bytes(v)?;
        Ok(())
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
        // Note, hitting this means likely a Option is not marked with #[serde(skip_serializing_if = "Option::is_none"]
        unimplemented!();
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
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if _name == "my_date" {
            let mut mydate_serializer = MyDateSerializer::new(&mut self.output);
            return value.serialize(&mut mydate_serializer);
        } else if _name.starts_with("my_enum|") {
            let (_, enum_name) = _name.split_at(_name.find('|').unwrap() + 1);
            if enum_name.ends_with("Enum") {
                let (enum_name2, _) = enum_name.split_at(enum_name.rfind("Enum").unwrap());

                // eprintln!("---enum2: {}", enum_name2 );

                if enum_name2 == "ObjectState" {
                    let mut myenum_serializer = MyEnumSerializer::new(
                        &mut self.output,
                        "State",
                        self.enum_resolver.clone(),
                    );
                    return value.serialize(&mut myenum_serializer);
                }

                let mut myenum_serializer =
                    MyEnumSerializer::new(&mut self.output, enum_name2, self.enum_resolver.clone());
                return value.serialize(&mut myenum_serializer);
            }
            // eprintln!("---enum: {}", enum_name );

            let mut myenum_serializer =
                MyEnumSerializer::new(&mut self.output, enum_name, self.enum_resolver.clone());
            return value.serialize(&mut myenum_serializer);
        }

        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to JSON in externally tagged form as `{ NAME: VALUE }`.
    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        let tag = Tag::from_str(name).map_err(|_| TTLVError::InvalidTagName {
            name: name.to_owned(),
        })?;
        self.output.write_tag_enum(tag)?;
        value.serialize(&mut *self)
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
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        unimplemented!();
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        self.output.write_struct_start()?;
        self.output.begin_inner()?;
        Ok(self)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        let t = match self.output.get_tag() {
            Some(t) => t,
            None => Tag::from_str(name).map_err(|_| TTLVError::InvalidTagName {
                name: name.to_owned(),
            })?,
        };
        // let t =  Tag::from_str(name).map_err(|_| TTLVError::InvalidTagName {
        //         name: name.to_owned() } )?;

        println!("serializing: {:?} - {:?}", name, t);

        self.output.write_tag_enum(t)?;

        self.serialize_map(Some(len))
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        unimplemented!();
    }
}

impl<'a, 'b, W: EncodedWriter> Serializer<W> {
    fn serialize_element_one<T>(&'a mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a, W: EncodedWriter> ser::SerializeSeq for &'a mut Serializer<W> {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_element_one(value)
    }

    // Close the sequence.
    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a, W: EncodedWriter> ser::SerializeTuple for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!();
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Same thing but for tuple structs.
impl<'a, W: EncodedWriter> ser::SerializeTupleStruct for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!();
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
// So the `end` method in this impl is responsible for closing both the `]` and
// the `}`.
impl<'a, W: EncodedWriter> ser::SerializeTupleVariant for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!();
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl<'a, W: EncodedWriter> ser::SerializeMap for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        key.serialize(&mut **self)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a, W: EncodedWriter> ser::SerializeStruct for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        println!("serializing {:?}", key);
        let tag = Tag::from_str(key).map_err(|_| TTLVError::InvalidTagName {
            name: key.to_owned(),
        })?;
        self.output.set_tag(tag);

        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        //println!("write_innter_close");
        self.output.close_inner()?;

        Ok(())
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl<'a, W: EncodedWriter> ser::SerializeStructVariant for &'a mut Serializer<W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        let tag = Tag::from_str(key).unwrap();
        self.output.write_tag_enum(tag)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

struct MyDateSerializer<'a, W>
where
    W: EncodedWriter,
{
    output: &'a mut W,
}

impl<'a, W: EncodedWriter> MyDateSerializer<'a, W> {
    pub fn new(output: &'a mut W) -> MyDateSerializer<'a, W> {
        MyDateSerializer { output }
    }
}

impl<'a, W: EncodedWriter> ser::Serializer for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // JSON does not distinguish between different sizes of integers, so all
    // signed integers will be serialized the same and all unsigned integers
    // will be serialized the same. Other formats, especially compact binary
    // formats, may need independent logic for the different sizes.
    fn serialize_i8(self, _v: i8) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_i16(self, _v: i16) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_i32(self, _v: i32) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Not particularly efficient but this is example code anyway. A more
    // performant approach would be to use the `itoa` crate.
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.output.write_optional_tag()?;
        self.output.write_i64_datetime(v)?;
        Ok(())
    }

    fn serialize_u8(self, _v: u8) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u16(self, _v: u16) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u32(self, _v: u32) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u64(self, _v: u64) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    fn serialize_char(self, _v: char) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, _v: &str) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, _v: &[u8]) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both serialize as just `null`. Unfortunately this is typically
    // what people expect when working with JSON. Other formats are encouraged
    // to behave more intelligently if possible.
    fn serialize_some<T>(self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    // In Serde, unit means an anonymous value containing no data. Map this to
    // JSON as `null`.
    fn serialize_unit(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
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
        _variant: &'static str,
        _value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
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
        Err(Error::UnsupportedType)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Err(Error::UnsupportedType)
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Err(Error::UnsupportedType)
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        Err(Error::UnsupportedType)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(Error::UnsupportedType)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Err(Error::UnsupportedType)
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Err(Error::UnsupportedType)
    }
}

impl<'a, W: EncodedWriter> ser::SerializeSeq for &'a mut MyDateSerializer<'a, W> {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    // Close the sequence.
    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Same thing but for tuples.
impl<'a, W: EncodedWriter> ser::SerializeTuple for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Same thing but for tuple structs.
impl<'a, W: EncodedWriter> ser::SerializeTupleStruct for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
// So the `end` method in this impl is responsible for closing both the `]` and
// the `}`.
impl<'a, W: EncodedWriter> ser::SerializeTupleVariant for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl<'a, W: EncodedWriter> ser::SerializeMap for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a, W: EncodedWriter> ser::SerializeStruct for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl<'a, W: EncodedWriter> ser::SerializeStructVariant for &'a mut MyDateSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

struct MyEnumSerializer<'a, W>
where
    W: EncodedWriter,
{
    output: &'a mut W,
    enum_resolver: Rc<dyn EnumResolver>,
    enum_name: &'a str,
}

impl<'a, W: EncodedWriter> MyEnumSerializer<'a, W> {
    pub fn new(
        output: &'a mut W,
        enum_name: &'a str,
        enum_resolver: Rc<dyn EnumResolver>,
    ) -> MyEnumSerializer<'a, W> {
        MyEnumSerializer {
            output,
            enum_resolver,
            enum_name,
        }
    }
}

impl<'a, W: EncodedWriter> ser::Serializer for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // JSON does not distinguish between different sizes of integers, so all
    // signed integers will be serialized the same and all unsigned integers
    // will be serialized the same. Other formats, especially compact binary
    // formats, may need independent logic for the different sizes.
    fn serialize_i8(self, _v: i8) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_i16(self, _v: i16) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.output.write_optional_tag()?;
        self.output
            .write_i32_enumeration(self.enum_name, v, self.enum_resolver.as_ref())?;
        Ok(())
    }

    // Not particularly efficient but this is example code anyway. A more
    // performant approach would be to use the `itoa` crate.
    fn serialize_i64(self, _v: i64) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u8(self, _v: u8) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u16(self, _v: u16) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u32(self, _v: u32) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_u64(self, _v: u64) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    fn serialize_char(self, _v: char) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, _v: &str) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, _v: &[u8]) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both serialize as just `null`. Unfortunately this is typically
    // what people expect when working with JSON. Other formats are encouraged
    // to behave more intelligently if possible.
    fn serialize_some<T>(self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    // In Serde, unit means an anonymous value containing no data. Map this to
    // JSON as `null`.
    fn serialize_unit(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
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
        _variant: &'static str,
        _value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
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
        Err(Error::UnsupportedType)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Err(Error::UnsupportedType)
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Err(Error::UnsupportedType)
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        Err(Error::UnsupportedType)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(Error::UnsupportedType)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Err(Error::UnsupportedType)
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Err(Error::UnsupportedType)
    }
}

impl<'a, W: EncodedWriter> ser::SerializeSeq for &'a mut MyEnumSerializer<'a, W> {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    // Close the sequence.
    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Same thing but for tuples.
impl<'a, W: EncodedWriter> ser::SerializeTuple for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Same thing but for tuple structs.
impl<'a, W: EncodedWriter> ser::SerializeTupleStruct for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
// So the `end` method in this impl is responsible for closing both the `]` and
// the `}`.
impl<'a, W: EncodedWriter> ser::SerializeTupleVariant for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl<'a, W: EncodedWriter> ser::SerializeMap for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a, W: EncodedWriter> ser::SerializeStruct for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl<'a, W: EncodedWriter> ser::SerializeStructVariant for &'a mut MyEnumSerializer<'a, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedType)
    }

    fn end(self) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use crate::{chrono::TimeZone, EnumResolver, TTLVError, Tag};
    use chrono::Utc;

    //use pretty_hex::hex_dump;
    use crate::de::to_print;
    use pretty_hex::PrettyHex;

    use crate::my_date_format;
    use crate::ser::to_bytes;

    struct TestEnumResolver;

    impl EnumResolver for TestEnumResolver {
        fn resolve_enum(&self, _name: &str, _value: i32) -> Result<String, TTLVError> {
            unimplemented! {}
        }
        fn resolve_enum_str(
            &self,
            _tag: crate::kmip_enums::Tag,
            _value: &str,
        ) -> std::result::Result<i32, TTLVError> {
            unimplemented! {}
        }

        fn to_string(&self, _tag: Tag, _value: i32) -> std::result::Result<String, TTLVError> {
            unimplemented!();
        }
    }

    #[test]
    fn test_struct() {
        #[derive(Serialize, Debug)]
        struct RequestHeader {
            #[serde(rename = "ProtocolVersionMajor")]
            pub protocol_version_major: i32,

            #[serde(rename = "ProtocolVersionMinor")]
            pub protocol_version_minor: i32,

            #[serde(skip_serializing_if = "Option::is_none", rename = "BatchOrderOption")]
            batch_order_option: Option<i32>,
            // Option::None - serializes as serialize_none()
            // TODO: Other fields are optional
            #[serde(rename = "BatchCount")]
            batch_count: i32,
        }

        let a = RequestHeader {
            protocol_version_major: 1,
            protocol_version_minor: 2,
            batch_order_option: None,
            batch_count: 3,
        };

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());

        let good = vec![
            0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x6a, 0x02, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00,
            0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(v.len(), 56);

        assert_eq!(v, good);
    }

    #[test]
    fn test_struct_nested() {
        #[derive(Serialize, Debug)]
        struct RequestHeader {
            #[serde(rename = "ProtocolVersionMajor")]
            protocol_version_major: i32,
            #[serde(rename = "BatchCount")]
            batch_count: i32,
        }

        #[derive(Serialize, Debug)]
        struct RequestMessage {
            #[serde(rename = "RequestHeader")]
            request_header: RequestHeader,

            #[serde(rename = "UniqueIdentifier")]
            unique_identifier: String,
        }

        let a = RequestMessage {
            request_header: RequestHeader {
                protocol_version_major: 3,
                batch_count: 4,
            },
            unique_identifier: String::new(),
        };

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());

        let good = vec![
            66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0,
            0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7,
            0, 0, 0, 0,
        ];

        assert_eq!(v.len(), 56);

        assert_eq!(v, good);
    }

    #[test]
    fn test_struct_nested2() {
        #[derive(Serialize, Debug)]
        struct ObjectType {
            #[serde(rename = "UniqueIdentifier")]
            unique_identifier: String,
        }

        #[derive(Serialize, Debug)]
        struct RequestHeader {
            #[serde(rename = "ProtocolVersionMinor")]
            protocol_version_minor: ObjectType,

            #[serde(rename = "BatchCount")]
            batch_count: i32,
        }

        let a = RequestHeader {
            protocol_version_minor: ObjectType {
                unique_identifier: String::new(),
            },
            batch_count: 3,
        };

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());

        let good = vec![
            66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 107, 1, 0, 0, 0, 8, 66, 0, 148, 7, 0, 0, 0, 0, 66,
            0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0,
        ];

        assert_eq!(v.len(), 40);

        assert_eq!(v, good);
    }

    #[test]
    fn test_struct_types() {
        #[derive(Serialize, Debug)]
        struct RequestHeader<'a> {
            #[serde(rename = "ProtocolVersionMajor")]
            protocol_version_major: String,

            #[serde(with = "serde_bytes", rename = "ProtocolVersionMinor")]
            protocol_version_minor: &'a [u8],

            #[serde(rename = "BatchCount")]
            batch_count: i64,
        }

        let v = vec![0x55, 0x66, 0x77];
        let a = RequestHeader {
            protocol_version_major: String::new(),
            protocol_version_minor: v.as_slice(),
            batch_count: 3,
        };

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());
        assert_eq!(v.len(), 48);
    }

    #[test]
    fn test_struct2() {
        #[derive(Serialize, Debug)]
        #[serde(tag = "Operation", content = "BatchItem")]
        enum CRTCoefficient {
            Attribute(Vec<u8>),
            CertificateRequest(String),
        }

        let a = CRTCoefficient::CertificateRequest(String::new());
        let _b = CRTCoefficient::Attribute(vec![0x1]);

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());

        let good = vec![
            66, 0, 39, 1, 0, 0, 0, 40, 66, 0, 92, 7, 0, 0, 0, 18, 67, 101, 114, 116, 105, 102, 105,
            99, 97, 116, 101, 82, 101, 113, 117, 101, 115, 116, 0, 0, 0, 0, 0, 0, 66, 0, 15, 7, 0,
            0, 0, 0,
        ];

        assert_eq!(v.len(), 48);

        assert_eq!(v, good);
    }

    #[test]
    fn test_struct3() {
        #[derive(Serialize, Debug)]
        struct CRTCoefficient {
            #[serde(rename = "BatchCount")]
            batch_count: Vec<i32>,
        }

        let a = CRTCoefficient {
            batch_count: vec![0x66, 0x77, 0x88],
        };

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());

        let good = vec![
            66, 0, 39, 1, 0, 0, 0, 48, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 102, 0, 0, 0, 0, 66, 0,
            13, 2, 0, 0, 0, 4, 0, 0, 0, 119, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 136, 0,
            0, 0, 0,
        ];

        assert_eq!(v.len(), 56);

        assert_eq!(v, good);
    }

    #[test]
    fn test_datetime() {
        #[derive(Serialize, Debug)]
        struct CRTCoefficient {
            #[serde(with = "my_date_format", rename = "BatchCount")]
            batch_count: chrono::DateTime<Utc>,
        }

        let a = CRTCoefficient {
            batch_count: chrono::Utc.timestamp(123456, 0),
        };

        let r = Rc::new(TestEnumResolver {});
        let v = to_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", v.hex_dump());

        to_print(v.as_slice());

        let good = vec![
            66, 0, 39, 1, 0, 0, 0, 16, 66, 0, 13, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 1, 226, 64,
        ];

        assert_eq!(v.len(), 24);

        assert_eq!(v, good);
    }
}
