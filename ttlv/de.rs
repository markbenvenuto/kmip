use serde::{ser, Serialize};

use error::{Error, Result};



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

