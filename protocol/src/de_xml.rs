use std::io::Cursor;
use std::io::Read;

use std::string::ToString;

use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::Deserialize;

use crate::error::{Error, Result};

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt};
use pretty_hex::*;
//use self::enums;

use crate::kmip_enums::*;

use crate::failures::*;
extern crate hex;
use std::str::FromStr;
use crate::de::EnumResolver;

type TTLVResult<T> = std::result::Result<T, TTLVError>;

#[derive(PartialEq, Debug)]
enum ReaderState {
    Tag,
    Type,
    LengthValue,
}


use xml::reader::EventReader;
use xml::reader::XmlEvent;

struct XmlItem {
    name : String,
    itemType : ItemType,
    value : Option<String>,
}

struct XmlEncodingReader<'a> {
    reader: EventReader<std::io::Cursor<&'a [u8]>>,
    state: ReaderState,
    cur_depths: Vec<u64>,
    depth : u64,
    end_document: bool,
    tag: Option<Tag>,
    element: Option<XmlItem>,
}

impl<'a> XmlEncodingReader<'a> { 

fn is_empty2(&mut self) -> TTLVResult<bool> {
    eprintln!("is_empty: ");
    if self.end_document {
        return Ok(true);
    }


    self.read_one_element()?;
    if self.end_document {
        return Ok(true);
    }

    // println!(
    //     "cmp1 {:?} == {:?}",
    //     *(self.end_positions.last().unwrap()),
    //     self.cur.position()
    // );
    Ok(*(self.cur_depths.last().unwrap()) == self.depth)
}


fn read_one_event(&mut self)  -> TTLVResult<Option<XmlItem>>  {
    let x = self.reader.next().map_err(|_| TTLVError::XmlError)?;
    match x {
        // Ignore StartDocument
        XmlEvent::StartElement{name, attributes, ..} => {
            eprintln!("Read Element: {} - {:?}", name, attributes);

            let name = name.local_name;
            let itemType = attributes.iter().find(|i| i.name.local_name == "type" ).unwrap();
            let value = attributes.iter().find(|i| i.name.local_name == "value" ).map(|x| x.value.to_string());

            
            let itemTypeEnum = ItemType::from_str(&itemType.value).map_err(|_| TTLVError::XmlError)?;

            self.depth += 1;
            Ok(Some(XmlItem {
                name: name,
                itemType : itemTypeEnum,
                value : value,
            }))
        },
        XmlEvent::EndElement{..} => {
            eprintln!("Read End Element");
            self.depth -=1;
            Ok(None)
        },
        XmlEvent::EndDocument => {
            eprintln!("Read End Document");
            self.end_document = true;
            Ok(None)
        }
        _ => Ok(None)
    }
}

fn read_one_element(&mut self)  -> TTLVResult<()>  {
    
    while !self.end_document && self.element.is_none() {
        self.element =  self.read_one_event()?
    }

    Ok(())
}
}

use crate::de::EncodingReader;

impl<'a> EncodingReader<'a> for XmlEncodingReader <'a> {
    fn new(buf: &'a [u8]) -> XmlEncodingReader {
        let cur = Cursor::new(buf);
        return XmlEncodingReader {
            reader : EventReader::new(cur),
            state: ReaderState::Tag,
            cur_depths: Vec::new(),
            depth : 0,
            end_document: false,
            tag: None,
            element : None,
            
        };
    }

    fn begin_inner_or_more(&mut self) -> TTLVResult<()> {
        eprintln!("begin_inner_or_more");
        if self.state == ReaderState::Tag {
            self.element = None;
            self.read_one_element()?;

            //println!("read_inner: {:?} - {:?}", t, self.cur.position());
            self.state = ReaderState::Type;
        }

        if self.state == ReaderState::Type {
            self.read_type_and_check(ItemType::Structure)?;
            self.state = ReaderState::LengthValue;
        }

        self.begin_inner_skip()
    }

    fn begin_inner_skip(&mut self) -> TTLVResult<()> {
        eprintln!("begin_inner_skip");
        assert_eq!(self.state, ReaderState::LengthValue);

        //println!(" read_inner_skip: {:?} - {:?}", len, self.cur.position());
        self.cur_depths.push(self.depth);
        self.state = ReaderState::Tag;
        self.element = None;
        Ok(())
    }

    fn close_inner(&mut self) {
        eprintln!(" close_inner");
        self.cur_depths.pop().unwrap();
    }

    fn is_empty(&mut self) -> TTLVResult<bool> {
        let e = self.is_empty2();
//        eprintln!("is_empty {:?} {:?} == {:?}",e , self.depth, (self.cur_depths.last().unwrap()));
       eprintln!("is_empty {:?} {:?}",e , self.depth);
        e
    }


    fn read_type(&mut self) -> TTLVResult<ItemType> {
        eprintln!("read_type");
        assert_eq!(self.state, ReaderState::Type);
        self.state = ReaderState::LengthValue;
        
        
       Ok( self.element.as_ref().unwrap().itemType)

    }

    fn read_type_and_check(&mut self, expected: ItemType) -> TTLVResult<()> {
        eprintln!("read_type_and_check");
        assert_eq!(self.state, ReaderState::Type);
        self.state = ReaderState::LengthValue;
        let t = self.element.as_ref().unwrap().itemType;
        if t!=expected {
            return Err(TTLVError::UnexpectedType{actual: t, expected : expected})
        }

        Ok(())
    }

    fn is_tag(&self) -> bool {
        self.state == ReaderState::Tag
    }

    fn get_tag(&self) -> Tag {
        eprintln!("get_tag");
        return self.tag.unwrap();
    }

    fn read_tag(&mut self) -> TTLVResult<Tag> {
        eprintln!("read_tag");
        assert_eq!(self.state, ReaderState::Tag);
        self.state = ReaderState::Type;
        self.read_one_element()?;

        let t = Tag::from_str(&self.element.as_ref().unwrap().name).map_err(|_| TTLVError::XmlError)?;
        self.tag = Some(t);
        return Ok(t);
    }

    fn peek_tag(&mut self) -> TTLVResult<Tag> {
        eprintln!("peek_tag");
        assert_eq!(self.state, ReaderState::Tag);
        // let pos = self.cur.position();
        // let tag = read_tag_enum(&mut self.cur)?;
        // self.cur.set_position(pos);

        
        let tag = Tag::from_str(&self.element.as_ref().unwrap().name).map_err(|_| TTLVError::XmlError)?;

        return Ok(tag);
    }

    fn reverse_tag(&mut self) {
        eprintln!("reverse_tag");
        assert_eq!(self.state, ReaderState::Type);
        self.state = ReaderState::Tag;
        // let pos = self.cur.position();
        // self.cur.set_position(pos - 3);
    }

    fn read_i32(&mut self) -> TTLVResult<i32> {
        eprintln!("read_i32");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        let value = self.element.as_ref().unwrap().value.as_ref().unwrap().parse::<i32>().map_err(|_| TTLVError::XmlError)?;
        self.element = None;
        Ok(value)
    }

    fn read_enumeration(&mut self) -> TTLVResult<i32> {
        eprintln!("read_enumeration");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        //read_enumeration(&mut self.cur)
        // TODO
        let value = 1;
        self.element = None;
        Ok(value)
    }

    fn read_i64(&mut self) -> TTLVResult<i64> {
        eprintln!("read_i64");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        let value = self.element.as_ref().unwrap().value.as_ref().unwrap().parse::<i64>().map_err(|_| TTLVError::XmlError)?;
        self.element = None;
        Ok(value)
    }

    fn read_datetime_i64(&mut self) -> TTLVResult<i64> {
        eprintln!("read_datetime_i64");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
           // TODO
        let value = 1;
        self.element = None;
        Ok(value)
    }

    fn read_string(&mut self) -> TTLVResult<String> {
        eprintln!("read_string");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        let value = self.element.as_ref().unwrap().value.as_ref().unwrap().to_string();
        self.element = None;
        Ok(value)
    }

    fn read_bytes(&mut self) -> TTLVResult<Vec<u8>> {
        eprintln!("read_bytes");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        let value = hex::decode(&self.element.as_ref().unwrap().value.as_ref().unwrap()).map_err(|_| TTLVError::XmlError)?;
        self.element = None;
        Ok(value)
    }
}
////////////////////


// By convention, the public API of a Serde deserializer is one or more
// `from_xyz` methods such as `from_str`, `from_bytes`, or `from_reader`
// depending on what Rust types the deserializer is able to consume as input.
//
// This basic deserializer supports only `from_str`.

use crate::de::Deserializer;

pub fn from_xml_bytes<'a, T>(s: &'a [u8], enum_resolver: &'a dyn EnumResolver) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = Deserializer::<XmlEncodingReader>::from_bytes(s, enum_resolver);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty()? {
        Ok(t)
    } else {
        Err(Error::Eof)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use chrono::Utc;

    //use pretty_hex::hex_dump;
    use crate::de_xml::from_xml_bytes;
    use crate::my_date_format;
    use crate::EnumResolver;
    use crate::TTLVError;

    struct TestEnumResolver;

    impl EnumResolver for TestEnumResolver {
        fn resolve_enum(&self, _name: &str, _value: i32) -> Result<String, TTLVError> {
            unimplemented! {}
        }
    }

    #[test]
    fn test_de_struct() {
        #[derive(Deserialize, Debug)]
        struct RequestHeader {
            #[serde(rename = "ProtocolVersionMajor")]
            pub protocol_version_major: i32,

            #[serde(rename = "ProtocolVersionMinor")]
            pub protocol_version_minor: i32,

            // #[serde(skip_serializing_if = "Option::is_none")]
            // BatchOrderOption : Option<i32>,
            // Option::None - serializes as serialize_none()
            // TODO: Other fields are optional
     #[serde(rename = "BatchCount")]
    pub batch_count: i32,
        }

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestHeader type=\"Structure\"><ProtocolVersionMajor type=\"Integer\" value=\"1\" /><ProtocolVersionMinor type=\"Integer\" value=\"2\" /><BatchCount type=\"Integer\" value=\"3\" /></RequestHeader>";

        let r: TestEnumResolver = TestEnumResolver {};
        let a = from_xml_bytes::<RequestHeader>(&good.as_bytes(), &r).unwrap();

        assert_eq!(a.protocol_version_major, 1);
        assert_eq!(a.protocol_version_minor, 2);
        assert_eq!(a.batch_count, 3);
    }

    #[test]
    fn test_struct2() {
        #[derive(Deserialize, Debug)]
        #[serde(tag = "Operation", content = "BatchItem")]
        enum CRTCoefficient {
            Attribute(Vec<u8>),
            CertificateRequest(String),
        }

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient type=\"Structure\"><Operation type=\"TextString\" value=\"CertificateRequest\" /><BatchItem type=\"TextString\" value=\"\" /></CRTCoefficient>";

        let r: TestEnumResolver = TestEnumResolver {};
        let _a = from_xml_bytes::<CRTCoefficient>(&good.as_bytes(), &r).unwrap();
    }

    #[test]
    fn test_struct3() {
        #[derive(Deserialize, Debug)]
        struct CRTCoefficient {
     #[serde(rename = "BatchCount")]
    pub batch_count: Vec<i32>,
        }

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient type=\"Structure\"><BatchCount type=\"Integer\" value=\"102\" /><BatchCount type=\"Integer\" value=\"119\" /><BatchCount type=\"Integer\" value=\"136\" /></CRTCoefficient>";


        let r: TestEnumResolver = TestEnumResolver {};
        let _a = from_xml_bytes::<CRTCoefficient>(&good.as_bytes(), &r).unwrap();
    }

    #[test]
    fn test_datetime() {
        #[derive(Deserialize, Debug)]
        struct CRTCoefficient {
            #[serde(with = "my_date_format", rename="BatchCount")]
            batch_count: chrono::DateTime<Utc>,
        }


        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient type=\"Structure\"><BatchCount type=\"DateTime\" value=\"1973-11-29T21:20:00+00:00\" /></CRTCoefficient>";


        let r: TestEnumResolver = TestEnumResolver {};
        let _a = from_xml_bytes::<CRTCoefficient>(&good.as_bytes(), &r).unwrap();
    }

    #[test]
    fn test_struct_nested() {
        #[derive(Deserialize, Debug)]
        struct RequestHeader {
            #[serde(rename = "ProtocolVersionMajor")]
            pub protocol_version_major: i32,
            #[serde(rename = "BatchCount")]
            pub batch_count: i32,
        }

        #[derive(Deserialize, Debug)]
        struct RequestMessage {
    #[serde(rename = "RequestHeader")]
            request_header: RequestHeader,
    #[serde(rename = "UniqueIdentifier")]
            unique_identifier: String,
        }


        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestMessage type=\"Structure\"><RequestHeader type=\"Structure\"><ProtocolVersionMajor type=\"Integer\" value=\"3\" /><BatchCount type=\"Integer\" value=\"4\" /></RequestHeader><UniqueIdentifier type=\"TextString\" value=\"\" /></RequestMessage>";


        let r: TestEnumResolver = TestEnumResolver {};
        let _a = from_xml_bytes::<RequestMessage>(&good.as_bytes(), &r).unwrap();
    }

}
