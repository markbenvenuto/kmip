use std::io::Cursor;

use std::string::ToString;

use serde::Deserialize;

use crate::error::{Error, Result};

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

extern crate byteorder;

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
    item_type : ItemType,
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
    last_attribute_tag: Option<Tag>,
}

impl<'a> XmlEncodingReader<'a> {

fn is_empty2(&mut self) -> TTLVResult<bool> {
    // eprintln!("is_empty: ");
    if self.end_document {
        return Ok(true);
    }


    self.read_one_element()?;
    if self.end_document {
        return Ok(true);
    }

    Ok(*(self.cur_depths.last().unwrap()) == self.depth)
}


fn read_one_event(&mut self)  -> TTLVResult<Option<XmlItem>>  {
    let x = self.reader.next().map_err(|_| TTLVError::XmlError)?;
    match x {
        // Ignore StartDocument
        XmlEvent::StartElement{name, attributes, ..} => {
            eprintln!("Read Element: {} - {:?}", name, attributes);

            let name = name.local_name;
            let item_type = attributes.iter().find(|i| i.name.local_name == "type" );
            let value = attributes.iter().find(|i| i.name.local_name == "value" ).map(|x| x.value.to_string());

            // If type is missing, the default is Structure
            let item_type_enum = match item_type {
                Some(x) => ItemType::from_str(&x.value).map_err(|_| TTLVError::XmlError)?,
                None => ItemType::Structure
            };

            self.depth += 1;
            Ok(Some(XmlItem {
                name: name,
                item_type : item_type_enum,
                value : value,
            }))
        },
        XmlEvent::EndElement{..} => {
            // eprintln!("Read End Element");
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
            last_attribute_tag : None,
        };
    }

    fn begin_inner_or_more(&mut self) -> TTLVResult<()> {
        // eprintln!("begin_inner_or_more");
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
        // eprintln!("begin_inner_skip");
        assert_eq!(self.state, ReaderState::LengthValue);

        //println!(" read_inner_skip: {:?} - {:?}", len, self.cur.position());
        self.cur_depths.push(self.depth);
        self.state = ReaderState::Tag;
        self.element = None;
        Ok(())
    }

    fn close_inner(&mut self) {
        // eprintln!(" close_inner");
        self.cur_depths.pop().unwrap();
    }

    fn is_empty(&mut self) -> TTLVResult<bool> {
        let e = self.is_empty2();
//        eprintln!("is_empty {:?} {:?} == {:?}",e , self.depth, (self.cur_depths.last().unwrap()));
    //    eprintln!("is_empty {:?} {:?}",e , self.depth);
        e
    }


    fn read_type(&mut self) -> TTLVResult<ItemType> {
        // eprintln!("read_type");
        assert_eq!(self.state, ReaderState::Type);
        self.state = ReaderState::LengthValue;


       Ok( self.element.as_ref().unwrap().item_type)

    }

    fn read_type_and_check(&mut self, expected: ItemType) -> TTLVResult<()> {
        // eprintln!("read_type_and_check");
        assert_eq!(self.state, ReaderState::Type);
        self.state = ReaderState::LengthValue;
        let t = self.element.as_ref().unwrap().item_type;
        if t!=expected {
            return Err(TTLVError::UnexpectedType{actual: t, expected : expected})
        }

        Ok(())
    }

    fn is_tag(&self) -> bool {
        self.state == ReaderState::Tag
    }

    fn get_tag(&self) -> Tag {
        // eprintln!("get_tag");
        return self.tag.unwrap();
    }

    fn read_tag(&mut self) -> TTLVResult<Tag> {
        // eprintln!("read_tag");
        assert_eq!(self.state, ReaderState::Tag);
        self.state = ReaderState::Type;
        self.read_one_element()?;

        let t = Tag::from_str(&self.element.as_ref().unwrap().name).map_err(|_| TTLVError::XmlError)?;
        self.tag = Some(t);
        return Ok(t);
    }

    fn peek_tag(&mut self) -> TTLVResult<Tag> {
        // eprintln!("peek_tag");
        assert_eq!(self.state, ReaderState::Tag);

        let tag = Tag::from_str(&self.element.as_ref().unwrap().name).map_err(|_| TTLVError::XmlError)?;

        return Ok(tag);
    }

    fn reverse_tag(&mut self) {
        // eprintln!("reverse_tag");
        assert_eq!(self.state, ReaderState::Type);
        self.state = ReaderState::Tag;
    }

    fn read_i32(&mut self, enum_resolver: &'a dyn EnumResolver) -> TTLVResult<i32> {
        // eprintln!("read_i32");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        // Special case
        // Per 2.1: 5.4.1.6.4 - (Cryptographic Usage Mask, Storage Status Mask) are special and may be strings
       let value = self.element.as_ref().unwrap().value.as_ref().unwrap();
        let parse_ret = value.parse::<i32>();
        let valuei: i32;
        if self.tag == Some(Tag::AttributeValue) {
            valuei = match self.last_attribute_tag.unwrap() {
                Tag::CryptographicUsageMask => {
                     match parse_ret {
                        Ok(i) => i,
                        Err(_) => {
                            let mut iv: i32 = 0;
                                  // Resolve as string for enum
                for ev in value.split(" ") {
                    iv |= enum_resolver.resolve_enum_str(Tag::CryptographicUsageMask, ev).unwrap();
                }
                            iv
                        }
                    }
                },
                Tag::StorageStatusMask => {
                    unimplemented!();
                }
                _ => {
                    parse_ret.map_err(|_| TTLVError::XmlError)?
                }
            }
        } else {
            valuei = parse_ret.map_err(|_| TTLVError::XmlError)?;

        }
 
        self.element = None;
        Ok(valuei)
    }

    fn read_enumeration(&mut self, enum_resolver: &'a dyn EnumResolver) -> TTLVResult<i32> {
        // eprintln!("read_enumeration");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        // TODO - this can either be a hex string or camel case enum text per 5.4.1.6.7
        let input_str = self.element.as_ref().unwrap().value.as_ref().unwrap();

        let mut value:i32;
        if input_str.starts_with("0x") {
            let without_prefix = input_str.trim_start_matches("0x");
            value = i32::from_str_radix(without_prefix, 16).map_err(|_| TTLVError::XmlError)?;
        } else {
            value = 0;
            let tag = match self.last_attribute_tag {
                Some(t) => t,
                None => self.tag.unwrap(),
            };

            // Resolve as string for enum
            for ev in input_str.split(" ") {
                value |= enum_resolver.resolve_enum_str(tag, ev).unwrap();
            }

        }


        self.element = None;
        self.last_attribute_tag = None;
        Ok(value)
    }

    fn read_i64(&mut self) -> TTLVResult<i64> {
        // eprintln!("read_i64");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        let value = self.element.as_ref().unwrap().value.as_ref().unwrap().parse::<i64>().map_err(|_| TTLVError::XmlError)?;
        self.element = None;
        Ok(value)
    }

    fn read_datetime_i64(&mut self) -> TTLVResult<i64> {
        // eprintln!("read_datetime_i64");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
           // TODO
        let value = 1;
        self.element = None;
        Ok(value)
    }

    fn read_string(&mut self) -> TTLVResult<String> {
        // eprintln!("read_string");
        assert_eq!(self.state, ReaderState::LengthValue);
        self.state = ReaderState::Tag;
        let value = self.element.as_ref().unwrap().value.as_ref().unwrap().to_string();

        // Buffer the attribute name so that enumerations can be decoded not as AttributeValue, but their real enumeration value

        if self.tag == Some(Tag::AttributeName) {
            let trimmed = value.replace(" ", "");
            let name = trimmed.as_ref();
            self.last_attribute_tag = Some(Tag::from_str(name).map_err(|_| TTLVError::XmlError)?)
        }

        self.element = None;
        Ok(value)
    }

    fn read_bytes(&mut self) -> TTLVResult<Vec<u8>> {
        // eprintln!("read_bytes");
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
    use chrono::Utc;

    //use pretty_hex::hex_dump;
    use crate::{Tag, de_xml::from_xml_bytes};
    use crate::my_date_format;
    use crate::EnumResolver;
    use crate::TTLVError;

    struct TestEnumResolver;

    impl EnumResolver for TestEnumResolver {
        fn resolve_enum(&self, _name: &str, _value: i32) -> Result<String, TTLVError> {
            unimplemented! {}
        }
        fn resolve_enum_str(&self, _tag : crate::kmip_enums::Tag, _value: &str) -> std::result::Result<i32, TTLVError> {
            unimplemented! {}
        }

        fn to_string(&self, tag: Tag, value: i32) -> std::result::Result<String, TTLVError> {
            unimplemented!();
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

        // Structure is defaulted
        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestHeader><ProtocolVersionMajor type=\"Integer\" value=\"1\" /><ProtocolVersionMinor type=\"Integer\" value=\"2\" /><BatchCount type=\"Integer\" value=\"3\" /></RequestHeader>";

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
