use serde::Serialize;

use crate::chrono::TimeZone;
use crate::{
    error::Result,
    ser::{EncodedWriter, Serializer},
    EnumResolver,
};
use std::{rc::Rc, str};

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

extern crate byteorder;

//use self::enums;
use crate::kmip_enums::*;

use crate::failures::*;

use xml::writer::{EmitterConfig, XmlEvent};

type TTLVResult<T> = std::result::Result<T, TTLVError>;

struct NestedWriter {
    writer: xml::writer::EventWriter<std::vec::Vec<u8>>,
    tag: Option<Tag>,
}

impl NestedWriter {
    fn write_element(&mut self, name: &str, type_name: &str, value: &str) -> TTLVResult<()> {
        // TODO - normalize names per 5.4.1.1 Normalizing Names
        self.writer
            .write(
                XmlEvent::start_element(name)
                    .attr("type", type_name)
                    .attr("value", value),
            )
            .map_err(|_| TTLVError::XmlError)?;
        self.writer
            .write(XmlEvent::end_element())
            .map_err(|_| TTLVError::XmlError)
    }
}

impl EncodedWriter for NestedWriter {
    fn new() -> NestedWriter {
        let vec = Vec::new();
        return NestedWriter {
            tag: None,
            writer: EmitterConfig::new().create_writer(vec),
        };
    }

    fn get_vector(self) -> Vec<u8> {
        return self.writer.into_inner();
    }

    fn set_tag(&mut self, tag: Tag) {
        self.tag = Some(tag)
    }

    fn write_optional_tag(&mut self) -> TTLVResult<()> {
        Ok(())
    }

    fn write_i32(&mut self, v: i32) -> TTLVResult<()> {
        // TODO special case masks - 5.4.1.6.4 Integer - Special case for Masks
        //  (Cryptographic Usage Mask, Storage Status Mask):
        self.write_element(self.tag.unwrap().as_ref(), "Integer", &v.to_string())
    }

    fn write_i32_enumeration(
        &mut self,
        v: i32,
        enum_resolver: &dyn EnumResolver,
    ) -> TTLVResult<()> {
        // TODO - write as hex string or camelCase per 5.4.1.6.7

        let tag = self.tag.unwrap();
        self.write_element(
            tag.as_ref(),
            "Enumeration",
            &enum_resolver.to_string(tag, v)?,
        )
    }
    fn write_i64(&mut self, v: i64) -> TTLVResult<()> {
        self.write_element(self.tag.unwrap().as_ref(), "LongInteger", &v.to_string())
    }
    fn write_i64_datetime(&mut self, v: i64) -> TTLVResult<()> {
        // TODO - to_rfc3339 can panic if the datetime is bad
        let dt = chrono::Utc.timestamp(v, 0);
        self.write_element(self.tag.unwrap().as_ref(), "DateTime", &dt.to_rfc3339())
    }

    fn write_string(&mut self, v: &str) -> TTLVResult<()> {
        self.write_element(self.tag.unwrap().as_ref(), "TextString", &v.to_string())
    }

    fn write_bytes(&mut self, v: &[u8]) -> TTLVResult<()> {
        self.write_element(self.tag.unwrap().as_ref(), "ByteString", &hex::encode(v))
    }

    fn write_tag_enum(&mut self, t: Tag) -> TTLVResult<()> {
        // This starts a struct
        // TODO - omit type as it is the default
        // self.writer.write( XmlEvent::start_element(t.as_ref()).attr("type", "Structure")).map_err(|_| TTLVError::XmlError)
        self.writer
            .write(XmlEvent::start_element(t.as_ref()))
            .map_err(|_| TTLVError::XmlError)
    }

    fn write_struct_start(&mut self) -> TTLVResult<()> {
        Ok(())
    }

    fn begin_inner(&mut self) -> TTLVResult<()> {
        //println!("write_innter");
        // let pos = self.vec.len();
        // self.vec
        //     .write_u32::<BigEndian>(0)
        //     .map_err(|error| TTLVError::BadWrite { count: 4, error })?;
        // self.start_positions.push(pos);
        // self.writer
        //     .write(XmlEvent::start_element("foo").attr("type", "Structure"))
        //     .map_err(|_| TTLVError::XmlError)
        //self.writer.write( XmlEvent::start_element(self.tag.unwrap().as_ref()).attr("type", "Structure")).map_err(|_| TTLVError::XmlError)
        Ok(())
    }

    fn close_inner(&mut self) -> TTLVResult<()> {
        // let current_pos = self.vec.len();
        // let start_pos = self.start_positions.pop().unwrap();
        // // offset by 4
        // let len = current_pos - start_pos - 4;

        // let mut v1: Vec<u8> = Vec::new();
        // v1.write_u32::<BigEndian>(len as u32)
        //     .map_err(|error| TTLVError::BadWrite { count: 4, error })?;

        // for i in 0..4 {
        //     self.vec[start_pos + i] = v1[i];
        // }
        self.writer
            .write(XmlEvent::end_element())
            .map_err(|_| TTLVError::XmlError)
    }
}

// impl Write for NestedWriter {
//     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//         return self.vec.write(buf);
//     }

//     fn flush(&mut self) -> std::io::Result<()> {
//         return Ok(());
//     }
// }

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
pub fn to_xml_bytes<'a, T>(value: &T, enum_resolver: Rc<dyn EnumResolver>) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: NestedWriter::new(),
        enum_resolver: enum_resolver,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output.get_vector())
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use crate::{chrono::TimeZone, EnumResolver, TTLVError, Tag};
    use chrono::Utc;

    use crate::my_date_format;
    use crate::ser_xml::to_xml_bytes;

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
        fn to_string(&self, tag: Tag, value: i32) -> std::result::Result<String, TTLVError> {
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
        let v = to_xml_bytes(&a, r).unwrap();

        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestHeader type=\"Structure\"><ProtocolVersionMajor type=\"Integer\" value=\"1\" /><ProtocolVersionMinor type=\"Integer\" value=\"2\" /><BatchCount type=\"Integer\" value=\"3\" /></RequestHeader>";

        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
        let v = to_xml_bytes(&a, r).unwrap();
        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestMessage type=\"Structure\"><RequestHeader type=\"Structure\"><ProtocolVersionMajor type=\"Integer\" value=\"3\" /><BatchCount type=\"Integer\" value=\"4\" /></RequestHeader><UniqueIdentifier type=\"TextString\" value=\"\" /></RequestMessage>";

        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
        let v = to_xml_bytes(&a, r).unwrap();
        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestHeader type=\"Structure\"><ObjectType type=\"Structure\"><UniqueIdentifier type=\"TextString\" value=\"\" /></ObjectType><BatchCount type=\"Integer\" value=\"3\" /></RequestHeader>";

        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
        let v = to_xml_bytes(&a, r).unwrap();
        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><RequestHeader type=\"Structure\"><ProtocolVersionMajor type=\"TextString\" value=\"\" /><ProtocolVersionMinor type=\"ByteString\" value=\"556677\" /><BatchCount type=\"LongInteger\" value=\"3\" /></RequestHeader>";
        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
        let v = to_xml_bytes(&a, r).unwrap();
        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient type=\"Structure\"><Operation type=\"TextString\" value=\"CertificateRequest\" /><BatchItem type=\"TextString\" value=\"\" /></CRTCoefficient>";

        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
        let v = to_xml_bytes(&a, r).unwrap();
        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient type=\"Structure\"><BatchCount type=\"Integer\" value=\"102\" /><BatchCount type=\"Integer\" value=\"119\" /><BatchCount type=\"Integer\" value=\"136\" /></CRTCoefficient>";

        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
        let v = to_xml_bytes(&a, r).unwrap();
        print!("Dump of bytes {:?}", std::str::from_utf8(&v));

        let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient type=\"Structure\"><BatchCount type=\"DateTime\" value=\"1970-01-02T10:17:36+00:00\" /></CRTCoefficient>";

        assert_eq!(std::str::from_utf8(&v).unwrap(), good);
    }
}
