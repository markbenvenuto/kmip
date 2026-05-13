use std::str::{self};

use chrono::TimeZone;
use xml::writer::{EmitterConfig, XmlEvent};

use crate::{de_xml::EnumResolver, error::TTLVError, kmip_enums::*, ser::EncodedWriter};

type TTLVResult<T> = std::result::Result<T, TTLVError>;

pub struct XmlNestedWriter<'a> {
    writer: xml::writer::EventWriter<std::vec::Vec<u8>>,
    tag: Option<Tag>,
    // In XML, when serializing AttibuteValue, we need to serialize from the values of a different
    // Tag Enumeration
    attribute_tag: Option<Tag>,

    enum_resolver: &'a dyn EnumResolver,
}

impl<'a> XmlNestedWriter<'a> {
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

    pub fn new(resolver: &'a dyn EnumResolver) -> XmlNestedWriter<'a> {
        let vec = Vec::new();
        XmlNestedWriter {
            tag: None,
            attribute_tag: None,
            writer: EmitterConfig::new().create_writer(vec),
            enum_resolver: resolver,
        }
    }
}

impl<'a> EncodedWriter for XmlNestedWriter<'a> {
    fn get_vector(self) -> Vec<u8> {
        self.writer.into_inner()
    }

    fn write_tag(&mut self, tag: Tag) -> TTLVResult<()> {
        self.tag = Some(tag);
        self.attribute_tag = None;
        // self.writer
        //     .write(XmlEvent::start_element(tag.as_ref()))
        //     .map_err(|_| TTLVError::XmlError)
        Ok(())
    }

    fn set_attribute_tag(&mut self, tag: Tag) -> TTLVResult<()> {
        self.attribute_tag = Some(tag);
        Ok(())
    }

    fn write_boolean(&mut self, v: bool) -> TTLVResult<()> {
        self.write_element(self.tag.unwrap().as_ref(), "Boolean", &v.to_string())
    }

    fn write_i32(&mut self, v: i32) -> TTLVResult<()> {
        // TODO special case masks - 5.4.1.6.4 Integer - Special case for Masks
        //  (Cryptographic Usage Mask, Storage Status Mask):

        let tag = self.tag.unwrap();

        // TODO - cannot make this work until change  to stop being an i32
        // if tag == Tag::CryptographicUsageMask {
        //     let mut buffer = String::new();

        //     let max_bit =
        //         f32::log2(CryptographicUsageMask::TranslateUnwrap as usize as f32) as usize;
        //     for i in 0..max_bit {
        //         let bit: i32 = 1 << i;
        //         if (v & bit) == 1 {
        //             if buffer.is_empty() {
        //                 buffer.push(' ');
        //             }
        //             let o: CryptographicUsageMask = num::FromPrimitive::from_i32(bit).unwrap();
        //             let s = o.as_static();
        //             buffer.push_str(s);
        //         }
        //     }

        //     return self.write_element(tag.as_ref(), "Integer", &buffer);
        // }

        self.write_element(tag.as_ref(), "Integer", &v.to_string())
    }

    fn write_u32_enumeration(&mut self, v: u32) -> TTLVResult<()> {
        let element_tag = self.attribute_tag.or(self.tag).unwrap();
        self.write_element(
            self.tag.unwrap().as_ref(),
            "Enumeration",
            &self.enum_resolver.to_string(element_tag, v)?,
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

    fn write_struct_start(&mut self) -> TTLVResult<()> {
        self.writer
            .write(XmlEvent::start_element(self.tag.unwrap().as_ref()))
            .map_err(|_| TTLVError::XmlError)
    }

    fn begin_inner(&mut self) -> TTLVResult<()> {
        self.tag = None;

        Ok(())
    }

    fn close_inner(&mut self) -> TTLVResult<()> {
        self.tag = None;

        self.writer
            .write(XmlEvent::end_element())
            .map_err(|_| TTLVError::XmlError)
    }
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
// pub fn to_xml_bytes<'a, T>(value: &T, enum_resolver: Rc<dyn EnumResolver>) -> Result<Vec<u8>>
// where
//     T: Serialize,
// {
//     let mut serializer = Serializer {
//         output: NestedWriter::new(),
//         enum_resolver: enum_resolver,
//     };
//     value.serialize(&mut serializer)?;
//     Ok(serializer.output.get_vector())
// }

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_struct() {
    //     #[derive(Serialize, Debug)]
    //     struct RequestHeader {
    //         #[serde(rename = "ProtocolVersionMajor")]
    //         pub protocol_version_major: i32,

    //         #[serde(rename = "ProtocolVersionMinor")]
    //         pub protocol_version_minor: i32,

    //         #[serde(skip_serializing_if = "Option::is_none", rename = "BatchOrderOption")]
    //         batch_order_option: Option<i32>,
    //         // Option::None - serializes as serialize_none()
    //         // TODO: Other fields are optional
    //         #[serde(rename = "BatchCount")]
    //         batch_count: i32,
    //     }

    //     let a = RequestHeader {
    //         protocol_version_major: 1,
    //         protocol_version_minor: 2,
    //         batch_order_option: None,
    //         batch_count: 3,
    //     };

    //     let r = Rc::new(TestEnumResolver {});
    //     let v = to_xml_bytes(&a, r).unwrap();

    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\"
    // encoding=\"utf-8\"?><RequestHeader><ProtocolVersionMajor type=\"Integer\" value=\"1\"
    // /><ProtocolVersionMinor type=\"Integer\" value=\"2\" /><BatchCount type=\"Integer\"
    // value=\"3\" /></RequestHeader>";

    //     assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
    //     let v = to_xml_bytes(&a, r).unwrap();
    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\"
    // encoding=\"utf-8\"?><RequestMessage><RequestHeader><ProtocolVersionMajor type=\"Integer\"
    // value=\"3\" /><BatchCount type=\"Integer\" value=\"4\" /></RequestHeader><UniqueIdentifier
    // type=\"TextString\" value=\"\" /></RequestMessage>";

    //     assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
    //     let v = to_xml_bytes(&a, r).unwrap();
    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\"
    // encoding=\"utf-8\"?><RequestHeader><ProtocolVersionMinor><UniqueIdentifier
    // type=\"TextString\" value=\"\" /></ProtocolVersionMinor><BatchCount type=\"Integer\"
    // value=\"3\" /></RequestHeader>";

    //     assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
    //     let v = to_xml_bytes(&a, r).unwrap();
    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\"
    // encoding=\"utf-8\"?><RequestHeader><ProtocolVersionMajor type=\"TextString\" value=\"\"
    // /><ProtocolVersionMinor type=\"ByteString\" value=\"556677\" /><BatchCount
    // type=\"LongInteger\" value=\"3\" /></RequestHeader>";     assert_eq!
    // (std::str::from_utf8(&v).unwrap(), good); }

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
    //     let v = to_xml_bytes(&a, r).unwrap();
    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient><Operation
    // type=\"TextString\" value=\"CertificateRequest\" /><BatchItem type=\"TextString\" value=\"\"
    // /></CRTCoefficient>";

    //     assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
    //     let v = to_xml_bytes(&a, r).unwrap();
    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient><BatchCount
    // type=\"Integer\" value=\"102\" /><BatchCount type=\"Integer\" value=\"119\" /><BatchCount
    // type=\"Integer\" value=\"136\" /></CRTCoefficient>";

    //     assert_eq!(std::str::from_utf8(&v).unwrap(), good);
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
    //     let v = to_xml_bytes(&a, r).unwrap();
    //     print!("Dump of bytes {:?}", std::str::from_utf8(&v));

    //     let good = "<?xml version=\"1.0\" encoding=\"utf-8\"?><CRTCoefficient><BatchCount
    // type=\"DateTime\" value=\"1970-01-02T10:17:36+00:00\" /></CRTCoefficient>";

    //     assert_eq!(std::str::from_utf8(&v).unwrap(), good);
    // }
}
