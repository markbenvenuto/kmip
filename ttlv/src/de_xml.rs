use std::{io::Cursor, str::FromStr};

use xml::reader::{EventReader, XmlEvent};

use crate::{
    de::Reader,
    error::TTLVError,
    kmip_enums::{ItemType, Tag, Value, ValueType},
};

type TTLVResult<T> = std::result::Result<T, TTLVError>;

pub trait EnumResolver {
    fn resolve(&self, tag: Tag, value: &str) -> TTLVResult<u32>;

    fn to_string(&self, tag: Tag, value: u32) -> TTLVResult<String>;
}

pub struct XmlReader<'a> {
    reader: EventReader<Cursor<&'a [u8]>>,
    struct_stack: Vec<(Tag, u64)>,
    depth: u64,
    enum_resolver: &'a dyn EnumResolver,
    peeked: Option<TTLVResult<Value>>,
    last_attribute_tag: Option<Tag>,
}

impl<'a> XmlReader<'a> {
    pub fn new(buf: &'a [u8], resolver: &'a dyn EnumResolver) -> Self {
        Self {
            reader: EventReader::new(Cursor::new(buf)),
            struct_stack: Vec::new(),
            depth: 0,
            enum_resolver: resolver,
            peeked: None,
            last_attribute_tag: None,
        }
    }

    fn read_inner(&mut self) -> Option<TTLVResult<Value>> {
        loop {
            let event = match self.reader.next() {
                Ok(e) => e,
                Err(e) => {
                    return Some(Err(TTLVError::XmlReadError {
                        message: e.to_string(),
                    }));
                }
            };

            match event {
                XmlEvent::StartElement {
                    name, attributes, ..
                } => {
                    self.depth += 1;
                    let local_name = name.local_name;

                    if local_name == "KMIP" {
                        continue;
                    }

                    let tag = match Tag::from_str(&local_name) {
                        Ok(t) => t,
                        Err(_) => return Some(Err(TTLVError::InvalidTagName { name: local_name })),
                    };

                    let type_attr = attributes.iter().find(|a| a.name.local_name == "type");

                    match type_attr {
                        None => {
                            println!("X Tag:{:?}", tag);

                            self.struct_stack.push((tag, self.depth));
                            return Some(Ok(Value {
                                tag,
                                value: ValueType::StructureBegin(0),
                            }));
                        }
                        Some(type_attr) => {
                            println!("XV Tag:{:?}", tag);
                            let item_type = match ItemType::from_str(&type_attr.value) {
                                Ok(t) => t,
                                Err(e) => {
                                    return Some(Err(TTLVError::XmlReadError {
                                        message: e.to_string(),
                                    }));
                                }
                            };

                            let value_str = attributes
                                .iter()
                                .find(|a| a.name.local_name == "value")
                                .map(|a| a.value.as_str())
                                .unwrap_or("");

                            let value_type = match self.parse_value(
                                tag,
                                item_type,
                                value_str,
                                self.enum_resolver,
                            ) {
                                Ok(v) => v,
                                Err(e) => return Some(Err(e)),
                            };

                            return Some(Ok(Value {
                                tag,
                                value: value_type,
                            }));
                        }
                    }
                }

                XmlEvent::EndElement { .. } => {
                    if let Some(&(struct_tag, struct_depth)) = self.struct_stack.last() {
                        if self.depth == struct_depth {
                            self.struct_stack.pop();
                            self.depth -= 1;
                            return Some(Ok(Value {
                                tag: struct_tag,
                                value: ValueType::StructureEnd,
                            }));
                        }
                    }
                    self.depth -= 1;
                }

                XmlEvent::EndDocument => return None,

                _ => {}
            }
        }
    }

    fn parse_value(
        &mut self,
        tag: Tag,
        item_type: ItemType,
        value: &str,
        resolver: &dyn EnumResolver,
    ) -> TTLVResult<ValueType> {
        match item_type {
            ItemType::Integer => {
                // Special work around for Bit mask
                // println!("Parse integer tag: {tag:?}");
                if tag == Tag::AttributeValue {
                    if let Some(last_attribute_tag) = self.last_attribute_tag {
                        if last_attribute_tag == Tag::CryptographicUsageMask {
                            let mut iv: i32 = 0;

                            for ev in value.split(' ') {
                                iv |= resolver.resolve(Tag::CryptographicUsageMask, ev).unwrap()
                                    as i32;
                            }

                            return Ok(ValueType::Integer(iv));
                        } else if last_attribute_tag == Tag::StorageStatusMask {
                            unimplemented!();
                        }

                        self.last_attribute_tag = None;
                    }
                }

                value
                    .parse::<i32>()
                    .map(ValueType::Integer)
                    .map_err(|e| TTLVError::XmlReadError {
                        message: format!("Parse integer as: {}", e.to_string()),
                    })
            }

            ItemType::LongInteger => {
                value
                    .parse::<i64>()
                    .map(ValueType::LongInteger)
                    .map_err(|e| TTLVError::XmlReadError {
                        message: e.to_string(),
                    })
            }

            ItemType::Enumeration => {
                let num = if value.starts_with("0x") || value.starts_with("0X") {
                    u32::from_str_radix(&value[2..], 16).map_err(|e| TTLVError::XmlReadError {
                        message: e.to_string(),
                    })
                } else {
                    if tag == Tag::AttributeValue
                        && let Some(last_attribute_tag) = self.last_attribute_tag
                    {
                        let ret =
                            ValueType::Enumeration(resolver.resolve(last_attribute_tag, value)?);
                        self.last_attribute_tag = None;
                        return Ok(ret);
                    }
                    resolver.resolve(tag, value)
                };
                num.map(ValueType::Enumeration)
            }

            ItemType::Boolean => Ok(ValueType::Boolean(value.eq_ignore_ascii_case("true"))),

            ItemType::TextString => {
                if tag == Tag::AttributeName {
                    let trimmed = value.replace(" ", "");
                    let name = trimmed.as_ref();
                    self.last_attribute_tag =
                        Some(Tag::from_str(name).map_err(|_| TTLVError::XmlError)?)
                }

                Ok(ValueType::TextString(value.to_string()))
            }

            ItemType::ByteString => {
                hex::decode(value)
                    .map(ValueType::ByteString)
                    .map_err(|e| TTLVError::XmlReadError {
                        message: e.to_string(),
                    })
            }

            ItemType::DateTime => {
                if value == "$NOW" {
                    Ok(ValueType::DateTime(0))
                } else {
                    chrono::DateTime::parse_from_rfc3339(value)
                        .map(|dt| ValueType::DateTime(dt.timestamp()))
                        .map_err(|e| TTLVError::XmlReadError {
                            message: e.to_string(),
                        })
                }
            }

            ItemType::Interval => {
                value
                    .parse::<u32>()
                    .map(ValueType::Interval)
                    .map_err(|e| TTLVError::XmlReadError {
                        message: e.to_string(),
                    })
            }

            ItemType::BigInteger => Err(TTLVError::XmlReadError {
                message: "TODO!".into(),
            }),

            ItemType::Structure => Err(TTLVError::XmlReadError {
                message: "TODO!".into(),
            }),
        }
    }
}

impl<'a> Reader for XmlReader<'a> {
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

pub fn read_to_end(buf: &[u8], resolver: &dyn EnumResolver) -> TTLVResult<Vec<Value>> {
    let mut reader = XmlReader::new(buf, resolver);
    let mut values = Vec::new();
    loop {
        match reader.read() {
            None => return Ok(values),
            Some(Ok(v)) => values.push(v),
            Some(Err(e)) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{de::Reader, kmip_enums::Tag};

    struct StubResolver;

    impl EnumResolver for StubResolver {
        fn resolve(&self, _tag: Tag, _value: &str) -> TTLVResult<u32> {
            Ok(0)
        }

        fn to_string(&self, _tag: Tag, _value: u32) -> std::result::Result<String, TTLVError> {
            todo!()
        }
    }

    static XML_BYTES: &[u8] = include_bytes!("../../test_cases/1.4/MSGENC-HTTPS-M-1-14.xml");

    #[test]
    fn test_first_token_is_request_message() {
        let resolver = StubResolver;
        let mut reader = XmlReader::new(XML_BYTES, &resolver);
        let first = reader
            .read()
            .expect("expected a token")
            .expect("expected Ok");
        assert_eq!(first.tag, Tag::RequestMessage);
        assert!(matches!(first.value, ValueType::StructureBegin(_)));
    }

    #[test]
    fn test_structure_begin_end_pairs() {
        let resolver = StubResolver;
        let values = read_to_end(XML_BYTES, &resolver).expect("parse failed");

        let begins: Vec<_> = values
            .iter()
            .filter(|v| matches!(v.value, ValueType::StructureBegin(_)))
            .collect();
        let ends: Vec<_> = values
            .iter()
            .filter(|v| matches!(v.value, ValueType::StructureEnd))
            .collect();

        assert_eq!(
            begins.len(),
            ends.len(),
            "StructureBegin count must equal StructureEnd count"
        );
        assert!(!begins.is_empty(), "expected at least one structure");
    }

    #[test]
    fn test_integer_values_parsed() {
        let resolver = StubResolver;
        let values = read_to_end(XML_BYTES, &resolver).expect("parse failed");

        let integers: Vec<_> = values
            .iter()
            .filter_map(|v| {
                if let ValueType::Integer(i) = v.value {
                    Some((v.tag, i))
                } else {
                    None
                }
            })
            .collect();

        assert!(!integers.is_empty(), "expected integer values");

        let major = integers
            .iter()
            .find(|(tag, _)| *tag == Tag::ProtocolVersionMajor);
        assert!(
            major.is_some(),
            "expected ProtocolVersionMajor integer value"
        );
        assert_eq!(major.unwrap().1, 1, "expected ProtocolVersionMajor == 1");
    }

    #[test]
    fn test_datetime_now_is_sentinel() {
        let resolver = StubResolver;
        let values = read_to_end(XML_BYTES, &resolver).expect("parse failed");

        let timestamps: Vec<_> = values
            .iter()
            .filter_map(|v| {
                if let ValueType::DateTime(ts) = v.value {
                    Some(ts)
                } else {
                    None
                }
            })
            .collect();

        assert!(!timestamps.is_empty(), "expected at least one DateTime");
        assert!(
            timestamps.iter().all(|&ts| ts == 0),
            "all $NOW DateTimes should be sentinel 0"
        );
    }

    #[test]
    fn test_text_string_parsed() {
        let resolver = StubResolver;
        let values = read_to_end(XML_BYTES, &resolver).expect("parse failed");

        let text_strings: Vec<_> = values
            .iter()
            .filter_map(|v| {
                if let ValueType::TextString(ref s) = v.value {
                    Some((v.tag, s.as_str()))
                } else {
                    None
                }
            })
            .collect();

        assert!(!text_strings.is_empty(), "expected text string values");

        let too_large = text_strings
            .iter()
            .find(|(tag, val)| *tag == Tag::ResultMessage && *val == "TOO_LARGE");
        assert!(too_large.is_some(), "expected ResultMessage == TOO_LARGE");
    }
}
