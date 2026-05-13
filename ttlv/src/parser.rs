use chrono::{DateTime, NaiveDateTime, Utc};

use crate::{Reader, TTLVError, kmip_enums::*};

type TTLVResult<T> = std::result::Result<T, TTLVError>;

pub fn expect_structure_begin(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<()> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::StructureBegin(_) => Ok(()),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::Structure,
            actual: token.value,
        }),
    }
}

pub fn expect_structure_end(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<()> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::StructureEnd => Ok(()),
        _ => {
            panic!();
            Err(TTLVError::WrongValueType {
                tag: token.tag,
                expected: ItemType::Interval,
                actual: token.value,
            })
        }
    }
}

pub fn expect_integer(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<i32> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::Integer(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::Integer,
            actual: token.value,
        }),
    }
}

pub fn expect_text_string(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<String> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::TextString(s) => Ok(s),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::TextString,
            actual: token.value,
        }),
    }
}

pub fn expect_long_integer(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<i64> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::LongInteger(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::LongInteger,
            actual: token.value,
        }),
    }
}

pub fn expect_boolean(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<bool> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::Boolean(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::Boolean,
            actual: token.value,
        }),
    }
}

pub fn expect_byte_string(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<Vec<u8>> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::ByteString(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::ByteString,
            actual: token.value,
        }),
    }
}

pub fn expect_enumeration(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<u32> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::Enumeration(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::Enumeration,
            actual: token.value,
        }),
    }
}

pub fn expect_datetime(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<DateTime<Utc>> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        panic!();
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::DateTime(v) => Ok(chrono::DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(v, 0),
            Utc,
        )),
        _ => Err(TTLVError::WrongValueType {
            tag: token.tag,
            expected: ItemType::DateTime,
            actual: token.value,
        }),
    }
}
