use chrono::DateTime;
use chrono::NaiveDateTime;
use chrono::Utc;

use crate::Reader;
use crate::TTLVError;
use crate::kmip_enums::*;

type TTLVResult<T> = std::result::Result<T, TTLVError>;

pub fn expect_structure_begin(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<()> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::StructureBegin(_) => Ok(()),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_structure_end(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<()> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::StructureEnd => Ok(()),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_integer(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<i32> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::Integer(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_text_string(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<String> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::TextString(s) => Ok(s),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_long_integer(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<i64> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::LongInteger(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_boolean(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<bool> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::Boolean(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_byte_string(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<Vec<u8>> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::ByteString(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_enumeration(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<u32> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
        return Err(TTLVError::UnexpectedTag {
            expected: expected_tag,
            actual: token.tag,
        });
    }
    match token.value {
        ValueType::Enumeration(v) => Ok(v),
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}

pub fn expect_datetime(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<DateTime<Utc>> {
    let token = reader.read().ok_or(TTLVError::EndOfTokenStream)??;
    if token.tag != expected_tag {
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
        _ => Err(TTLVError::WrongValueType { tag: token.tag }),
    }
}
