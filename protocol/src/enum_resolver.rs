use ttlv::{TTLVError, Tag, de_xml::EnumResolver};

use crate::*;

pub struct KmipEnumResolver;

fn to_static_str<T>(value: u32) -> std::result::Result<String, TTLVError>
where
    T: num::FromPrimitive + Into<&'static str>,
{
    let o: T = num::FromPrimitive::from_u32(value).ok_or_else(|| TTLVError::XmlReadError {
        message: format!("Unknown enum value: {}", value),
    })?;

    let ss: &'static str = o.into();
    Ok(ss.to_owned())
}

fn from_str<T>(orig: &str) -> std::result::Result<u32, TTLVError>
where
    T: num::ToPrimitive + FromStr,
    <T as FromStr>::Err: std::fmt::Debug,
{
    let o = T::from_str(orig).map_err(|e| TTLVError::XmlReadError {
        message: format!("Failed to parse enum '{}': {:?}", orig, e),
    })?;

    let v = num::ToPrimitive::to_u32(&o).ok_or_else(|| TTLVError::XmlReadError {
        message: format!("Failed to convert enum value to u32: {}", orig),
    })?;
    Ok(v)
}

impl EnumResolver for KmipEnumResolver {
    fn resolve(&self, tag: Tag, orig: &str) -> std::result::Result<u32, TTLVError> {
        let trimmed = orig.replace(" ", "").replace("_", "");
        let value = trimmed.as_ref();

        match tag {
            Tag::CryptographicAlgorithm => from_str::<CryptographicAlgorithm>(value),
            Tag::CryptographicUsageMask => from_str::<CryptographicUsageMask>(value),
            Tag::Operation => from_str::<Operation>(value),
            Tag::ObjectType => from_str::<ObjectType>(value),
            Tag::NameType => from_str::<NameType>(value),
            Tag::SecretDataType => from_str::<SecretDataType>(value),
            Tag::KeyFormatType => from_str::<KeyFormatType>(value),
            Tag::BlockCipherMode => from_str::<BlockCipherMode>(value),
            Tag::PaddingMethod => from_str::<PaddingMethod>(value),
            Tag::HashingAlgorithm => from_str::<HashingAlgorithm>(value),
            Tag::DigitalSignatureAlgorithm => from_str::<DigitalSignatureAlgorithm>(value),
            Tag::RevocationReasonCode => from_str::<RevocationReasonCode>(value),
            Tag::ValidityIndicator => from_str::<ValidityIndicator>(value),
            Tag::State => from_str::<State>(value),
            Tag::UsageLimitsUnit => from_str::<UsageLimitsUnit>(value),
            _ => Err(TTLVError::XmlReadError {
                message: format!("Unresolved enumeration: tag {:?}, value {:?}", tag, orig),
            }),
        }
    }

    fn to_string(&self, tag: Tag, value: u32) -> std::result::Result<String, TTLVError> {
        match tag {
            Tag::CryptographicAlgorithm => {
                return to_static_str::<CryptographicAlgorithm>(value);
            }
            Tag::Operation => {
                return to_static_str::<Operation>(value);
            }
            Tag::ObjectType => {
                return to_static_str::<ObjectType>(value);
            }
            Tag::ResultStatus => {
                return to_static_str::<ResultStatus>(value);
            }
            Tag::ResultReason => {
                return to_static_str::<ResultReason>(value);
            }
            Tag::NameType => {
                return to_static_str::<NameType>(value);
            }
            Tag::KeyFormatType => {
                return to_static_str::<KeyFormatType>(value);
            }
            Tag::BlockCipherMode => {
                return to_static_str::<BlockCipherMode>(value);
            }
            Tag::PaddingMethod => {
                return to_static_str::<PaddingMethod>(value);
            }
            Tag::HashingAlgorithm => {
                return to_static_str::<HashingAlgorithm>(value);
            }
            Tag::DigitalSignatureAlgorithm => {
                return to_static_str::<DigitalSignatureAlgorithm>(value);
            }
            Tag::SecretDataType => {
                return to_static_str::<SecretDataType>(value);
            }
            Tag::RevocationReasonCode => {
                return to_static_str::<RevocationReasonCode>(value);
            }
            Tag::ValidityIndicator => {
                return to_static_str::<ValidityIndicator>(value);
            }
            Tag::State => {
                return to_static_str::<State>(value);
            }
            Tag::UsageLimitsUnit => {
                return to_static_str::<UsageLimitsUnit>(value);
            }

            _ => Err(TTLVError::XmlReadError {
                message: format!("Unresolved tag for to_string: {:?}", tag),
            }),
        }
    }
}
