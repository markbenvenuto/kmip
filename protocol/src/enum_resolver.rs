use ttlv::{TTLVError, Tag, de_xml::EnumResolver};

use crate::*;

pub struct KmipEnumResolver;

fn to_static_str<T>(value: u32) -> std::result::Result<String, TTLVError>
where
    T: num::FromPrimitive + Into<&'static str>,
{
    // TODO - stop using unwrap
    let o: T = num::FromPrimitive::from_u32(value).unwrap();
    let ss: &'static str = o.into();
    Ok(ss.to_owned())
}

fn from_str<T>(orig: &str) -> std::result::Result<u32, TTLVError>
where
    T: num::ToPrimitive + FromStr + std::fmt::Debug,
    <T as FromStr>::Err: std::fmt::Debug,
{
    // TODO - stop using unwrap
    let o = &T::from_str(orig).unwrap();
    let v = num::ToPrimitive::to_u32(o).unwrap();
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
            _ => {
                println!("Not implemented resolve_enum_str: {:?}", tag);
                unimplemented! {}
            }
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

            _ => {
                println!("Not implemented to_string: {:?}", tag);
                unimplemented! {}
            }
        }
    }
}
