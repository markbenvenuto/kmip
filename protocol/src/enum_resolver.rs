use strum::AsStaticRef;
use ttlv::TTLVError;
use ttlv::Tag;
use ttlv::de_xml::EnumResolver;

use crate::*;

pub struct KmipEnumResolver;

impl EnumResolver for KmipEnumResolver {
    fn resolve(&self, tag: Tag, orig: &str) -> std::result::Result<u32, TTLVError> {
        let trimmed = orig.replace(" ", "").replace("_", "");
        let value = trimmed.as_ref();

        match tag {
            Tag::CryptographicAlgorithm => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_u32(&CryptographicAlgorithm::from_str(value).unwrap())
                        .unwrap(),
                )
            }
            Tag::CryptographicUsageMask => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_u32(&CryptographicUsageMask::from_str(value).unwrap())
                        .unwrap(),
                )
            }
            Tag::Operation => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&Operation::from_str(value).unwrap()).unwrap())
            }
            Tag::ObjectType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&ObjectType::from_str(value).unwrap()).unwrap())
            }
            Tag::NameType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&NameType::from_str(value).unwrap()).unwrap())
            }
            Tag::SecretDataType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&SecretDataType::from_str(value).unwrap()).unwrap())
            }
            Tag::KeyFormatType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&KeyFormatType::from_str(value).unwrap()).unwrap())
            }
            Tag::BlockCipherMode => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&BlockCipherMode::from_str(value).unwrap()).unwrap())
            }
            Tag::PaddingMethod => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&PaddingMethod::from_str(value).unwrap()).unwrap())
            }
            Tag::HashingAlgorithm => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&HashingAlgorithm::from_str(value).unwrap()).unwrap())
            }
            Tag::DigitalSignatureAlgorithm => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_u32(&DigitalSignatureAlgorithm::from_str(value).unwrap())
                        .unwrap(),
                )
            }

            Tag::RevocationReasonCode => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_u32(&RevocationReasonCode::from_str(value).unwrap())
                        .unwrap(),
                )
            }
            Tag::ValidityIndicator => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&ValidityIndicator::from_str(value).unwrap()).unwrap())
            }
            Tag::State => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_u32(&State::from_str(value).unwrap()).unwrap())
            }
            _ => {
                println!("Not implemented resolve_enum_str: {:?}", tag);
                unimplemented! {}
            }
        }
    }

    fn to_string(&self, tag: Tag, value: u32) -> std::result::Result<String, TTLVError> {
        match tag {
            Tag::CryptographicAlgorithm => {
                let o: CryptographicAlgorithm = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::Operation => {
                let o: Operation = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ObjectType => {
                let o: ObjectType = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ResultStatus => {
                let o: ResultStatus = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ResultReason => {
                let o: ResultReason = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::NameType => {
                let o: NameType = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::KeyFormatType => {
                let o: KeyFormatType = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::BlockCipherMode => {
                let o: BlockCipherMode = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::PaddingMethod => {
                let o: PaddingMethod = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::HashingAlgorithm => {
                let o: HashingAlgorithm = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::DigitalSignatureAlgorithm => {
                let o: DigitalSignatureAlgorithm = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::SecretDataType => {
                let o: SecretDataType = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::RevocationReasonCode => {
                let o: RevocationReasonCode = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ValidityIndicator => {
                let o: ValidityIndicator = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::State => {
                let o: State = num::FromPrimitive::from_u32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }

            _ => {
                println!("Not implemented to_string: {:?}", tag);
                unimplemented! {}
            }
        }
    }
}
