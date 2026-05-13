use num::FromPrimitive;
use ttlv::{
    Reader,
    TTLVError,
    Tag,
    TtlvDeserialize,
    parser::{expect_boolean, expect_enumeration, expect_integer},
};

use crate::*;

impl TtlvDeserialize for AttributesEnum {
    fn parse(reader: &mut dyn ttlv::Reader) -> Result<Self, TTLVError> {
        use ttlv::parser::*;
        expect_structure_begin(reader, Tag::Attribute)?;
        let attr_name = expect_text_string(reader, Tag::AttributeName)?;
        let result = match attr_name.as_str() {
            "Cryptographic Algorithm" => {
                let v = expect_enumeration(reader, Tag::AttributeValue)?;
                Self::CryptographicAlgorithm(num::FromPrimitive::from_u32(v).ok_or(
                    TTLVError::InvalidEnumValue {
                        tag: Tag::AttributeValue,
                        value: v,
                    },
                )?)
            }
            "Cryptographic Length" => {
                Self::CryptographicLength(expect_integer(reader, Tag::AttributeValue)?)
            }
            "Cryptographic Usage Mask" => {
                Self::CryptographicUsageMask(expect_integer(reader, Tag::AttributeValue)?)
            }
            "Activation Date" => {
                Self::ActivationDate(expect_datetime(reader, Tag::AttributeValue)?)
            }
            "Deactivation Date" => {
                Self::DeactivationDate(expect_datetime(reader, Tag::AttributeValue)?)
            }
            "Name" => {
                expect_structure_begin(reader, Tag::AttributeValue)?;
                let name_value = expect_text_string(reader, Tag::NameValue)?;
                let v = expect_enumeration(reader, Tag::NameType)?;
                let name_type =
                    num::FromPrimitive::from_u32(v).ok_or(TTLVError::InvalidEnumValue {
                        tag: Tag::NameType,
                        value: v,
                    })?;
                expect_structure_end(reader, Tag::AttributeValue)?;
                Self::Name(Name {
                    name_value,
                    name_type,
                })
            }
            "Cryptographic Parameters" => {
                expect_structure_begin(reader, Tag::AttributeValue)?;

                let block_cipher_mode: Option<BlockCipherMode> =
                    parse_optional_enumeration(reader, Tag::BlockCipherMode)?;
                let padding_method: Option<PaddingMethod> =
                    parse_optional_enumeration(reader, Tag::PaddingMethod)?;
                let hashing_algorithm: Option<HashingAlgorithm> =
                    parse_optional_enumeration(reader, Tag::HashingAlgorithm)?;
                let key_role_type: Option<KeyRoleType> =
                    parse_optional_enumeration(reader, Tag::KeyRoleType)?;
                let digital_signature_algorithm: Option<DigitalSignatureAlgorithm> =
                    parse_optional_enumeration(reader, Tag::DigitalSignatureAlgorithm)?;
                let cryptographic_algorithm: Option<CryptographicAlgorithm> =
                    parse_optional_enumeration(reader, Tag::CryptographicAlgorithm)?;
                let random_iv = parse_optional_bool(reader, Tag::RandomIV)?;
                let iv_length = parse_optional_integer(reader, Tag::IVLength)?;
                let tag_length = parse_optional_integer(reader, Tag::TagLength)?;
                let fixed_field_length = parse_optional_integer(reader, Tag::FixedFieldLength)?;
                let invocation_field_length =
                    parse_optional_integer(reader, Tag::InvocationFieldLength)?;
                let counter_length = parse_optional_integer(reader, Tag::CounterLength)?;
                let initial_counter_value =
                    parse_optional_integer(reader, Tag::InitialCounterValue)?;

                expect_structure_end(reader, Tag::AttributeValue)?;
                Self::CryptographicParameters(CryptographicParameters {
                    block_cipher_mode,
                    padding_method,
                    hashing_algorithm,
                    key_role_type,
                    digital_signature_algorithm,
                    cryptographic_algorithm,
                    random_iv,
                    iv_length,
                    tag_length,
                    fixed_field_length,
                    invocation_field_length,
                    counter_length,
                    initial_counter_value,
                })
                // Self::CryptographicParameters(CryptographicParameters::parse(reader)?)
            }
            "State" => {
                let v = expect_enumeration(reader, Tag::AttributeValue)?;
                Self::State(
                    num::FromPrimitive::from_u32(v).ok_or(TTLVError::InvalidEnumValue {
                        tag: Tag::AttributeValue,
                        value: v,
                    })?,
                )
            }
            "Initial Date" => Self::InitialDate(expect_datetime(reader, Tag::AttributeValue)?),
            "Last Change Date" => {
                Self::LastChangeDate(expect_datetime(reader, Tag::AttributeValue)?)
            }
            "Object Type" => {
                let v = expect_enumeration(reader, Tag::AttributeValue)?;
                Self::ObjectType(num::FromPrimitive::from_u32(v).ok_or(
                    TTLVError::InvalidEnumValue {
                        tag: Tag::AttributeValue,
                        value: v,
                    },
                )?)
            }
            "Unique Identifier" => {
                Self::UniqueIdentifier(expect_text_string(reader, Tag::AttributeValue)?)
            }
            n => {
                return Err(TTLVError::InvalidTagName {
                    name: n.to_string(),
                });
            }
        };
        expect_structure_end(reader, Tag::Attribute)?;
        Ok(result)
    }
}

fn parse_optional_enumeration<T>(
    reader: &mut dyn Reader,
    expected_tag: Tag,
) -> Result<Option<T>, TTLVError>
where
    T: FromPrimitive,
{
    let value = if let Some(tag) = reader.peek_tag()
        && tag == expected_tag
    {
        let v = expect_enumeration(reader, expected_tag)?;
        let enum_value: T = num::FromPrimitive::from_u32(v).ok_or(TTLVError::InvalidEnumValue {
            tag: expected_tag,
            value: v,
        })?;

        Some(enum_value)
    } else {
        None
    };

    Ok(value)
}

fn parse_optional_bool(
    reader: &mut dyn Reader,
    expected_tag: Tag,
) -> Result<Option<bool>, TTLVError> {
    let value = if let Some(tag) = reader.peek_tag()
        && tag == expected_tag
    {
        Some(expect_boolean(reader, expected_tag)?)
    } else {
        None
    };

    Ok(value)
}

fn parse_optional_integer(
    reader: &mut dyn Reader,
    expected_tag: Tag,
) -> Result<Option<i32>, TTLVError> {
    let value = if let Some(tag) = reader.peek_tag()
        && tag == expected_tag
    {
        Some(expect_integer(reader, expected_tag)?)
    } else {
        None
    };

    Ok(value)
}

impl ResponseOperationEnum {
    pub fn parse(reader: &mut dyn ttlv::Reader, operation: Operation) -> Result<Self, TTLVError> {
        match operation {
            Operation::Create => Ok(Self::Create(CreateResponse::parse(reader)?)),
            Operation::Get => Ok(Self::Get(GetResponse::parse(reader)?)),
            Operation::GetAttributes => {
                Ok(Self::GetAttributes(GetAttributesResponse::parse(reader)?))
            }
            Operation::GetAttributeList => Ok(Self::GetAttributeList(
                GetAttributeListResponse::parse(reader)?,
            )),
            Operation::Activate => Ok(Self::Activate(ActivateResponse::parse(reader)?)),
            Operation::Destroy => Ok(Self::Destroy(DestroyResponse::parse(reader)?)),
            Operation::Register => Ok(Self::Register(RegisterResponse::parse(reader)?)),
            Operation::Encrypt => Ok(Self::Encrypt(EncryptResponse::parse(reader)?)),
            Operation::Decrypt => Ok(Self::Decrypt(DecryptResponse::parse(reader)?)),
            Operation::MAC => Ok(Self::MAC(MACResponse::parse(reader)?)),
            Operation::MACVerify => Ok(Self::MACVerify(MACVerifyResponse::parse(reader)?)),
            Operation::Revoke => Ok(Self::Revoke(RevokeResponse::parse(reader)?)),
            op => Err(TTLVError::InvalidEnumValue {
                tag: Tag::Operation,
                value: num::ToPrimitive::to_u32(&op).unwrap_or(0),
            }),
        }
    }
}

impl TtlvDeserialize for ResponseBatchItem {
    fn parse(reader: &mut dyn ttlv::Reader) -> Result<Self, TTLVError> {
        use ttlv::parser::*;
        expect_structure_begin(reader, Tag::BatchItem)?;

        let operation = if reader.peek_tag() == Some(Tag::Operation) {
            Some(Operation::parse(reader)?)
        } else {
            None
        };

        let result_status = ResultStatus::parse(reader)?;

        let result_reason = if reader.peek_tag() == Some(Tag::ResultReason) {
            Some(ResultReason::parse(reader)?)
        } else {
            None
        };

        let result_message = if reader.peek_tag() == Some(Tag::ResultMessage) {
            Some(expect_text_string(reader, Tag::ResultMessage)?)
        } else {
            None
        };

        let (operation, response_payload) = match operation {
            Some(op)
                if result_status == ResultStatus::Success
                    && reader.peek_tag() == Some(Tag::ResponsePayload) =>
            {
                let payload = ResponseOperationEnum::parse(reader, op)?;
                let recovered_op = get_operation_for_response(&payload);
                (Some(recovered_op), Some(payload))
            }
            op => (op, None),
        };

        expect_structure_end(reader, Tag::BatchItem)?;
        Ok(Self {
            operation,
            result_status,
            result_reason,
            result_message,
            response_payload,
        })
    }
}
