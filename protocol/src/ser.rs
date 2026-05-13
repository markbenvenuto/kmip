use ttlv::{TTLVError, Tag, TtlvSerialize};

use crate::*;

impl TtlvSerialize for AttributesEnum {
    fn serialize(&self, writer: &mut dyn ttlv::ser::EncodedWriter) -> Result<(), TTLVError> {
        use ttlv::ser::*;
        ser_write_structure_begin(writer, Tag::Attribute)?;
        match self {
            Self::CryptographicAlgorithm(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Cryptographic Algorithm")?;
                ser_write_enumeration_attribute_typed(writer, Tag::CryptographicAlgorithm, v)?;
            }
            Self::CryptographicLength(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Cryptographic Length")?;
                ser_write_integer(writer, Tag::AttributeValue, *v)?;
            }
            Self::CryptographicUsageMask(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Cryptographic Usage Mask")?;
                ser_write_integer(writer, Tag::AttributeValue, *v)?;
            }
            Self::ActivationDate(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Activation Date")?;
                ser_write_datetime(writer, Tag::AttributeValue, v)?;
            }
            Self::DeactivationDate(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Deactivation Date")?;
                ser_write_datetime(writer, Tag::AttributeValue, v)?;
            }
            Self::Name(n) => {
                ser_write_text_string(writer, Tag::AttributeName, "Name")?;
                ser_write_structure_begin(writer, Tag::AttributeValue)?;
                ser_write_text_string(writer, Tag::NameValue, &n.name_value)?;
                ser_write_enumeration_typed(writer, Tag::NameType, &n.name_type)?;
                ser_write_structure_end(writer)?;
            }
            Self::CryptographicParameters(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Cryptographic Parameters")?;
                ser_write_structure_begin(writer, Tag::AttributeValue)?;

                if let Some(value) = v.block_cipher_mode {
                    ser_write_enumeration_typed(writer, Tag::BlockCipherMode, &value)?;
                }

                if let Some(value) = v.block_cipher_mode {
                    ser_write_enumeration_typed(writer, Tag::BlockCipherMode, &value)?;
                }

                if let Some(value) = v.padding_method {
                    ser_write_enumeration_typed(writer, Tag::PaddingMethod, &value)?;
                }

                if let Some(value) = v.hashing_algorithm {
                    ser_write_enumeration_typed(writer, Tag::HashingAlgorithm, &value)?;
                }

                if let Some(value) = v.key_role_type {
                    ser_write_enumeration_typed(writer, Tag::KeyRoleType, &value)?;
                }

                if let Some(value) = v.digital_signature_algorithm {
                    ser_write_enumeration_typed(writer, Tag::DigitalSignatureAlgorithm, &value)?;
                }

                if let Some(value) = v.cryptographic_algorithm {
                    ser_write_enumeration_typed(writer, Tag::CryptographicAlgorithm, &value)?;
                }

                if let Some(value) = v.random_iv {
                    ser_write_boolean(writer, Tag::RandomIV, value)?;
                }

                if let Some(value) = v.iv_length {
                    ser_write_integer(writer, Tag::IVLength, value)?;
                }
                if let Some(value) = v.tag_length {
                    ser_write_integer(writer, Tag::TagLength, value)?;
                }
                if let Some(value) = v.fixed_field_length {
                    ser_write_integer(writer, Tag::FixedFieldLength, value)?;
                }
                if let Some(value) = v.invocation_field_length {
                    ser_write_integer(writer, Tag::InvocationFieldLength, value)?;
                }
                if let Some(value) = v.counter_length {
                    ser_write_integer(writer, Tag::CounterLength, value)?;
                }
                if let Some(value) = v.initial_counter_value {
                    ser_write_integer(writer, Tag::InitialCounterValue, value)?;
                }

                ser_write_structure_end(writer)?;
            }
            Self::State(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "State")?;
                ser_write_enumeration_attribute_typed(writer, Tag::State, v)?;
            }
            Self::InitialDate(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Initial Date")?;
                ser_write_datetime(writer, Tag::AttributeValue, v)?;
            }
            Self::LastChangeDate(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Last Change Date")?;
                ser_write_datetime(writer, Tag::AttributeValue, v)?;
            }
            Self::ObjectType(v) => {
                ser_write_text_string(writer, Tag::AttributeName, "Object Type")?;
                ser_write_enumeration_attribute_typed(writer, Tag::ObjectType, v)?;
            }
            Self::UniqueIdentifier(s) => {
                ser_write_text_string(writer, Tag::AttributeName, "Unique Identifier")?;
                ser_write_text_string(writer, Tag::AttributeValue, s)?;
            }
        }
        ser_write_structure_end(writer)?;
        Ok(())
    }
}

impl TtlvSerialize for ResponseOperationEnum {
    fn serialize(&self, writer: &mut dyn ttlv::ser::EncodedWriter) -> Result<(), TTLVError> {
        match self {
            Self::Create(v) => TtlvSerialize::serialize(v, writer),
            Self::Get(v) => TtlvSerialize::serialize(v, writer),
            Self::GetAttributes(v) => TtlvSerialize::serialize(v, writer),
            Self::GetAttributeList(v) => TtlvSerialize::serialize(v, writer),
            Self::Activate(v) => TtlvSerialize::serialize(v, writer),
            Self::Destroy(v) => TtlvSerialize::serialize(v, writer),
            Self::Register(v) => TtlvSerialize::serialize(v, writer),
            Self::Encrypt(v) => TtlvSerialize::serialize(v, writer),
            Self::Decrypt(v) => TtlvSerialize::serialize(v, writer),
            Self::MAC(v) => TtlvSerialize::serialize(v, writer),
            Self::MACVerify(v) => TtlvSerialize::serialize(v, writer),
            Self::Revoke(v) => TtlvSerialize::serialize(v, writer),
        }
    }
}

impl TtlvSerialize for ResponseBatchItem {
    fn serialize(&self, writer: &mut dyn ttlv::ser::EncodedWriter) -> Result<(), TTLVError> {
        use ttlv::ser::*;
        ser_write_structure_begin(writer, Tag::BatchItem)?;

        if let Some(rp) = self.response_payload.as_ref() {
            let operation = get_operation_for_response(rp);
            TtlvSerialize::serialize(&operation, writer)?;
        } else if let Some(op) = self.operation.as_ref() {
            TtlvSerialize::serialize(op, writer)?;
        }

        TtlvSerialize::serialize(&self.result_status, writer)?;

        if self.result_status == ResultStatus::OperationFailed {
            if let Some(ref reason) = self.result_reason {
                TtlvSerialize::serialize(reason, writer)?;
            }
        }

        if let Some(ref msg) = self.result_message {
            ser_write_text_string(writer, Tag::ResultMessage, msg)?;
        }

        if self.result_status == ResultStatus::Success {
            if let Some(ref payload) = self.response_payload {
                TtlvSerialize::serialize(payload, writer)?;
            }
        }

        ser_write_structure_end(writer)?;
        Ok(())
    }
}
