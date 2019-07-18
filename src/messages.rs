use log::{info, warn};

use serde_enum::{Deserialize_enum, Serialize_enum};

use chrono::*;

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::string::ToString;

use strum::AsStaticRef;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use ttlv::*;


#[derive(FromPrimitive, Serialize_enum, Deserialize_enum, Debug, AsStaticStr)]
#[repr(i32)]
pub enum Operation {
    Create = 0x00000001,
    CreateKeyPair = 0x00000002,
    Register = 0x00000003,
    ReKey = 0x00000004,
    DeriveKey = 0x00000005,
    Certify = 0x00000006,
    ReCertify = 0x00000007,
    Locate = 0x00000008,
    Check = 0x00000009,
    Get = 0x0000000A,
    GetAttributes = 0x0000000B,
    GetAttributeList = 0x0000000C,
    AddAttribute = 0x0000000D,
    ModifyAttribute = 0x0000000E,
    DeleteAttribute = 0x0000000F,
    ObtainLease = 0x00000010,
    GetUsageAllocation = 0x00000011,
    Activate = 0x00000012,
    Revoke = 0x00000013,
    Destroy = 0x00000014,
    Archive = 0x00000015,
    Recover = 0x00000016,
    Validate = 0x00000017,
    Query = 0x00000018,
    Cancel = 0x00000019,
    Poll = 0x0000001A,
    Notify = 0x0000001B,
    Put = 0x0000001C,
    ReKeyKeyPair = 0x0000001D,
    DiscoverVersions = 0x0000001E,
    Encrypt = 0x0000001F,
    Decrypt = 0x00000020,
    Sign = 0x00000021,
    SignatureVerify = 0x00000022,
    MAC = 0x00000023,
    MACVerify = 0x00000024,
    RNGRetrieve = 0x00000025,
    RNGSeed = 0x00000026,
    Hash = 0x00000027,
    CreateSplitKey = 0x00000028,
    JoinSplitKey = 0x00000029,
    Import = 0x0000002A,
    Export = 0x0000002B,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
pub enum ObjectTypeEnum {
    Certificate = 0x00000001,
    SymmetricKey = 0x00000002,
    PublicKey = 0x00000003,
    PrivateKey = 0x00000004,
    SplitKey = 0x00000005,
    Template = 0x00000006, //(deprecated)
    SecretData = 0x00000007,
    OpaqueObject = 0x00000008,
    PGPKey = 0x00000009,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
pub enum NameTypeEnum {
    UninterpretedTextString = 0x00000001,
    URI = 0x00000002,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
pub enum CryptographicAlgorithm {
    DES = 0x00000001,
    TripleDES = 0x00000002,
    AES = 0x00000003,
    RSA = 0x00000004,
    DSA = 0x00000005,
    ECDSA = 0x00000006,
    HMACSHA1 = 0x00000007,
    HMACSHA224 = 0x00000008,
    HMACSHA256 = 0x00000009,
    HMACSHA384 = 0x0000000A,
    HMACSHA512 = 0x0000000B,
    HMACMD5 = 0x0000000C,
    DH = 0x0000000D,
    ECDH = 0x0000000E,
    ECMQV = 0x0000000F,
    Blowfish = 0x00000010,
    Camellia = 0x00000011,
    CAST5 = 0x00000012,
    IDEA = 0x00000013,
    MARS = 0x00000014,
    RC2 = 0x00000015,
    RC4 = 0x00000016,
    RC5 = 0x00000017,
    SKIPJACK = 0x00000018,
    Twofish = 0x00000019,
    EC = 0x0000001A,
    OneTimePad = 0x0000001B,
    ChaCha20 = 0x0000001C,
    Poly1305 = 0x0000001D,
    ChaCha20Poly1305 = 0x0000001E,
    SHA3224 = 0x0000001F,
    SHA3256 = 0x00000020,
    SHA3384 = 0x00000021,
    SHA3512 = 0x00000022,
    HMACSHA3224 = 0x00000023,
    HMACSHA3256 = 0x00000024,
    HMACSHA3384 = 0x00000025,
    HMACSHA3512 = 0x00000026,
    SHAKE128 = 0x00000027,
    SHAKE256 = 0x00000028,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CryptographicUsageMask {
    Sign = 0x00000001,
    Verify = 0x00000002,
    Encrypt = 0x00000004,
    Decrypt = 0x00000008,
    WrapKey = 0x00000010,
    UnwrapKey = 0x00000020,
    Export = 0x00000040,
    MACGenerate = 0x00000080,
    MACVerify = 0x00000100,
    DeriveKey = 0x00000200,
    ContentCommitment = 0x00000400, // (NonRepudiation)
    KeyAgreement = 0x00000800,
    CertificateSign = 0x00001000,
    CRLSign = 0x00002000,
    GenerateCryptogram = 0x00004000,
    ValidateCryptogram = 0x00008000,
    TranslateEncrypt = 0x00010000,
    TranslateDecrypt = 0x00020000,
    TranslateWrap = 0x00040000,
    TranslateUnwrap = 0x00080000,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
pub enum KeyFormatTypeEnum {
    Raw = 0x00000001,
    Opaque = 0x00000002,
    PKCS1 = 0x00000003,
    PKCS8 = 0x00000004,
    X509 = 0x00000005,
    ECPrivateKey = 0x00000006,
    TransparentSymmetricKey = 0x00000007,
    TransparentDSAPrivateKey = 0x00000008,
    TransparentDSAPublicKey = 0x00000009,
    TransparentRSAPrivateKey = 0x0000000A,
    TransparentRSAPublicKey = 0x0000000B,
    TransparentDHPrivateKey = 0x0000000C,
    TransparentDHPublicKey = 0x0000000D,
    TransparentECDSAPrivateKey = 0x0000000E, //(deprecated),
    TransparentECDSAPublicKey = 0x0000000F,  //(deprecated),
    TransparentECDHPrivateKey = 0x00000010,  //(deprecated),
    TransparentECDHPublicKey = 0x00000011,   //(deprecated),
    TransparentECMQVPrivateKey = 0x00000012, //(deprecated),
    TransparentECMQVPublicKey = 0x00000013,  //(deprecated),
    TransparentECPrivateKey = 0x00000014,
    TransparentECPublicKey = 0x00000015,
    PKCS12 = 0x00000016,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x00000001,
    ECPublicKeyTypeX962CompressedPrime = 0x00000002,
    ECPublicKeyTypeX962CompressedChar2 = 0x00000003,
    ECPublicKeyTypeX962Hybrid = 0x00000004,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
pub enum ResultStatus {
    Success = 0x00000000,
    OperationFailed = 0x00000001,
    OperationPending = 0x00000002,
    OperationUndone = 0x00000003,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr)]
#[repr(i32)]
pub enum ResultReason {
    ItemNotFound = 0x00000001,
    ResponseTooLarge = 0x00000002,
    AuthenticationNotSuccessful = 0x00000003,
    InvalidMessage = 0x00000004,
    OperationNotSupported = 0x00000005,
    MissingData = 0x00000006,
    InvalidField = 0x00000007,
    FeatureNotSupported = 0x00000008,
    OperationCanceledByRequester = 0x00000009,
    CryptographicFailure = 0x0000000A,
    IllegalOperation = 0x0000000B,
    PermissionDenied = 0x0000000C,
    Objectarchived = 0x0000000D,
    IndexOutofBounds = 0x0000000E,
    ApplicationNamespaceNotSupported = 0x0000000F,
    KeyFormatTypeNotSupported = 0x00000010,
    KeyCompressionTypeNotSupported = 0x00000011,
    EncodingOptionError = 0x00000012,
    KeyValueNotPresent = 0x00000013,
    AttestationRequired = 0x00000014,
    AttestationFailed = 0x00000015,
    Sensitive = 0x00000016,
    NotExtractable = 0x00000017,
    ObjectAlreadyExists = 0x00000018,
    GeneralFailure = 0x00000100,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyValue {
    #[serde(with = "serde_bytes")]
    pub KeyMaterial: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyBlock {
    pub KeyFormatType: KeyFormatTypeEnum,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub KeyCompressionType: Option<KeyCompressionType>,

    // TODO : this type is not just a struct all the time
    pub KeyValue: KeyValue,

    // TODO - omitted in some cases
    pub CryptographicAlgorithm: CryptographicAlgorithm,
    pub CryptographicLength: i32,
    // TODO
    // KeyWrappingData  : KeyWrappingData
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SymmetricKey {
    pub KeyBlock: KeyBlock,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttributeStruct {
    pub AttributeName: String,
    pub AttributeIndex: Option<i32>,
    // AttributeValue type varies based on type
    //AttributeValue: ???
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NameStruct {
    pub NameValue: String,
    pub NameType: NameTypeEnum,
}

// #[derive(Serialize, Deserialize, Debug)]
// struct TemplateAttribute {
//     Name : NameStruct,
//     Attribute : AttributeStruct,
// }

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "AttributeName", content = "AttributeValue")]
pub enum CreateRequestAttributes {
    #[serde(rename = "Cryptographic Algorithm")]
    // TODO - use CryptographicAlgorithm as the type but serde calls deserialize_identifier
    // and we do not have enough context to realize it is CryptographicAlgorithm, we think it is AttributeValue
    CryptographicAlgorithm(i32),

    #[serde(rename = "Cryptographic Length")]
    CryptographicLength(i32),

    #[serde(rename = "Cryptographic Usage Mask")]
    CryptographicUsageMask(i32),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TemplateAttribute {
    pub Name: Option<NameStruct>,

    #[serde(rename = "Attribute")]
    pub Attribute: Vec<CreateRequestAttributes>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub ObjectType: ObjectTypeEnum,
    pub TemplateAttribute: Vec<TemplateAttribute>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct CreateResponse {
    pub ObjectType: ObjectTypeEnum,
    pub UniqueIdentifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GetRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub UniqueIdentifier: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub KeyFormatType: Option<KeyFormatTypeEnum>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub KeyWrapType: Option<KeyFormatTypeEnum>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub KeyCompressionType: Option<KeyCompressionType>,
    // TODO KeyWrappingSpecification: KeyWrappingSpecification
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct GetResponse {
    pub ObjectType: ObjectTypeEnum,
    pub UniqueIdentifier: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub SymmetricKey: Option<SymmetricKey>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "Operation", content = "RequestPayload")]
pub enum RequestBatchItem {
    Create(CreateRequest),
    Get(GetRequest),
    // TODO - add support for: Unique Batch Item ID, will require custom deserializer, serializer
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProtocolVersion {
    pub ProtocolVersionMajor: i32,
    pub ProtocolVersionMinor: i32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RequestHeader {
    pub ProtocolVersion: ProtocolVersion,
    // TODO: Other fields are optional
    pub BatchCount: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestMessage {
    pub RequestHeader: RequestHeader,
    pub BatchItem: RequestBatchItem,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ResponseHeader {
    pub ProtocolVersion: ProtocolVersion,
    #[serde(with = "ttlv::my_date_format")]
    pub TimeStamp: chrono::DateTime<Utc>,
    // TODO: Other fields are optional
    pub BatchCount: i32,
}

#[derive(Serialize, Deserialize, Debug)]
//#[serde(tag = "Operation", content = "RequestPayload")]
pub enum ResponseOperationEnum {
    Create(CreateResponse),
    Get(GetResponse),
    Empty,
    // TODO - add support for: Unique Batch Item ID
}

// TODO - remove Deserialize
#[derive(Deserialize, Debug)]
#[serde(rename = "BatchItem")]
pub struct ResponseBatchItem {
    //Operation: Option<String>,
    pub ResultStatus: ResultStatus,
    pub ResultReason: ResultReason,
    pub ResultMessage: Option<String>,
    pub ResponsePayload: Option<ResponseOperationEnum>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseMessage {
    pub ResponseHeader: ResponseHeader,
    #[serde(rename = "BatchItem")]
    pub BatchItem: ResponseBatchItem,
}

impl Serialize for ResponseBatchItem {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut field_count = 1;
        let mut serialize_reason = false;
        let mut serialize_operation = false;
        let mut serialize_message = false;

        if self.ResultStatus == ResultStatus::OperationFailed {
            field_count += 1;
            serialize_reason = true;

            if self.ResultMessage.is_some() {
                field_count += 1;
                serialize_message = true;
            }
        }

        //         if self.Operation.is_some() {
        //             field_count += 2;
        //             serialize_operation = true;
        // //            assert_eq!(self.Operation.is_some(), self.ResponsePayload.is_some() );
        //         }

        if self.ResponsePayload.is_some() {
            field_count += 2;
            serialize_operation = true;
        }

        let mut ser_struct = serializer.serialize_struct("BatchItem", field_count)?;

        // if serialize_operation {
        //     let op = self.Operation.as_ref();
        //     ser_struct.serialize_field("Operation", &op)?;
        // }

        if serialize_operation {
            // TODO - use a macro to derive this stuff
            match self.ResponsePayload.as_ref().unwrap() {
                ResponseOperationEnum::Create(_) => {
                    ser_struct.serialize_field("Operation", &Operation::Create)?;
                }
                ResponseOperationEnum::Get(_) => {
                    ser_struct.serialize_field("Operation", &Operation::Get)?;
                }
                ResponseOperationEnum::Empty => unimplemented!(),
            }
        }

        ser_struct.serialize_field("ResultStatus", &self.ResultStatus)?;

        if serialize_reason {
            ser_struct.serialize_field("ResultReason", &self.ResultReason)?;
        }

        if serialize_message {
            ser_struct.serialize_field("ResultMessage", &self.ResultMessage)?;
        }

        if serialize_operation {
            // TODO - use a macro to derive this stuff
            //ser_struct.serialize_field("ResultPayload", &self.ResponsePayload.as_ref())?;
            match self.ResponsePayload.as_ref().unwrap() {
                ResponseOperationEnum::Create(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Get(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Empty => unimplemented!(),
            }
        }

        ser_struct.end()
    }
}


pub struct KmipEnumResolver;

impl ttlv::EnumResolver for KmipEnumResolver {
    fn resolve_enum(&self, name: &str, value: i32) -> String {
        match name {
            "Foo" => "Bar".to_owned(),
            "Operation" => {
                let o: Operation = num::FromPrimitive::from_i32(value).unwrap();
                return o.as_static().to_owned();
            }
            "ObjectType" => {
                let o: ObjectTypeEnum = num::FromPrimitive::from_i32(value).unwrap();
                return o.as_static().to_owned();
            }
            "CryptographicAlgorithm" => {
                let o: CryptographicAlgorithm = num::FromPrimitive::from_i32(value).unwrap();
                return o.as_static().to_owned();
            }
            _ => {
                println!("Not implemented: {:?}", name);
                unimplemented! {}
            }
        }
    }
}
