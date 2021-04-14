
#![allow(
    clippy::upper_case_acronyms
)]

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate serde_derive;

//#[macro_use]
extern crate serde_enum;

extern crate strum;
#[macro_use]
extern crate strum_macros;

use serde_bytes::ByteBuf;
use serde_enum::{Deserialize_enum, Serialize_enum};

use chrono::Utc;
use chrono::{DateTime, NaiveDateTime};
use std::fmt;
use std::io::{Cursor, Read};
use std::str::FromStr;

mod de;
mod de_xml;
mod error;
mod kmip_enums;
mod my_date_format;
mod my_opt_date_format;
mod ser;
mod ser_xml;

#[macro_use]
extern crate log;

extern crate chrono;

use strum::AsStaticRef;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};

pub use de::from_bytes;
pub use de_xml::from_xml_bytes;
pub use error::{Error, Result};
pub use ser::to_bytes;
pub use ser_xml::to_xml_bytes;

pub use de::to_print;
pub use error::TTLVError;

pub use de::EnumResolver;

pub use de::read_len;
pub use de::read_tag;
pub use de::read_type;

pub use kmip_enums::ItemType;
pub use kmip_enums::Tag;


#[derive(
    FromPrimitive, ToPrimitive, Serialize_enum, Deserialize_enum, Debug, EnumString, AsStaticStr,
)]
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

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    PartialEq
)]
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

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    PartialEq,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum ObjectStateEnum {
    PreActive = 0x00000001,
    Active = 0x00000002,
    Deactivated = 0x00000003,
    Compromised = 0x00000004,
    Destroyed = 0x00000005,
    DestroyedCompromised = 0x00000006,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Copy,
    Clone,
)]
#[repr(i32)]
pub enum NameTypeEnum {
    UninterpretedTextString = 0x00000001,
    URI = 0x00000002,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    PartialEq,
)]
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

    // Extension
    UNKNOWN = 0x8000000,
}

#[derive(
    Debug, Deserialize, Serialize, EnumString, FromPrimitive, ToPrimitive, AsStaticStr, Clone, Copy,
)]
#[repr(i32)]
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

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
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

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x00000001,
    ECPublicKeyTypeX962CompressedPrime = 0x00000002,
    ECPublicKeyTypeX962CompressedChar2 = 0x00000003,
    ECPublicKeyTypeX962Hybrid = 0x00000004,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum SecretDataType {
    Password = 0x00000001,
    Seed = 0x00000002,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum EncodingOption {
    NoEncoding = 0x00000001,
    TTLVEncoding = 0x00000002,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum WrappingMethod {
    Encrypt = 0x00000001,
    MACsign = 0x00000002,
    EncryptThenMACsign = 0x00000003,
    MACsignThenEncrypt = 0x00000004,
    TR31 = 0x00000005,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum BlockCipherMode {
    CBC = 0x00000001,
    ECB = 0x00000002,
    PCBC = 0x00000003,
    CFB = 0x00000004,
    OFB = 0x00000005,
    CTR = 0x00000006,
    CMAC = 0x00000007,
    CCM = 0x00000008,
    GCM = 0x00000009,
    CBCMAC = 0x0000000A,
    XTS = 0x0000000B,
    AESKeyWrapPadding = 0x0000000C,
    NISTKeyWrap = 0x0000000D,
    X9102AESKW = 0x0000000E,
    X9102TDKW = 0x0000000F,
    X9102AKW1 = 0x00000010,
    X9102AKW2 = 0x00000011,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum PaddingMethod {
    None = 0x00000001,
    OAEP = 0x00000002,
    PKCS5 = 0x00000003,
    SSL3 = 0x00000004,
    Zeros = 0x00000005,
    ANSIX923 = 0x00000006,
    ISO10126 = 0x00000007,
    PKCS1v15 = 0x00000008,
    X931 = 0x00000009,
    PSS = 0x0000000A,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum HashingAlgorithm {
    MD2 = 0x00000001,
    MD4 = 0x00000002,
    MD5 = 0x00000003,
    SHA1 = 0x00000004,
    SHA224 = 0x00000005,
    SHA256 = 0x00000006,
    SHA384 = 0x00000007,
    SHA512 = 0x00000008,
    RIPEMD160 = 0x00000009,
    Tiger = 0x0000000A,
    Whirlpool = 0x0000000B,
    SHA512224 = 0x0000000C,
    SHA512256 = 0x0000000D,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum KeyRoleType {
    BDK = 0x00000001,
    CVK = 0x00000002,
    DEK = 0x00000003,
    MKAC = 0x00000004,
    MKSMC = 0x00000005,
    MKSMI = 0x00000006,
    MKDAC = 0x00000007,
    MKDN = 0x00000008,
    MKCP = 0x00000009,
    MKOTH = 0x0000000A,
    KEK = 0x0000000B,
    MAC16609 = 0x0000000C,
    MAC97971 = 0x0000000D,
    MAC97972 = 0x0000000E,
    MAC97973 = 0x0000000F,
    MAC97974 = 0x00000010,
    MAC97975 = 0x00000011,
    ZPK = 0x00000012,
    PVKIBM = 0x00000013,
    PVKPVV = 0x00000014,
    PVKOTH = 0x00000015,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum DigitalSignatureAlgorithm {
    MD2withRSAEncryptionPKCS1v15 = 0x00000001,
    MD5withRSAEncryptionPKCS1v15 = 0x00000002,
    SHA1withRSAEncryptionPKCS1v15 = 0x00000003,
    SHA224withRSAEncryptionPKCS1v15 = 0x00000004,
    SHA256withRSAEncryptionPKCS1v15 = 0x00000005,
    SHA384withRSAEncryptionPKCS1v15 = 0x00000006,
    SHA512withRSAEncryptionPKCS1v15 = 0x00000007,
    RSASSAPSSPKCS1v21 = 0x00000008,
    DSAwithSHA1 = 0x00000009,
    DSAwithSHA224 = 0x0000000A,
    DSAwithSHA256 = 0x0000000B,
    ECDSAwithSHA1 = 0x0000000C,
    ECDSAwithSHA224 = 0x0000000D,
    ECDSAwithSHA256 = 0x0000000E,
    ECDSAwithSHA384 = 0x0000000F,
    ECDSAwithSHA512 = 0x00000010,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
)]
#[repr(i32)]
pub enum ValidityIndicator {
    Valid = 0x00000001,
    Invalid = 0x00000002,
    Unknown = 0x00000003,
}

#[derive(
    Debug,
    Serialize_enum,
    Deserialize_enum,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    PartialEq,
)]
#[repr(i32)]
pub enum RevocationReasonCode {
    Unspecified = 0x00000001,
    KeyCompromise = 0x00000002,
    CACompromise = 0x00000003,
    AffiliationChanged = 0x00000004,
    Superseded = 0x00000005,
    CessationofOperation = 0x00000006,
    PrivilegeWithdrawn = 0x00000007,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, PartialEq)]
#[repr(i32)]
pub enum ResultStatus {
    Success = 0x00000000,
    OperationFailed = 0x00000001,
    OperationPending = 0x00000002,
    OperationUndone = 0x00000003,
}

#[derive(Debug, Serialize_enum, Deserialize_enum, FromPrimitive, AsStaticStr, Copy, Clone, Display)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyValue {
    #[serde(with = "serde_bytes", rename = "KeyMaterial")]
    pub key_material: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionKeyInformation {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
    //#[serde(skip_serializing_if = "Option::is_none", rename = "CryptographicParameters")]
    //pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MACSignatureKeyInformation {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
    // #[serde(skip_serializing_if = "Option::is_none", rename = "CryptographicParameters")]
    //pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyWrappingData {
    #[serde(rename = "Wrapping Method")]
    pub wrapping_method: WrappingMethod,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "EncryptionKeyInformation"
    )]
    pub encryption_key_information: Option<EncryptionKeyInformation>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "MACSignatureKeyInformation"
    )]
    pub mac_signature_key_information: Option<MACSignatureKeyInformation>,

    #[serde(
        with = "serde_bytes",
        skip_serializing_if = "Option::is_none",
        rename = "MACSignature"
    )]
    pub mac_signature: Option<Vec<u8>>,

    #[serde(
        with = "serde_bytes",
        skip_serializing_if = "Option::is_none",
        rename = "IVCounterNonce"
    )]
    pub iv_counter_nonce: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "EncodingOption")]
    pub encoding_option: Option<EncodingOption>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyBlock {
    #[serde(rename = "KeyFormatType")]
    pub key_format_type: KeyFormatTypeEnum,

    #[serde(skip_serializing_if = "Option::is_none", rename = "KeyCompressionType")]
    pub key_compression_type: Option<KeyCompressionType>,

    // TODO : this type is not just a struct all the time
    #[serde(rename = "KeyValue")]
    pub key_value: KeyValue,

    // omitted in for SecretData and other cases
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicAlgorithm"
    )]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicLength"
    )]
    pub cryptographic_length: Option<i32>,

    // TODO
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicLength"
    )]
    pub key_wrapping_data: Option<KeyWrappingData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(rename (serialize = "AttributeValue", deserialize = "CryptographicParameters"))]
#[serde(rename = "CryptographicParameters")]
pub struct CryptographicParameters {
    #[serde(skip_serializing_if = "Option::is_none", rename = "BlockCipherMode")]
    pub block_cipher_mode: Option<BlockCipherMode>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "PaddingMethod")]
    pub padding_method: Option<PaddingMethod>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "HashingAlgorithm")]
    pub hashing_algorithm: Option<HashingAlgorithm>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "KeyRoleType")]
    pub key_role_type: Option<KeyRoleType>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "DigitalSignatureAlgorithm"
    )]
    pub digital_signature_algorigthm: Option<DigitalSignatureAlgorithm>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicAlgorithm"
    )]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "RandomIV")]
    pub random_iv: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "IVLength")]
    pub iv_length: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "TagLength")]
    pub tag_length: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "FixedFieldLength")]
    pub fixed_field_length: Option<i32>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "InvocationFieldLength"
    )]
    pub invocation_field_length: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "CounterLength")]
    pub counter_length: Option<i32>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "InitialCounterValue"
    )]
    pub initial_counter_value: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SymmetricKey {
    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretData {
    #[serde(rename = "SecretDataType")]
    pub secret_data_type: SecretDataType,

    #[serde(rename = "KeyBlock")]
    pub key_block: KeyBlock,
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct AttributeStruct {
//     #[serde(rename = "AttributeName")]
//     pub attribute_name: String,
//     #[serde(rename = "AttributeIndex")]
//     pub attribute_index: Option<i32>,
//     // AttributeValue type varies based on type
//     //AttributeValue: ???
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename = "Name")]
pub struct NameStruct {
    #[serde(rename = "NameValue")]
    pub name_value: String,

    #[serde(rename = "NameType")]
    pub name_type: NameTypeEnum,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevocationReason {
    #[serde(rename = "RevocationReasonCode")]
    pub revocation_reason_code: RevocationReasonCode,

    #[serde(skip_serializing_if = "Option::is_none", rename = "RevocationMessage")]
    pub revocation_message: Option<String>,
}

// #[derive(Serialize, Deserialize, Debug)]
// struct TemplateAttribute {
//     Name : NameStruct,
//     Attribute : AttributeStruct,
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    rename = "Attribute",
    tag = "AttributeName",
    content = "AttributeValue"
)]
pub enum AttributesEnum {
    #[serde(rename = "Cryptographic Algorithm")]
    // TODO - use CryptographicAlgorithm as the type but serde calls deserialize_identifier
    // and we do not have enough context to realize it is CryptographicAlgorithm, we think it is AttributeValue
    CryptographicAlgorithm(CryptographicAlgorithm),

    #[serde(rename = "Cryptographic Length")]
    CryptographicLength(i32),

    #[serde(rename = "Cryptographic Usage Mask")]
    CryptographicUsageMask(i32),

    #[serde(with = "my_date_format", rename = "Activation Date")]
    ActivationDate(DateTime<Utc>),

    #[serde(with = "my_date_format", rename = "Deactivation Date")]
    DeactivationDate(DateTime<Utc>),

    #[serde(rename = "Name")]
    Name(NameStruct),

    #[serde(rename = "Cryptographic Parameters")]
    CryptographicParameters(CryptographicParameters),

    #[serde(rename = "State")]
    State(ObjectStateEnum),

    #[serde(with = "my_date_format", rename = "Initial Date")]
    InitialDate(DateTime<Utc>),

    #[serde(with = "my_date_format", rename = "Last Change Date")]
    LastChangeDate(DateTime<Utc>),

    #[serde(rename = "Object Type")]
    ObjectType(ObjectTypeEnum),

    #[serde(rename = "Unique Identifier")]
    UniqueIdentifier(String),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TemplateAttribute {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<NameStruct>,

    #[serde(rename = "Attribute")]
    pub attribute: Vec<AttributesEnum>,
}

///////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct CreateRequest {
    #[serde(rename = "ObjectType")]
    pub object_type: ObjectTypeEnum,

    #[serde(rename = "TemplateAttribute")]
    pub template_attribute: Vec<TemplateAttribute>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct CreateResponse {
    #[serde(rename = "ObjectType")]
    pub object_type: ObjectTypeEnum,
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct RegisterRequest {
    #[serde(rename = "ObjectType")]
    pub object_type: ObjectTypeEnum,

    #[serde(rename = "TemplateAttribute")]
    pub template_attribute: Vec<TemplateAttribute>,

    #[serde(rename = "SecretData", skip_serializing_if = "Option::is_none")]
    pub secret_data: Option<SecretData>,

    #[serde(rename = "SymmetricKey", skip_serializing_if = "Option::is_none")]
    pub symmetric_key: Option<SymmetricKey>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct RegisterResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(skip_serializing_if = "Option::is_none", rename = "TemplateAttribute")]
    pub template_attribute: Option<Vec<TemplateAttribute>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct GetRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(skip_serializing_if = "Option::is_none", rename = "KeyFormatType")]
    pub key_format_type: Option<KeyFormatTypeEnum>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "KeyWrapType")]
    pub key_wrap_type: Option<KeyFormatTypeEnum>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "KeyCompressionType")]
    pub key_compression_type: Option<KeyCompressionType>,
    // TODO KeyWrappingSpecification: KeyWrappingSpecification
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct GetResponse {
    #[serde(rename = "ObjectType")]
    pub object_type: ObjectTypeEnum,

    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(skip_serializing_if = "Option::is_none", rename = "SymmetricKey")]
    pub symmetric_key: Option<SymmetricKey>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "SecretData")]
    pub secret_data: Option<SecretData>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct GetAttributesRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(rename = "AttributeName")]
    pub attribute: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct GetAttributesResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(rename = "Attribute")]
    pub attribute: Vec<AttributesEnum>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct GetAttributeListRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct GetAttributeListResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(rename = "AttributeName")]
    pub attribute: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct ActivateRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "ResponsePayload")]
pub struct ActivateResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct RevokeRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(rename = "RevocationReason")]
    pub revocation_reason: RevocationReason,

    // TODO - the option datetime is messing with Serde
    // Serde thinks the field is required for deserialization even thought it is not
    // ByteBuf works - so look into how it work
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "my_opt_date_format",
        rename = "CompromiseOccurrenceDate"
    )]
    pub compromise_occurrence_date: Option<DateTime<Utc>>,
    // #[serde(skip_serializing_if = "Option::is_none", rename = "CompromiseOccurrenceDate")]
    // pub compromise_occurrence_date: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "ResponsePayload")]
pub struct RevokeResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct DestroyRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "ResponsePayload")]
pub struct DestroyResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct EncryptRequest {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: Option<String>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicParameters"
    )]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    #[serde(with = "serde_bytes", rename = "Data")]
    pub data: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "IVCounterNonce")]
    pub iv_counter_nonce: Option<ByteBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct EncryptResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(with = "serde_bytes", rename = "Data")]
    pub data: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "IVCounterNonce")]
    pub iv_counter_nonce: Option<ByteBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct DecryptRequest {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: Option<String>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicParameters"
    )]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    #[serde(with = "serde_bytes", rename = "Data")]
    pub data: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "IVCounterNonce")]
    pub iv_counter_nonce: Option<ByteBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct DecryptResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(with = "serde_bytes", rename = "Data")]
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct MACRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: Option<String>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicParameters"
    )]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    #[serde(with = "serde_bytes", rename = "Data")]
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct MACResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(with = "serde_bytes", rename = "MACData")]
    pub mac_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename = "RequestPayload")]
pub struct MACVerifyRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: Option<String>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "CryptographicParameters"
    )]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    #[serde(with = "serde_bytes", rename = "Data")]
    pub data: Vec<u8>,

    #[serde(with = "serde_bytes", rename = "MACData")]
    pub mac_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "ResponsePayload")]
pub struct MACVerifyResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,

    #[serde(rename = "ValidityIndicator")]
    pub validity_indicator: ValidityIndicator,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "BatchItem", tag = "Operation", content = "RequestPayload")]
pub enum RequestBatchItem {
    Create(CreateRequest),
    Get(GetRequest),
    GetAttributes(GetAttributesRequest),
    GetAttributeList(GetAttributeListRequest),
    Activate(ActivateRequest),
    Destroy(DestroyRequest),
    Register(RegisterRequest),
    Encrypt(EncryptRequest),
    Decrypt(DecryptRequest),
    MAC(MACRequest),
    MACVerify(MACVerifyRequest),
    Revoke(RevokeRequest),
    // TODO - add support for: Unique Batch Item ID, will require custom deserializer, serializer
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProtocolVersion {
    #[serde(rename = "ProtocolVersionMajor")]
    pub protocol_version_major: i32,

    #[serde(rename = "ProtocolVersionMinor")]
    pub protocol_version_minor: i32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RequestHeader {
    #[serde(rename = "ProtocolVersion")]
    pub protocol_version: ProtocolVersion,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "ClientCorrelationValue"
    )]
    pub client_correlation_value: Option<String>,

    // TODO: Other fields are optional
    #[serde(rename = "BatchCount")]
    pub batch_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestMessage {
    #[serde(rename = "RequestHeader")]
    pub request_header: RequestHeader,

    // TODO - this should be a vector of batch items
    #[serde(rename = "BatchItem")]
    pub batch_item: RequestBatchItem,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ResponseHeader {
    #[serde(rename = "ProtocolVersion")]
    pub protocol_version: ProtocolVersion,

    #[serde(with = "my_date_format", rename = "TimeStamp")]
    pub time_stamp: chrono::DateTime<Utc>,
    // TODO: Other fields are optional
    #[serde(rename = "BatchCount")]
    pub batch_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ResponseOperationEnum {
    Create(CreateResponse),
    Get(GetResponse),
    GetAttributes(GetAttributesResponse),
    GetAttributeList(GetAttributeListResponse),
    Activate(ActivateResponse),
    Destroy(DestroyResponse),
    Register(RegisterResponse),
    Encrypt(EncryptResponse),
    Decrypt(DecryptResponse),
    MAC(MACResponse),
    MACVerify(MACVerifyResponse),
    Revoke(RevokeResponse),
    // TODO - add support for: Unique Batch Item ID
}

#[derive(Debug)]
pub struct ResponseBatchItem {
    pub result_status: ResultStatus,

    pub result_reason: Option<ResultReason>,

    pub result_message: Option<String>,

    pub response_payload: Option<ResponseOperationEnum>,

    // Hack for error messages - we must specify an operation type but it is not a full enum
    pub result_response_enum: Option<Operation>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseMessage {
    #[serde(rename = "ResponseHeader")]
    pub response_header: ResponseHeader,

    #[serde(rename = "BatchItem")]
    pub batch_item: ResponseBatchItem,
}

pub fn get_operation_for_request(item: &RequestBatchItem) -> Operation {
    match item {
        RequestBatchItem::Create(_) => Operation::Create,
        RequestBatchItem::Get(_) => Operation::Get,
        RequestBatchItem::GetAttributes(_) => Operation::GetAttributes,
        RequestBatchItem::GetAttributeList(_) => Operation::GetAttributeList,
        RequestBatchItem::Activate(_) => Operation::Activate,
        RequestBatchItem::Destroy(_) => Operation::Destroy,
        RequestBatchItem::Register(_) => Operation::Register,
        RequestBatchItem::Encrypt(_) => Operation::Encrypt,
        RequestBatchItem::Decrypt(_) => Operation::Decrypt,
        RequestBatchItem::MAC(_) => Operation::MAC,
        RequestBatchItem::MACVerify(_) => Operation::MACVerify,
        RequestBatchItem::Revoke(_) => Operation::Revoke,
    }
}

pub fn get_operation_for_response(item: &ResponseOperationEnum) -> Operation {
    match item {
        ResponseOperationEnum::Create(_) => Operation::Create,
        ResponseOperationEnum::Get(_) => Operation::Get,
        ResponseOperationEnum::GetAttributes(_) => Operation::GetAttributes,
        ResponseOperationEnum::GetAttributeList(_) => Operation::GetAttributeList,
        ResponseOperationEnum::Activate(_) => Operation::Activate,
        ResponseOperationEnum::Destroy(_) => Operation::Destroy,
        ResponseOperationEnum::Register(_) => Operation::Register,
        ResponseOperationEnum::Encrypt(_) => Operation::Encrypt,
        ResponseOperationEnum::Decrypt(_) => Operation::Decrypt,
        ResponseOperationEnum::MAC(_) => Operation::MAC,
        ResponseOperationEnum::MACVerify(_) => Operation::MACVerify,
        ResponseOperationEnum::Revoke(_) => Operation::Revoke,
    }
}

impl Serialize for ResponseBatchItem {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut field_count = 1;
        let mut serialize_reason = false;
        let mut serialize_operation = false;
        let mut serialize_operation_enum = false;
        let mut serialize_message = false;

        if self.result_status == ResultStatus::OperationFailed {
            field_count += 2;
            serialize_reason = true;
            serialize_operation_enum = true;

            if self.result_message.is_some() {
                field_count += 1;
                serialize_message = true;
            }
        }

        //         if self.Operation.is_some() {
        //             field_count += 2;
        //             serialize_operation = true;
        // //            assert_eq!(self.Operation.is_some(), self.ResponsePayload.is_some() );
        //         }

        if self.response_payload.is_some() {
            field_count += 2;
            serialize_operation = true;
        }

        let mut ser_struct = serializer.serialize_struct("BatchItem", field_count)?;

        // if serialize_operation {
        //     let op = self.Operation.as_ref();
        //     ser_struct.serialize_field("Operation", &op)?;
        // }

        if serialize_operation {
            let op = get_operation_for_response(self.response_payload.as_ref().unwrap());
            ser_struct.serialize_field("Operation", &op)?;
        }

        if serialize_operation_enum {
            ser_struct
                .serialize_field("Operation", &self.result_response_enum.as_ref().unwrap())?;
        }

        ser_struct.serialize_field("ResultStatus", &self.result_status)?;

        if serialize_reason {
            ser_struct.serialize_field("ResultReason", &self.result_reason)?;
        }

        if serialize_message {
            ser_struct.serialize_field("ResultMessage", &self.result_message)?;
        }

        if serialize_operation {
            // TODO - use a macro to derive this stuff
            //ser_struct.serialize_field("ResultPayload", &self.response_payload.as_ref())?;
            match self.response_payload.as_ref().unwrap() {
                ResponseOperationEnum::Create(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Get(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::GetAttributes(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::GetAttributeList(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Activate(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Destroy(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Register(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Encrypt(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Decrypt(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::MAC(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::MACVerify(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
                ResponseOperationEnum::Revoke(x) => {
                    ser_struct.serialize_field("ResponsePayload", x)?;
                }
            }
        }

        ser_struct.end()
    }
}

impl<'de> Deserialize<'de> for ResponseBatchItem {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Operation,
            ResultStatus,
            ResultReason,
            ResultMessage,
            ResponsePayload,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("response batch item`")
                    }

                    fn visit_str<E>(self, value: &str) -> std::result::Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        info!("VISITING: {:?}", value);
                        // TODO - include
                        match value {
                            "Operation" => Ok(Field::Operation),
                            "ResultStatus" => Ok(Field::ResultStatus),
                            "ResultReason" => Ok(Field::ResultReason),
                            "ResultMessage" => Ok(Field::ResultMessage),
                            "ResponsePayload" => Ok(Field::ResponsePayload),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ResponseBatchItemVisitor;

        impl<'de> Visitor<'de> for ResponseBatchItemVisitor {
            type Value = ResponseBatchItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ResponseBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ResponseBatchItem, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<Operation> = None;
                let mut result_status: Option<ResultStatus> = None;
                let mut result_reason: Option<ResultReason> = None;
                let mut result_message: Option<String> = None;
                let mut response_payload: Option<ResponseOperationEnum> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(serde::de::Error::duplicate_field("operation"));
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::ResultStatus => {
                            if result_status.is_some() {
                                return Err(serde::de::Error::duplicate_field("result_status"));
                            }
                            result_status = Some(map.next_value()?);
                        }
                        Field::ResultReason => {
                            if result_reason.is_some() {
                                return Err(serde::de::Error::duplicate_field("result_reason"));
                            }
                            result_reason = Some(map.next_value()?);
                        }
                        Field::ResultMessage => {
                            if result_message.is_some() {
                                return Err(serde::de::Error::duplicate_field("result_message"));
                            }
                            result_message = Some(map.next_value()?);
                        }
                        Field::ResponsePayload => {
                            if response_payload.is_some() {
                                return Err(serde::de::Error::duplicate_field("response_payload"));
                            }

                            let op = operation
                                .as_ref()
                                .expect("Operation must come before ResponsePayload");

                            response_payload = match op {
                                Operation::Create => {
                                    let c: CreateResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Create(c))
                                }
                                Operation::Get => {
                                    let c: GetResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Get(c))
                                }
                                Operation::GetAttributes => {
                                    let c: GetAttributesResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::GetAttributes(c))
                                }
                                Operation::GetAttributeList => {
                                    let c: GetAttributeListResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::GetAttributeList(c))
                                }
                                Operation::Activate => {
                                    let c: ActivateResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Activate(c))
                                }
                                Operation::Destroy => {
                                    let c: DestroyResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Destroy(c))
                                }
                                Operation::Register => {
                                    let c: RegisterResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Register(c))
                                }
                                Operation::Encrypt => {
                                    let c: EncryptResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Encrypt(c))
                                }
                                Operation::Decrypt => {
                                    let c: DecryptResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Decrypt(c))
                                }
                                Operation::MAC => {
                                    let c: MACResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::MAC(c))
                                }
                                Operation::MACVerify => {
                                    let c: MACVerifyResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::MACVerify(c))
                                }
                                Operation::Revoke => {
                                    let c: RevokeResponse = map.next_value()?;
                                    Some(ResponseOperationEnum::Revoke(c))
                                }
                                _ => {
                                    unimplemented!();
                                }
                            }
                        }
                    }
                }

                let operation =
                    operation.ok_or_else(|| serde::de::Error::missing_field("Operation"))?;
                let result_status =
                    result_status.ok_or_else(|| serde::de::Error::missing_field("ResultStatus"))?;

                // TODO check for reason and message per KMIP rules

                Ok(ResponseBatchItem {
                    result_status,
                    result_reason,
                    result_message,
                    response_payload,
                    result_response_enum: Some(operation),
                })
            }
        }

        const FIELDS: &[&str] = &[
            "Operation",
            "ResultStatus",
            "ResultReason",
            "ResultMessage",
            "ResponsePayload",
        ];
        deserializer.deserialize_struct("ResponseBatchItem", FIELDS, ResponseBatchItemVisitor)
    }
}

impl<'de> Deserialize<'de> for RevokeRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            UniqueIdentifier,
            RevocationReason,
            CompromiseOccurrenceDate,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("revoke request")
                    }

                    fn visit_str<E>(self, value: &str) -> std::result::Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        info!("VISITING: {:?}", value);
                        // TODO - include
                        match value {
                            "UniqueIdentifier" => Ok(Field::UniqueIdentifier),
                            "RevocationReason" => Ok(Field::RevocationReason),
                            "CompromiseOccurrenceDate" => Ok(Field::CompromiseOccurrenceDate),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct RevokeRequestVisitor;

        impl<'de> Visitor<'de> for RevokeRequestVisitor {
            type Value = RevokeRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct RevokeRequest")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<RevokeRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut unique_identifier: Option<String> = None;
                let mut revocation_reason: Option<RevocationReason> = None;
                let mut compromise_occurrence_date: Option<DateTime<Utc>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::UniqueIdentifier => {
                            if unique_identifier.is_some() {
                                return Err(serde::de::Error::duplicate_field("UniqueIdentifier"));
                            }
                            unique_identifier = Some(map.next_value()?);
                        }
                        Field::RevocationReason => {
                            if revocation_reason.is_some() {
                                return Err(serde::de::Error::duplicate_field("RevocationReason"));
                            }
                            revocation_reason = Some(map.next_value()?);
                        }
                        Field::CompromiseOccurrenceDate => {
                            if compromise_occurrence_date.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "CompromiseOccurrenceDate",
                                ));
                            }
                            let a1: i64 = map.next_value()?;

                            compromise_occurrence_date = Some(chrono::DateTime::<Utc>::from_utc(
                                NaiveDateTime::from_timestamp(a1, 0),
                                Utc,
                            ));
                            // compromise_occurrence_date = Some(map.next_value::<my_date_format>::deserialize()?);
                        }
                    }
                }

                let unique_identifier = unique_identifier
                    .ok_or_else(|| serde::de::Error::missing_field("UniqueIdentifier"))?;
                let revocation_reason = revocation_reason
                    .ok_or_else(|| serde::de::Error::missing_field("RevocationReason"))?;

                // TODO check for reason and message per KMIP rules

                Ok(RevokeRequest {
                    unique_identifier,
                    revocation_reason,
                    compromise_occurrence_date,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "UniqueIdentifier",
            "RevocationReason",
            "CompromiseOccurrenceDate",
        ];
        deserializer.deserialize_struct("RevokeRequest", FIELDS, RevokeRequestVisitor)
    }
}

// impl Serialize for AttributesEnum {
//     fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut state = serializer.serialize_struct("Attribute", 2)?;

//         match &*self {
//             AttributesEnum::CryptographicAlgorithm(i) => {
//                 state.serialize_field(
//                     "AttributeName",
//                     &"Cryptographic Algorithm"
//                 )?;
//                 state.serialize_field("AttributeValue", &i)?;
//             }
//             AttributesEnum::CryptographicLength(i) => {
//                 state.serialize_field(
//                     "AttributeName",
//                     &"Cryptographic Length"
//                 )?;
//                 state.serialize_field("AttributeValue", &i)?;
//             }
//             AttributesEnum::CryptographicUsageMask(i) => {
//                 // TODO - serialize as mask
//                 state.serialize_field(
//                     "AttributeName",
//                     &"Cryptographic Usage Mask"
//                 )?;
//                 state.serialize_field("AttributeValue", &i)?;
//             }
//             AttributesEnum::ActivationDate(date) => {
//                 state.serialize_field(
//                     "AttributeName",
//                     &"Activation Date"
//                 )?;
//                 state.serialize_field("AttributeValue", &date)?;
//             }
//             AttributesEnum::Name(i) => {
//                 state.serialize_field(
//                     "AttributeName",
//                     &"Name"
//                 )?;
//                 state.serialize_field("AttributeValue", &i)?;
//             }
//             AttributesEnum::CryptographicParameters(i) => {
//                 state.serialize_field(
//                     "AttributeName",
//                     &"Cryptographic Parameters"
//                 )?;
//                 state.serialize_field("AttributeValue", &i)?;
//             }
//             AttributesEnum::State(i) => {
//                 state.serialize_field(
//                     "AttributeName",
//                     &"State"
//                 )?;
//                 state.serialize_field("AttributeValue", &i)?;
//             }

//         }

//         state.end()
//     }
// }

pub struct KmipEnumResolver;

impl EnumResolver for KmipEnumResolver {
    fn resolve_enum(&self, orig: &str, value: i32) -> std::result::Result<String, TTLVError> {
        let trimmed = orig.replace(" ", "").replace("_", "");
        let name = trimmed.as_ref();
        let tag = Tag::from_str(name).map_err(|_| TTLVError::XmlError)?;
        self.to_string(tag, value)
    }

    fn resolve_enum_str(&self, tag: Tag, orig: &str) -> std::result::Result<i32, TTLVError> {
        let trimmed = orig.replace(" ", "").replace("_", "");
        let value = trimmed.as_ref();

        match tag {
            Tag::CryptographicAlgorithm => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_i32(&CryptographicAlgorithm::from_str(value).unwrap())
                        .unwrap(),
                )
            }
            Tag::CryptographicUsageMask => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_i32(&CryptographicUsageMask::from_str(value).unwrap())
                        .unwrap(),
                )
            }
            Tag::Operation => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&Operation::from_str(value).unwrap()).unwrap())
            }
            Tag::ObjectType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&ObjectTypeEnum::from_str(value).unwrap()).unwrap())
            }
            Tag::NameType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&NameTypeEnum::from_str(value).unwrap()).unwrap())
            }
            Tag::SecretDataType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&SecretDataType::from_str(value).unwrap()).unwrap())
            }
            Tag::KeyFormatType => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&KeyFormatTypeEnum::from_str(value).unwrap()).unwrap())
            }
            Tag::BlockCipherMode => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&BlockCipherMode::from_str(value).unwrap()).unwrap())
            }
            Tag::PaddingMethod => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&PaddingMethod::from_str(value).unwrap()).unwrap())
            }
            Tag::HashingAlgorithm => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&HashingAlgorithm::from_str(value).unwrap()).unwrap())
            }
            Tag::DigitalSignatureAlgorithm => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_i32(&DigitalSignatureAlgorithm::from_str(value).unwrap())
                        .unwrap(),
                )
            }

            Tag::RevocationReasonCode => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(
                    num::ToPrimitive::to_i32(&RevocationReasonCode::from_str(value).unwrap())
                        .unwrap(),
                )
            }
            Tag::ValidityIndicator => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&ValidityIndicator::from_str(value).unwrap()).unwrap())
            }
            Tag::State => {
                // TODO - go from string to i32 in one pass instead of two
                Ok(num::ToPrimitive::to_i32(&ObjectStateEnum::from_str(value).unwrap()).unwrap())
            }
            _ => {
                println!("Not implemented resolve_enum_str: {:?}", tag);
                unimplemented! {}
            }
        }
    }

    fn to_string(&self, tag: Tag, value: i32) -> std::result::Result<String, TTLVError> {
        match tag {
            Tag::CryptographicAlgorithm => {
                let o: CryptographicAlgorithm = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::Operation => {
                let o: Operation = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ObjectType => {
                let o: ObjectTypeEnum = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ResultStatus => {
                let o: ResultStatus = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ResultReason => {
                let o: ResultReason = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::NameType => {
                let o: NameTypeEnum = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::KeyFormatType => {
                let o: KeyFormatTypeEnum = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::BlockCipherMode => {
                let o: BlockCipherMode = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::PaddingMethod => {
                let o: PaddingMethod = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::HashingAlgorithm => {
                let o: HashingAlgorithm = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::DigitalSignatureAlgorithm => {
                let o: DigitalSignatureAlgorithm = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::SecretDataType => {
                let o: SecretDataType = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::RevocationReasonCode => {
                let o: RevocationReasonCode = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::ValidityIndicator => {
                let o: ValidityIndicator = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }
            Tag::State => {
                let o: ObjectStateEnum = num::FromPrimitive::from_i32(value).unwrap();
                return Ok(o.as_static().to_owned());
            }

            _ => {
                println!("Not implemented to_string: {:?}", tag);
                unimplemented! {}
            }
        }
    }
}

pub fn read_msg(reader: &mut dyn Read) -> std::result::Result<Vec<u8>, TTLVError> {
    let mut msg: Vec<u8> = Vec::new();
    msg.resize(8, 0);

    // TODO -assert item type in buffer
    reader
        .read_exact(msg.as_mut())
        .map_err(|error| TTLVError::BadRead { count: 8, error })?;

    // Check length
    let len: usize;
    {
        let mut cur = Cursor::new(msg);
        read_tag(&mut cur)?;
        let t = read_type(&mut cur)?;
        if t != ItemType::Structure {
            return Err(TTLVError::UnexpectedType {
                expected: ItemType::Structure,
                actual: t,
            });
        }

        len = read_len(&mut cur)? as usize;

        msg = cur.into_inner();
    }

    msg.resize(msg.len() + len, 0);

    let slice: &mut [u8] = msg.as_mut();
    reader
        .read_exact(&mut slice[8..])
        .map_err(|error| TTLVError::BadRead { count: len, error })?;

    Ok(msg)
}
