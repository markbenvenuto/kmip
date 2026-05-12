#![allow(clippy::upper_case_acronyms)]

use std::str::FromStr;

use chrono::DateTime;
use chrono::Utc;
use num::FromPrimitive;
use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use strum::AsStaticRef;
use strum_macros::AsStaticStr;
use strum_macros::Display;
use strum_macros::EnumString;
use ttlv::NestedWriter;
use ttlv::Reader;
use ttlv::TTLVError;
use ttlv::Tag;
use ttlv::TtlvDeserialize;
use ttlv::TtlvEnumDeserialize;
use ttlv::TtlvEnumSerialize;
use ttlv::TtlvSerialize;
use ttlv::TtlvTaggedEnumDeserialize;
use ttlv::TtlvTaggedEnumSerialize;
use ttlv::de_xml::EnumResolver;
use ttlv::parser::expect_boolean;
use ttlv::parser::expect_enumeration;
use ttlv::parser::expect_integer;
use ttlv::ser::EncodedWriter;

#[derive(
    FromPrimitive,
    ToPrimitive,
    Debug,
    EnumString,
    AsStaticStr,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    PartialEq,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
)]
#[ttlv(tag = "ObjectType")]
#[repr(i32)]
pub enum ObjectType {
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    PartialEq,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
)]
#[ttlv(tag = "State")]
#[repr(i32)]
pub enum State {
    PreActive = 0x00000001,
    Active = 0x00000002,
    Deactivated = 0x00000003,
    Compromised = 0x00000004,
    Destroyed = 0x00000005,
    DestroyedCompromised = 0x00000006,
}

#[derive(
    Debug,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Copy,
    Clone,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
)]
#[ttlv(tag = "NameType")]
#[repr(i32)]
pub enum NameType {
    UninterpretedTextString = 0x00000001,
    URI = 0x00000002,
}

#[derive(
    Debug,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    PartialEq,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    Debug,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
)]
#[ttlv(tag = "KeyFormatType")]
#[repr(i32)]
pub enum KeyFormatType {
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
)]
#[repr(i32)]
pub enum SecretDataType {
    Password = 0x00000001,
    Seed = 0x00000002,
}

#[derive(
    Debug,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
)]
#[repr(i32)]
pub enum EncodingOption {
    NoEncoding = 0x00000001,
    TTLVEncoding = 0x00000002,
}

#[derive(
    Debug,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
    Serialize,
    Deserialize,
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
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
)]
#[repr(i32)]
pub enum ValidityIndicator {
    Valid = 0x00000001,
    Invalid = 0x00000002,
    Unknown = 0x00000003,
}

#[derive(
    Debug,
    EnumString,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Clone,
    Copy,
    TtlvEnumDeserialize,
    PartialEq,
    TtlvEnumSerialize,
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

#[derive(
    Debug,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    PartialEq,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
)]
#[repr(i32)]
pub enum ResultStatus {
    Success = 0x00000000,
    OperationFailed = 0x00000001,
    OperationPending = 0x00000002,
    OperationUndone = 0x00000003,
}

#[derive(
    Debug,
    FromPrimitive,
    ToPrimitive,
    AsStaticStr,
    Copy,
    Clone,
    Display,
    TtlvEnumDeserialize,
    TtlvEnumSerialize,
)]
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

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct KeyValue {
    pub key_material: Vec<u8>,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct EncryptionKeyInformation {
    pub unique_identifier: String,
    //#[serde(skip_serializing_if = "Option::is_none", rename = "CryptographicParameters")]
    //pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct MACSignatureKeyInformation {
    pub unique_identifier: String,
    //pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct KeyWrappingData {
    pub wrapping_method: WrappingMethod,

    pub encryption_key_information: Option<EncryptionKeyInformation>,

    #[ttlv(tag = "MACSignatureKeyInformation")]
    pub mac_signature_key_information: Option<MACSignatureKeyInformation>,

    #[ttlv(tag = "MACSignature")]
    pub mac_signature: Option<Vec<u8>>,

    #[ttlv(tag = "IVCounterNonce")]
    pub iv_counter_nonce: Option<Vec<u8>>,

    pub encoding_option: Option<EncodingOption>,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,

    pub key_compression_type: Option<KeyCompressionType>,

    // TODO : this type is not just a struct all the time
    pub key_value: KeyValue,

    // omitted in for SecretData and other cases
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    pub cryptographic_length: Option<i32>,

    // TODO
    pub key_wrapping_data: Option<KeyWrappingData>,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct CryptographicParameters {
    pub block_cipher_mode: Option<BlockCipherMode>,

    pub padding_method: Option<PaddingMethod>,

    pub hashing_algorithm: Option<HashingAlgorithm>,

    pub key_role_type: Option<KeyRoleType>,

    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,

    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    #[ttlv(tag = "RandomIV")]
    pub random_iv: Option<bool>,

    #[ttlv(tag = "IVLength")]
    pub iv_length: Option<i32>,

    pub tag_length: Option<i32>,

    pub fixed_field_length: Option<i32>,

    pub invocation_field_length: Option<i32>,

    pub counter_length: Option<i32>,

    pub initial_counter_value: Option<i32>,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct SymmetricKey {
    pub key_block: KeyBlock,
}

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
pub struct SecretData {
    pub secret_data_type: SecretDataType,

    pub key_block: KeyBlock,
}

// #[derive( Debug, TtlvDeserialize)]
// pub struct AttributeStruct {
//     pub attribute_name: String,
//     pub attribute_index: Option<i32>,
//     // AttributeValue type varies based on type
//     //AttributeValue: ???
// }

#[derive(Debug, Clone, TtlvDeserialize, TtlvSerialize, Serialize, Deserialize)]
#[ttlv(tag = "Name")]
pub struct Name {
    pub name_value: String,

    pub name_type: NameType,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
pub struct RevocationReason {
    pub revocation_reason_code: RevocationReasonCode,

    pub revocation_message: Option<String>,
}

// #[derive( Debug, TtlvDeserialize)]
// struct TemplateAttribute {
//     Name : Name,
//     Attribute : AttributeStruct,
// }

#[derive(Debug, Clone)]
pub enum AttributesEnum {
    CryptographicAlgorithm(CryptographicAlgorithm),
    CryptographicLength(i32),
    CryptographicUsageMask(i32),
    ActivationDate(DateTime<Utc>),
    DeactivationDate(DateTime<Utc>),
    Name(Name),
    CryptographicParameters(CryptographicParameters),
    State(State),
    InitialDate(DateTime<Utc>),
    LastChangeDate(DateTime<Utc>),
    ObjectType(ObjectType),
    UniqueIdentifier(String),
}

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

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]

pub struct TemplateAttribute {
    pub name: Option<Name>,

    pub attribute: Vec<AttributesEnum>,
}

///////////////////////////////////////////////////

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct CreateRequest {
    pub object_type: ObjectType,

    pub template_attribute: Vec<TemplateAttribute>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct CreateResponse {
    pub object_type: ObjectType,
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct RegisterRequest {
    pub object_type: ObjectType,

    pub template_attribute: Vec<TemplateAttribute>,

    pub secret_data: Option<SecretData>,

    pub symmetric_key: Option<SymmetricKey>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct RegisterResponse {
    pub unique_identifier: String,

    pub template_attribute: Option<Vec<TemplateAttribute>>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct GetRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: String,

    pub key_format_type: Option<KeyFormatType>,

    pub key_wrap_type: Option<KeyFormatType>,

    pub key_compression_type: Option<KeyCompressionType>,
    // TODO KeyWrappingSpecification: KeyWrappingSpecification
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct GetResponse {
    pub object_type: ObjectType,

    pub unique_identifier: String,

    pub symmetric_key: Option<SymmetricKey>,

    pub secret_data: Option<SecretData>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct GetAttributesRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: String,

    pub attribute_name: Option<Vec<String>>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct GetAttributesResponse {
    pub unique_identifier: String,

    pub attribute: Vec<AttributesEnum>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct GetAttributeListRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct GetAttributeListResponse {
    pub unique_identifier: String,

    pub attribute: Vec<String>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct ActivateRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct ActivateResponse {
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct RevokeRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: String,

    pub revocation_reason: RevocationReason,

    // TODO - the option datetime is messing with Serde
    // Serde thinks the field is required for deserialization even thought it is not
    // ByteBuf works - so look into how it work
    pub compromise_occurrence_date: Option<DateTime<Utc>>,
    // pub compromise_occurrence_date: Option<String>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct RevokeResponse {
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct DestroyRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct DestroyResponse {
    pub unique_identifier: String,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct EncryptRequest {
    pub unique_identifier: Option<String>,

    pub cryptographic_parameters: Option<CryptographicParameters>,

    pub data: Vec<u8>,

    #[ttlv(tag = "IVCounterNonce")]
    pub iv_counter_nonce: Option<Vec<u8>>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct EncryptResponse {
    pub unique_identifier: String,

    pub data: Vec<u8>,

    #[ttlv(tag = "IVCounterNonce")]
    pub iv_counter_nonce: Option<Vec<u8>>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct DecryptRequest {
    pub unique_identifier: Option<String>,

    pub cryptographic_parameters: Option<CryptographicParameters>,

    pub data: Vec<u8>,

    #[ttlv(tag = "IVCounterNonce")]
    pub iv_counter_nonce: Option<Vec<u8>>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct DecryptResponse {
    pub unique_identifier: String,

    pub data: Vec<u8>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct MACRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: Option<String>,

    pub cryptographic_parameters: Option<CryptographicParameters>,

    pub data: Vec<u8>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct MACResponse {
    pub unique_identifier: String,

    #[ttlv(tag = "MACData")]
    pub mac_data: Vec<u8>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "RequestPayload")]
pub struct MACVerifyRequest {
    // TODO - this is optional in batches - we use the implicit server generated id from the first batch
    pub unique_identifier: Option<String>,

    pub cryptographic_parameters: Option<CryptographicParameters>,

    pub data: Vec<u8>,

    #[ttlv(tag = "MACData")]
    pub mac_data: Vec<u8>,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
#[ttlv(tag = "ResponsePayload")]
pub struct MACVerifyResponse {
    pub unique_identifier: String,

    pub validity_indicator: ValidityIndicator,
}

#[derive(Debug, TtlvTaggedEnumDeserialize, TtlvTaggedEnumSerialize)]
#[ttlv(tag = "BatchItem")]
#[ttlv(discriminator_tag = "Operation")]
#[ttlv(discriminator_enum = "Operation")]
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

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
pub struct ProtocolVersion {
    pub protocol_version_major: i32,

    pub protocol_version_minor: i32,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
pub struct RequestHeader {
    pub protocol_version: ProtocolVersion,

    pub client_correlation_value: Option<String>,

    // TODO: Other fields are optional
    pub batch_count: i32,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
pub struct RequestMessage {
    pub request_header: RequestHeader,

    // TODO - this should be a vector of batch items
    pub batch_item: RequestBatchItem,
}

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
pub struct ResponseHeader {
    pub protocol_version: ProtocolVersion,

    pub time_stamp: chrono::DateTime<Utc>,
    // TODO: Other fields are optional
    pub batch_count: i32,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ResponseBatchItem {
    pub operation: Option<Operation>,

    pub result_status: ResultStatus,

    pub result_reason: Option<ResultReason>,

    pub result_message: Option<String>,

    pub response_payload: Option<ResponseOperationEnum>,
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

#[derive(Debug, TtlvDeserialize, TtlvSerialize)]
pub struct ResponseMessage {
    pub response_header: ResponseHeader,

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
