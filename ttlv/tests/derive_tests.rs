use ttlv::{Reader, Tag, TtlvDeserialize, TtlvEnumDeserialize, TtlvTaggedEnumDeserialize, TTLVError};

// ── Basic required-fields struct ─────────────────────────────────────────────
// Mirrors the hand-written parse_request_header / parse_request_message from de.rs
// Uses the same byte sequence as test_de_struct2.

#[derive(TtlvDeserialize)]
struct RequestHeader {
    protocol_version_major: i32,
    batch_count: i32,
}

#[derive(TtlvDeserialize)]
struct RequestMessage {
    request_header: RequestHeader,
    unique_identifier: String,
}

#[test]
fn test_derive_basic_struct() {
    // Same bytes as test_de_struct2 in de.rs:
    // RequestMessage { RequestHeader { pvm=3, bc=4 }, UniqueIdentifier="" }
    let bytes = [
        66, 0, 120, 1, 0, 0, 0, 48, 66, 0, 119, 1, 0, 0, 0, 32, 66, 0, 106, 2, 0, 0, 0, 4, 0,
        0, 0, 3, 0, 0, 0, 0, 66, 0, 13, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 66, 0, 148, 7,
        0, 0, 0, 0,
    ];
    let mut reader = Reader::new(&bytes);
    let msg = RequestMessage::parse(&mut reader).unwrap();
    assert_eq!(msg.request_header.protocol_version_major, 3);
    assert_eq!(msg.request_header.batch_count, 4);
    assert_eq!(msg.unique_identifier, "");
}

// ── Optional field ────────────────────────────────────────────────────────────
// ResponseHeader (0x42007A) with required ProtocolVersionMajor and optional BatchCount.

#[derive(TtlvDeserialize)]
struct ResponseHeader {
    protocol_version_major: i32,
    batch_count: Option<i32>,
}

#[test]
fn test_derive_option_present() {
    // ResponseHeader { pvm=1, bc=Some(2) }
    // ResponseHeader 0x42007A len=32; pvm=1 (16 bytes); bc=2 (16 bytes)
    let bytes = [
        0x42, 0x00, 0x7A, 0x01, 0x00, 0x00, 0x00, 0x20, // ResponseHeader struct, len=32
        0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, // ProtocolVersionMajor Integer(1)
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, // BatchCount Integer(2)
    ];
    let mut reader = Reader::new(&bytes);
    let hdr = ResponseHeader::parse(&mut reader).unwrap();
    assert_eq!(hdr.protocol_version_major, 1);
    assert_eq!(hdr.batch_count, Some(2));
}

#[test]
fn test_derive_option_absent() {
    // ResponseHeader { pvm=1, bc=None }
    // ResponseHeader 0x42007A len=16; pvm=1 (16 bytes)
    let bytes = [
        0x42, 0x00, 0x7A, 0x01, 0x00, 0x00, 0x00, 0x10, // ResponseHeader struct, len=16
        0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, // ProtocolVersionMajor Integer(1)
    ];
    let mut reader = Reader::new(&bytes);
    let hdr = ResponseHeader::parse(&mut reader).unwrap();
    assert_eq!(hdr.protocol_version_major, 1);
    assert_eq!(hdr.batch_count, None);
}

// ── Repeated nested struct (Vec<T>) ──────────────────────────────────────────
// ResponseMessage (0x42007B) containing zero, one, or two BatchItem (0x42000F) structs.
// Field `batch_items` uses #[ttlv(tag = "BatchItem")] because the field name
// pluralises to BatchItems which is not a valid tag.

#[derive(TtlvDeserialize)]
struct BatchItem {
    batch_count: i32,
}

#[derive(TtlvDeserialize)]
struct ResponseMessage {
    #[ttlv(tag = "BatchItem")]
    batch_items: Vec<BatchItem>,
}

#[test]
fn test_derive_vec_zero() {
    // ResponseMessage { batch_items: [] }
    // ResponseMessage 0x42007B len=0
    let bytes = [0x42, 0x00, 0x7B, 0x01, 0x00, 0x00, 0x00, 0x00];
    let mut reader = Reader::new(&bytes);
    let msg = ResponseMessage::parse(&mut reader).unwrap();
    assert!(msg.batch_items.is_empty());
}

#[test]
fn test_derive_vec_one() {
    // ResponseMessage { batch_items: [BatchItem { batch_count: 5 }] }
    // BatchItem 0x42000F len=16; BatchCount=5 (16 bytes)
    // ResponseMessage 0x42007B len=24 (8 header + 16 content)
    let bytes = [
        0x42, 0x00, 0x7B, 0x01, 0x00, 0x00, 0x00, 0x18, // ResponseMessage struct, len=24
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x10, // BatchItem struct, len=16
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x00, // BatchCount Integer(5)
    ];
    let mut reader = Reader::new(&bytes);
    let msg = ResponseMessage::parse(&mut reader).unwrap();
    assert_eq!(msg.batch_items.len(), 1);
    assert_eq!(msg.batch_items[0].batch_count, 5);
}

#[test]
fn test_derive_vec_two() {
    // ResponseMessage { batch_items: [BatchItem{3}, BatchItem{4}] }
    // Each BatchItem = 8 (header) + 16 (BatchCount) = 24 bytes
    // ResponseMessage len = 48
    let bytes = [
        0x42, 0x00, 0x7B, 0x01, 0x00, 0x00, 0x00, 0x30, // ResponseMessage struct, len=48
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x10, // BatchItem struct, len=16
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, // BatchCount Integer(3)
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x10, // BatchItem struct, len=16
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, // BatchCount Integer(4)
    ];
    let mut reader = Reader::new(&bytes);
    let msg = ResponseMessage::parse(&mut reader).unwrap();
    assert_eq!(msg.batch_items.len(), 2);
    assert_eq!(msg.batch_items[0].batch_count, 3);
    assert_eq!(msg.batch_items[1].batch_count, 4);
}

// ── TtlvEnumDeserialize ───────────────────────────────────────────────────────

#[derive(TtlvEnumDeserialize, num_derive::FromPrimitive, PartialEq, Debug)]
#[repr(i32)]
enum CryptographicAlgorithm {
    Aes = 3,
    TripleDes = 6,
}

// ── TtlvTaggedEnumDeserialize ─────────────────────────────────────────────────

#[derive(TtlvDeserialize, PartialEq, Debug)]
#[ttlv(tag = "Name")]
struct TestName {
    name_type: i32,     // Tag::NameType = 0x420054 — lower tag, comes first in TTLV
    name_value: String, // Tag::NameValue = 0x420055 — higher tag, comes second
}

#[derive(TtlvTaggedEnumDeserialize, PartialEq, Debug)]
#[ttlv(tag = "Attribute")]
#[ttlv(discriminator_tag = "AttributeName")]
enum TestAttr {
    #[ttlv(discriminator = Tag::CryptographicLength)]
    CryptographicLength(i32),

    #[ttlv(discriminator = Tag::CryptographicAlgorithm)]
    CryptographicAlgorithm(CryptographicAlgorithm),

    #[ttlv(discriminator = Tag::Name)]
    Name(TestName),
}

#[derive(TtlvDeserialize, PartialEq, Debug)]
#[ttlv(tag = "TemplateAttribute")]
struct TestTemplate {
    #[ttlv(tag = "Attribute")]
    attrs: Vec<TestAttr>,
}

#[test]
fn test_tagged_enum_primitive_variant() {
    // Attribute { AttributeName=CryptographicLength(0x42002A), CryptographicLength=256 }
    let bytes = [
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x20, // Attribute Structure len=32
        0x42, 0x00, 0x0A, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x42, 0x00, 0x2A, 0x00, 0x00,
        0x00, 0x00, // AttributeName Enum = Tag::CryptographicLength (0x42002A)
        0x42, 0x00, 0x2A, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, // CryptographicLength Integer = 256
    ];
    let mut reader = Reader::new(&bytes);
    let attr = TestAttr::parse(&mut reader).unwrap();
    assert_eq!(attr, TestAttr::CryptographicLength(256));
}

#[test]
fn test_tagged_enum_enum_variant() {
    // Attribute { AttributeName=CryptographicAlgorithm(0x420028), CryptographicAlgorithm=Aes(3) }
    let bytes = [
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x20, // Attribute Structure len=32
        0x42, 0x00, 0x0A, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x42, 0x00, 0x28, 0x00, 0x00,
        0x00, 0x00, // AttributeName Enum = Tag::CryptographicAlgorithm (0x420028)
        0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, // CryptographicAlgorithm Enum = 3 (Aes)
    ];
    let mut reader = Reader::new(&bytes);
    let attr = TestAttr::parse(&mut reader).unwrap();
    assert_eq!(attr, TestAttr::CryptographicAlgorithm(CryptographicAlgorithm::Aes));
}

#[test]
fn test_tagged_enum_struct_variant() {
    // Attribute { AttributeName=Name(0x420053), Name { NameType=1, NameValue="hi" } }
    // NameType (0x420054) sorts before NameValue (0x420055) in TTLV tag order
    let bytes = [
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x38, // Attribute Structure len=56
        0x42, 0x00, 0x0A, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x42, 0x00, 0x53, 0x00, 0x00,
        0x00, 0x00, // AttributeName Enum = Tag::Name (0x420053)
        0x42, 0x00, 0x53, 0x01, 0x00, 0x00, 0x00, 0x20, // Name Structure len=32
        0x42, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, // NameType Integer = 1
        0x42, 0x00, 0x55, 0x07, 0x00, 0x00, 0x00, 0x02, 0x68, 0x69, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // NameValue TextString = "hi"
    ];
    let mut reader = Reader::new(&bytes);
    let attr = TestAttr::parse(&mut reader).unwrap();
    assert_eq!(
        attr,
        TestAttr::Name(TestName { name_type: 1, name_value: "hi".to_string() })
    );
}

#[test]
fn test_tagged_enum_unknown_discriminator() {
    // Attribute { AttributeName=0x99999999 (unknown discriminator) }
    let bytes = [
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x10, // Attribute Structure len=16
        0x42, 0x00, 0x0A, 0x05, 0x00, 0x00, 0x00, 0x04, 0x99, 0x99, 0x99, 0x99, 0x00, 0x00,
        0x00, 0x00, // AttributeName Enum = 0x99999999 (no matching variant)
    ];
    let mut reader = Reader::new(&bytes);
    let err = TestAttr::parse(&mut reader).unwrap_err();
    assert!(matches!(err, TTLVError::InvalidEnumValue { .. }));
}

#[test]
fn test_tagged_enum_vec_field() {
    // TemplateAttribute containing [CryptographicLength=256, CryptographicAlgorithm=Aes]
    let bytes = [
        0x42, 0x00, 0x91, 0x01, 0x00, 0x00, 0x00, 0x50, // TemplateAttribute Structure len=80
        // first Attribute: CryptographicLength=256
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x42, 0x00, 0x0A, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x42, 0x00, 0x2A, 0x00, 0x00,
        0x00, 0x00,
        0x42, 0x00, 0x2A, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00,
        // second Attribute: CryptographicAlgorithm=Aes
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x20,
        0x42, 0x00, 0x0A, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x42, 0x00, 0x28, 0x00, 0x00,
        0x00, 0x00,
        0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut reader = Reader::new(&bytes);
    let tmpl = TestTemplate::parse(&mut reader).unwrap();
    assert_eq!(tmpl.attrs.len(), 2);
    assert_eq!(tmpl.attrs[0], TestAttr::CryptographicLength(256));
    assert_eq!(tmpl.attrs[1], TestAttr::CryptographicAlgorithm(CryptographicAlgorithm::Aes));
}

// ── TtlvEnumDeserialize ───────────────────────────────────────────────────────

#[test]
fn test_enum_valid_value() {
    // CryptographicAlgorithm Enumeration(3) = Aes
    let bytes = [
        0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut reader = Reader::new(&bytes);
    let val = CryptographicAlgorithm::parse(&mut reader).unwrap();
    assert_eq!(val, CryptographicAlgorithm::Aes);
}

#[test]
fn test_enum_unknown_discriminant() {
    // CryptographicAlgorithm Enumeration(0xFFFF) — no such variant
    let bytes = [
        0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut reader = Reader::new(&bytes);
    let err = CryptographicAlgorithm::parse(&mut reader).unwrap_err();
    assert!(matches!(err, TTLVError::InvalidEnumValue { .. }));
}

#[test]
fn test_enum_wrong_tag() {
    // BatchCount (0x42000D) with Enumeration type — wrong tag for CryptographicAlgorithm
    let bytes = [
        0x42, 0x00, 0x0D, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut reader = Reader::new(&bytes);
    let err = CryptographicAlgorithm::parse(&mut reader).unwrap_err();
    assert!(matches!(err, TTLVError::UnexpectedTag { .. }));
}

// Composition: #[derive(TtlvDeserialize)] struct with an enum field

#[derive(TtlvDeserialize)]
#[ttlv(tag = "Attribute")]
struct AlgoAttr {
    cryptographic_algorithm: CryptographicAlgorithm,
}

#[test]
fn test_enum_in_struct() {
    // Attribute Structure containing CryptographicAlgorithm=Aes(3)
    // Attribute (0x420008) Structure len=16
    // CryptographicAlgorithm (0x420028) Enumeration(3) — 16 bytes
    let bytes = [
        0x42, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x10, // Attribute struct, len=16
        0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, // CryptographicAlgorithm Enumeration(3)
    ];
    let mut reader = Reader::new(&bytes);
    let attr = AlgoAttr::parse(&mut reader).unwrap();
    assert_eq!(attr.cryptographic_algorithm, CryptographicAlgorithm::Aes);
}

// ── Tag override on struct ────────────────────────────────────────────────────
// Verify #[ttlv(tag = "...")] on the struct itself uses a different outer tag.

#[derive(TtlvDeserialize)]
#[ttlv(tag = "RequestHeader")]
struct AltHeader {
    protocol_version_major: i32,
    batch_count: i32,
}

#[test]
fn test_derive_struct_tag_override() {
    // RequestHeader bytes from test_de_struct from de.rs (pvm=1, pvm_minor=2 skipped, bc=3)
    // Using simpler: RequestHeader { pvm=3, bc=4 } — same sub-bytes as test_de_struct2
    let bytes = [
        0x42, 0x00, 0x77, 0x01, 0x00, 0x00, 0x00, 0x20, // RequestHeader struct, len=32
        0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x00, // ProtocolVersionMajor Integer(7)
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x00, // BatchCount Integer(8)
    ];
    let mut reader = Reader::new(&bytes);
    let hdr = AltHeader::parse(&mut reader).unwrap();
    assert_eq!(hdr.protocol_version_major, 7);
    assert_eq!(hdr.batch_count, 8);
}
