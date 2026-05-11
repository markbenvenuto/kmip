use ttlv::{Reader, TtlvDeserialize};

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
