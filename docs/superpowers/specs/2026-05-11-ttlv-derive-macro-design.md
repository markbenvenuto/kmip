# TtlvDeserialize Derive Macro — Design Spec

**Date:** 2026-05-11
**Branch:** no_serde

## Context

The `no_serde` branch replaces the serde-based KMIP deserialization (`from_bytes::<T>()`) with a
direct token-stream parser. The foundation is already in place:

- `ttlv::de::Reader` parses binary TTLV bytes into a stream of `Value` tokens
- `expect_structure_begin/end`, `expect_integer`, `expect_text_string` are public helpers that
  consume tokens and return typed values or errors
- `parse_request_header` / `parse_request_message` were written manually this session to show
  the pattern

This spec describes a `#[derive(TtlvDeserialize)]` proc-macro that generates that same boilerplate
from struct definitions.

---

## 1. Workspace Layout

Add a new crate `ttlv_derive` to the workspace:

```
ttlv_derive/
  Cargo.toml   (proc-macro = true)
  src/lib.rs
```

Dependencies: `syn = "2"`, `quote = "1"`, `proc-macro2 = "1"`, `heck = "0.5"`.

The `ttlv` crate adds `ttlv_derive` as a regular dependency and re-exports the macro so
consumers only need one import:

```rust
// ttlv/src/lib.rs
pub use ttlv_derive::TtlvDeserialize;
```

---

## 2. The TtlvDeserialize Trait

Defined in `ttlv/src/de.rs`:

```rust
pub trait TtlvDeserialize: Sized {
    fn parse(reader: &mut Reader<'_>) -> Result<Self, TTLVError>;
}
```

The derive macro generates `impl TtlvDeserialize for T`. Nested struct fields call
`T::parse(reader)` directly — no coupling to free functions.

---

## 3. Reader Changes

`Option<T>` and `Vec<T>` fields require non-destructive tag inspection. Add a one-token
lookahead buffer to `Reader`:

```rust
pub struct Reader<'a> {
    len: u64,
    cur: Cursor<&'a [u8]>,
    end_positions: Vec<(Tag, u64)>,
    peeked: Option<Value>,   // new
}
```

`read()` drains `peeked` before reading from the cursor. New public method:

```rust
pub fn peek_tag(&mut self) -> Option<Tag> {
    if self.peeked.is_none() {
        self.peeked = self.read()?.ok();
    }
    self.peeked.as_ref().map(|v| v.tag)
}
```

Synthetic `StructureEnd` tokens work unchanged — `peeked` can hold them, so optional fields at
the end of a structure naturally fall through.

---

## 4. New Helper Functions

Added to `ttlv/src/de.rs` alongside the existing `expect_integer` and `expect_text_string`:

| Function | Rust type | TTLV ValueType |
|---|---|---|
| `expect_integer` | `i32` | `Integer(i32)` — exists |
| `expect_long_integer` | `i64` | `LongInteger(i64)` |
| `expect_boolean` | `bool` | `Boolean(bool)` |
| `expect_byte_string` | `Vec<u8>` | `ByteString(Vec<u8>)` |
| `expect_enumeration` | `u32` | `Enumeration(u32)` |
| `expect_text_string` | `String` | `TextString(String)` — exists |

All follow the same pattern: `reader.read()`, check tag, match value variant, return inner
value or `TTLVError`.

Custom KMIP enum types (e.g. `CryptographicAlgorithm`) are out of scope; map those fields
as `u32` and convert manually for now.

---

## 5. Type Mapping

The macro inspects each field's Rust type syntactically and generates the corresponding call:

| Field type | Generated code |
|---|---|
| `i32` | `expect_integer(reader, Tag::X)?` |
| `i64` | `expect_long_integer(reader, Tag::X)?` |
| `bool` | `expect_boolean(reader, Tag::X)?` |
| `u32` | `expect_enumeration(reader, Tag::X)?` |
| `String` | `expect_text_string(reader, Tag::X)?` |
| `Vec<u8>` | `expect_byte_string(reader, Tag::X)?` |
| `Vec<T>` (T ≠ u8) | `while peek_tag == Tag::X` loop, primitive helper or `T::parse` |
| `Option<T>` | `if peek_tag == Tag::X { Some(...) } else { None }` |
| Any other `T` | `T::parse(reader)?` — assumed `TtlvDeserialize` |

`Vec<u8>` is matched before the general `Vec<T>` case.

---

## 6. Tag Derivation

**Field tags:** snake_case field name → PascalCase via `heck::ToPascalCase` → `Tag::PascalName`.
Example: `protocol_version_major` → `Tag::ProtocolVersionMajor`.

**Struct tag:** struct name used as-is for `expect_structure_begin` / `expect_structure_end`.
Example: `RequestHeader` → `Tag::RequestHeader`.

**Override attribute** (field or struct):
```rust
#[ttlv(tag = "OtherTagName")]
```
The `#[ttlv(...)]` attribute is consumed by the macro and stripped from the output.

---

## 7. Generated Code Examples

**All-required fields:**
```rust
#[derive(TtlvDeserialize)]
struct RequestHeader {
    protocol_version_major: i32,
    batch_count: i32,
}
// expands to:
impl TtlvDeserialize for RequestHeader {
    fn parse(reader: &mut Reader<'_>) -> Result<Self, TTLVError> {
        expect_structure_begin(reader, Tag::RequestHeader)?;
        let protocol_version_major = expect_integer(reader, Tag::ProtocolVersionMajor)?;
        let batch_count = expect_integer(reader, Tag::BatchCount)?;
        expect_structure_end(reader, Tag::RequestHeader)?;
        Ok(Self { protocol_version_major, batch_count })
    }
}
```

**Optional field:**
```rust
optional_iv: Option<Vec<u8>>,
// expands to:
let optional_iv = if reader.peek_tag() == Some(Tag::Iv) {
    Some(expect_byte_string(reader, Tag::Iv)?)
} else {
    None
};
```

**Repeated nested struct:**
```rust
batch_items: Vec<BatchItem>,
// expands to:
let mut batch_items = Vec::new();
while reader.peek_tag() == Some(Tag::BatchItem) {
    batch_items.push(BatchItem::parse(reader)?);
}
```

**Repeated primitive:**
```rust
values: Vec<i32>,
// expands to:
let mut values = Vec::new();
while reader.peek_tag() == Some(Tag::Values) {
    values.push(expect_integer(reader, Tag::Values)?);
}
```

---

## 8. Testing

**`ttlv_derive` crate:** `trybuild` tests verify correct expansion of valid inputs and that
invalid inputs (unknown types, bad attribute syntax) produce the expected compile errors.

**`ttlv` integration tests:** A `tests/` directory in the `ttlv` crate:
- Derives `TtlvDeserialize` for structs matching the hand-written `RequestHeader` /
  `RequestMessage` from this session; asserts same parse results using the existing
  `test_de_struct2` byte arrays
- `Option<T>`: one byte sequence with the optional field present, one without
- `Vec<T>`: byte sequences with zero, one, and multiple repeated elements

---

## Out of Scope

- Custom KMIP enum types as field types (follow-up: a companion `#[derive(TtlvDeserializeEnum)]`)
- Serialization (a `TtlvSerialize` derive is a separate effort)
- Tuple structs, enums, generic structs
