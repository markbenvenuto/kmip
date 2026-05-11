# TtlvSerialize Proc Macro Design

**Date:** 2026-05-11
**Goal:** Add a `#[derive(TtlvSerialize)]` proc macro to `ttlv_derive` that serializes Rust structs to binary TTLV using the `EncodedWriter` trait. Mirrors the existing `TtlvDeserialize` macro symmetrically.

---

## 1. Scope

Five locations change:

| Location | Change |
|---|---|
| `ttlv/src/ser.rs` | Add `where Self: Sized` to `new()` and `get_vector()` on `EncodedWriter`; define `TtlvSerialize` trait; add `write_*` helper free functions |
| `ttlv/src/lib.rs` | Re-export `TtlvSerialize`; expose helpers + `EncodedWriter` via `__private`; add `pub use ttlv_derive::TtlvSerialize` |
| `ttlv_derive/src/lib.rs` | Add `#[proc_macro_derive(TtlvSerialize, attributes(ttlv))]` entry point + `serialize_impl` function |
| `ttlv_derive/Cargo.toml` | No changes needed |
| `ttlv/src/error.rs` | No changes needed |

No new crates. No `to_bytes()` convenience — callers construct `NestedWriter` themselves and call `get_vector()` after serialization.

---

## 2. EncodedWriter Object-Safety Fix

Two methods on `EncodedWriter` currently take/return `Self`, making the trait not object-safe. Adding `where Self: Sized` to both makes the remaining `&mut self` methods usable through `&mut dyn EncodedWriter`:

```rust
pub trait EncodedWriter {
    fn new() -> Self where Self: Sized;
    fn get_vector(self) -> Vec<u8> where Self: Sized;
    // all other methods unchanged — already &mut self
}
```

Existing call sites for `new()` and `get_vector()` (e.g., the test in `ser.rs`) are unaffected because they already use concrete types.

---

## 3. TtlvSerialize Trait

Defined in `ttlv/src/ser.rs`:

```rust
pub trait TtlvSerialize {
    fn serialize(&self, writer: &mut dyn EncodedWriter) -> TTLVResult<()>;
}
```

Re-exported from `ttlv/src/lib.rs`:
```rust
pub use ser::TtlvSerialize;
pub use ttlv_derive::TtlvSerialize;
```

And via `__private` for use by the derive macro:
```rust
pub mod __private {
    // existing ...
    pub use crate::ser::{
        EncodedWriter, TtlvSerialize,
        write_integer, write_long_integer, write_enumeration,
        write_boolean, write_text_string, write_byte_string,
        write_datetime, write_structure_begin, write_structure_end,
    };
}
```

---

## 4. write_* Helper Functions

Nine public free functions added to `ttlv/src/ser.rs`. Each bundles a tag-write with the appropriate value-write, symmetric with the `expect_*` helpers in `de.rs`:

| Helper signature | Writer calls |
|---|---|
| `write_integer(w: &mut dyn EncodedWriter, tag: Tag, v: i32)` | `w.write_tag(tag)?; w.write_i32(v)` |
| `write_long_integer(w, tag: Tag, v: i64)` | `w.write_tag(tag)?; w.write_i64(v)` |
| `write_enumeration(w, tag: Tag, v: u32)` | `w.write_tag(tag)?; w.write_i32_enumeration(v as i32)` |
| `write_boolean(w, tag: Tag, v: bool)` | `w.write_tag(tag)?; w.write_boolean(v)` |
| `write_text_string(w, tag: Tag, v: &str)` | `w.write_tag(tag)?; w.write_string(v)` |
| `write_byte_string(w, tag: Tag, v: &[u8])` | `w.write_tag(tag)?; w.write_bytes(v)` |
| `write_datetime(w, tag: Tag, v: &DateTime<Utc>)` | `w.write_tag(tag)?; w.write_i64_datetime(v.timestamp())` |
| `write_structure_begin(w, tag: Tag)` | `w.write_tag(tag)?; w.write_struct_start()?; w.begin_inner()` |
| `write_structure_end(w)` | `w.close_inner()` |

All return `TTLVResult<()>`.

---

## 5. Generated Code

### Struct-level

The struct tag is derived from the struct name converted to PascalCase, or overridden with `#[ttlv(tag = "TagName")]` — identical to `TtlvDeserialize`.

For a struct `RequestHeader` with fields `protocol_version_major: i32` and `batch_count: i32`:

```rust
impl ::ttlv::__private::TtlvSerialize for RequestHeader {
    fn serialize(
        &self,
        writer: &mut dyn ::ttlv::__private::EncodedWriter,
    ) -> ::core::result::Result<(), ::ttlv::__private::TTLVError> {
        ::ttlv::__private::write_structure_begin(writer, ::ttlv::__private::Tag::RequestHeader)?;
        ::ttlv::__private::write_integer(writer, ::ttlv::__private::Tag::ProtocolVersionMajor, self.protocol_version_major)?;
        ::ttlv::__private::write_integer(writer, ::ttlv::__private::Tag::BatchCount, self.batch_count)?;
        ::ttlv::__private::write_structure_end(writer)?;
        ::core::result::Result::Ok(())
    }
}
```

### Field type mapping

| Rust field type | Generated expression |
|---|---|
| `i32` | `write_integer(writer, TAG, self.f)?` |
| `i64` | `write_long_integer(writer, TAG, self.f)?` |
| `u32` | `write_enumeration(writer, TAG, self.f)?` |
| `bool` | `write_boolean(writer, TAG, self.f)?` |
| `String` | `write_text_string(writer, TAG, &self.f)?` |
| `Vec<u8>` | `write_byte_string(writer, TAG, &self.f)?` |
| `DateTime<Utc>` | `write_datetime(writer, TAG, &self.f)?` |
| `Option<T>` | `if let Some(ref v) = self.f { write_*(writer, TAG, v or *v or v.as_str())?; }` — copy types (`i32`, `i64`, `u32`, `bool`) are dereferenced with `*v`; `String` uses `v.as_str()`; `Vec<u8>` uses `v.as_slice()`; nested `T` passes `v` directly |
| `Vec<T>` (T ≠ u8) | `for v in &self.f { write_*(writer, TAG, v or *v)?; }` — same deref rules as above |
| `T` (nested struct) | `<T as ::ttlv::__private::TtlvSerialize>::serialize(&self.f, writer)?` |

For `Option<Vec<u8>>`, the inner `Vec<u8>` is treated as a byte string (matching the `TtlvDeserialize` handling).

### Macro implementation in ttlv_derive

New entry point added alongside the existing `derive_ttlv_deserialize`:

```rust
#[proc_macro_derive(TtlvSerialize, attributes(ttlv))]
pub fn derive_ttlv_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    serialize_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}
```

`serialize_impl` mirrors `derive_impl` in structure:
- Reuses `struct_tag_tokens` and `field_tag_tokens` (no duplication)
- Adds a new `serialize_field_statement` function (analogous to `field_statement`) that dispatches to `write_*` helpers based on field type
- Adds a new `write_expr` function (analogous to `value_expr`) that generates the write call for a single value

---

## 6. Error Handling

All generated calls propagate errors with `?`. The trait method returns `TTLVResult<()>` — same error type as the deserializer. No new error variants needed.

---

## 7. Testing

A `#[test]` in `ttlv/src/ser.rs` (or a new integration test) derives `TtlvSerialize` on a minimal struct and round-trips through the binary TTLV format:

```rust
#[derive(TtlvSerialize, TtlvDeserialize)]
struct RequestHeader {
    protocol_version_major: i32,
    batch_count: i32,
}
```

Test assertions:
- Serialized bytes match the expected TTLV binary for a known `RequestHeader`
- A struct serialized then deserialized produces the original value (round-trip)
- Optional fields absent when `None`, present when `Some`
- Repeated fields (`Vec<T>`) serialize in order
