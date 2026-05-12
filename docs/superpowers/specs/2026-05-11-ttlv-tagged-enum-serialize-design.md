# TtlvTaggedEnumSerialize — Design Spec

**Date:** 2026-05-11  
**Branch:** no_serde  
**Status:** Approved

---

## Overview

Add a `TtlvTaggedEnumSerialize` proc-macro to `ttlv_derive` that generates a `TtlvSerialize` implementation for "tagged enums" — Rust enums whose TTLV wire form is a Structure containing a discriminator Enumeration field followed by a variant-specific value. This is the exact serialize counterpart to the existing `TtlvTaggedEnumDeserialize` macro.

Apply the new macro to `AttributesEnum`, `RequestBatchItem`, and `ResponseOperationEnum` in `protocol/src/lib.rs`.

---

## Motivation

The three protocol enums currently derive `TtlvTaggedEnumDeserialize` (read from wire) but have no TTLV serialization path. The server needs to serialize responses and the client needs to serialize requests. The only existing path is the serde-based XML/JSON path, which is being removed on this branch (`no_serde`).

---

## Wire Format

For a tagged enum, the TTLV encoding is:

```
Structure(outer_tag) {
    Enumeration(discriminator_tag) = discriminator_value,
    <inner value with its own tag>,
}
```

Examples:
- `RequestBatchItem::Create(req)` → `Structure(BatchItem) { Enumeration(Operation)=Create, Structure(RequestPayload){...} }`
- `AttributesEnum::CryptographicLength(256)` → `Structure(Attribute) { Enumeration(AttributeName)=Tag::CryptographicLength, Integer(CryptographicLength)=256 }`

---

## Macro Interface

`TtlvTaggedEnumSerialize` accepts the same `#[ttlv(...)]` attributes as `TtlvTaggedEnumDeserialize`:

| Location | Attribute | Required | Meaning |
|---|---|---|---|
| Enum | `#[ttlv(tag = "BatchItem")]` | Yes | Outer Structure tag |
| Enum | `#[ttlv(discriminator_tag = "Operation")]` | Yes | Tag of the discriminator Enumeration field |
| Enum | `#[ttlv(discriminator_enum = "Operation")]` | No | Auto-map `VariantName` → `EnumName::VariantName as u32` |
| Variant | `#[ttlv(discriminator = Expr)]` | If no `discriminator_enum` | Explicit discriminator value expression |
| Variant | `#[ttlv(value_tag = "TagName")]` | No | Override inner-value tag for primitive variants |

No new attributes are introduced. The attribute set is intentionally identical to the deserialize counterpart so both macros can always be derived together.

---

## Generated Code

### Pattern

```rust
impl ::ttlv::__private::TtlvSerialize for EnumName {
    fn serialize(
        &self,
        writer: &mut dyn ::ttlv::__private::EncodedWriter,
    ) -> ::core::result::Result<(), ::ttlv::__private::TTLVError> {
        ::ttlv::__private::ser_write_structure_begin(writer, STRUCT_TAG)?;
        match self {
            Self::VariantName(v) => {
                ::ttlv::__private::ser_write_enumeration(writer, DISC_TAG, DISC_VALUE as u32)?;
                // inner value write — see dispatch table below
            }
            // ...
        }
        ::ttlv::__private::ser_write_structure_end(writer)?;
        ::core::result::Result::Ok(())
    }
}
```

### Inner value dispatch (per variant)

The inner type determines how the value is written. This reuses the same `write_expr` logic already used by `TtlvSerialize`:

| Inner type | Write call | Value form in match arm |
|---|---|---|
| `i32` | `ser_write_integer(writer, value_tag, *v)` | `*v` (copy) |
| `i64` | `ser_write_long_integer(writer, value_tag, *v)` | `*v` (copy) |
| `u32` | `ser_write_enumeration(writer, value_tag, *v)` | `*v` (copy) |
| `bool` | `ser_write_boolean(writer, value_tag, *v)` | `*v` (copy) |
| `String` | `ser_write_text_string(writer, value_tag, v.as_str())` | `v` (ref) |
| `DateTime<Utc>` | `ser_write_datetime(writer, value_tag, v)` | `v` (ref) |
| `T` (other) | `TtlvSerialize::serialize(v, writer)` | `v` (ref) — type handles its own tag |

The `value_tag` for primitive inner types defaults to `Tag::<VariantName>` or is overridden by `#[ttlv(value_tag = "...")]`.

### Discriminator value

- With `discriminator_enum = "OpEnum"`: auto-derive `OpEnum::VariantName as u32`
- With per-variant `discriminator = Expr`: use `(Expr) as u32`
- Variants with an explicit `discriminator` override the auto-derive even when `discriminator_enum` is set

---

## Implementation Plan

### `ttlv_derive/src/lib.rs`

Add three new items:

1. **`#[proc_macro_derive(TtlvTaggedEnumSerialize, attributes(ttlv))]`** entry point — calls `tagged_enum_serialize_impl`.

2. **`tagged_enum_serialize_impl(input: DeriveInput)`** — parallel to `derive_tagged_enum_impl`:
   - Validates input is an enum
   - Reads `struct_tag`, `disc_tag`, optional `disc_enum_ident` (same attribute lookups as deserializer)
   - Iterates variants, calls `variant_serialize_arm` for each
   - Emits the `impl TtlvSerialize` with `ser_write_structure_begin`, match block, `ser_write_structure_end`

3. **`variant_serialize_arm(variant, disc_enum_ident)`** — parallel to `variant_match_arm`:
   - Validates variant has exactly one unnamed field
   - Resolves discriminator expression (`discriminator_enum` auto-derive or explicit `discriminator`)
   - Resolves `value_tag` (variant name or explicit `value_tag` attribute)
   - Determines `v_expr`: `*v` for copy types, `v` otherwise (same as `option_elem_value`)
   - Calls `write_expr(inner_ty, &value_tag, v_expr)` to get the inner write statement
   - Emits one match arm: `Self::VariantName(v) => { ser_write_enumeration(...)?; #write_stmt }`

No existing functions need modification. All helper functions (`struct_tag_tokens`, `find_ttlv_str_attr`, `find_ttlv_expr_attr`, `write_expr`, `option_elem_value`) are reused as-is.

### `ttlv/src/lib.rs`

Add `TtlvTaggedEnumSerialize` to the existing `pub use ttlv_derive::{ ... }` line.

### `protocol/src/lib.rs`

- Add `use ttlv::TtlvTaggedEnumSerialize;` import
- Add `TtlvTaggedEnumSerialize` to the `#[derive(...)]` of:
  - `AttributesEnum` (line ~885)
  - `RequestBatchItem` (line ~1282)
  - `ResponseOperationEnum` (line ~1351)

### `ttlv/tests/derive_tests.rs`

Add `TtlvTaggedEnumSerialize` to the import line and add a new test section **`TtlvTaggedEnumSerialize round-trip tests`** covering:

- `test_tagged_enum_serialize_primitive_variant` — `TestAttr::CryptographicLength(256)`: serialize and verify bytes match the known deserialization input from the existing test
- `test_tagged_enum_serialize_enum_variant` — `TestAttr::CryptographicAlgorithm(CryptographicAlgorithm::Aes)`: same
- `test_tagged_enum_serialize_struct_variant` — `TestAttr::Name(TestName{...})`: same
- `test_tagged_enum_serialize_discriminator_enum` — `TestItem::Alpha(...)`: verifies `discriminator_enum` auto-derive path

The `TestAttr` and `TestItem` enums used by existing deserialization tests gain `TtlvTaggedEnumSerialize` derives. Byte vectors for assertions are taken from the existing deserialization tests (round-trip: serialize → deserialize → assert equal, and serialize → assert bytes equal known vector).

---

## Error Handling

The macro emits `syn::Error` compile-time diagnostics (same as the deserializer) for:
- Applied to a non-enum type
- Missing `discriminator_tag` attribute
- Variant with != 1 unnamed field
- Variant missing `discriminator` when no `discriminator_enum` is set

---

## Non-goals

- No support for multi-field variants (not used anywhere in the codebase)
- No support for unit variants (no inner value to write)
- No changes to the existing `TtlvTaggedEnumDeserialize` macro
