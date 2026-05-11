# TtlvEnumDeserialize Derive Macro — Design Spec

**Date:** 2026-05-11
**Branch:** no_serde

## Context

The `TtlvDeserialize` derive macro (spec: `2026-05-11-ttlv-derive-macro-design.md`) handles
structs. Its unknown-type code path already calls `<T as TtlvDeserialize>::parse(reader)?` for
any field type that is not a recognised primitive. This spec adds `#[derive(TtlvEnumDeserialize)]`
to fill the gap: it generates `impl TtlvDeserialize for T` for `#[repr(i32)]` KMIP enumeration
types, so enum fields in derived structs work without any additional annotation.

---

## 1. The Derive Macro

`#[derive(TtlvEnumDeserialize)]` is added to `ttlv_derive/src/lib.rs` alongside the existing
`TtlvDeserialize` macro. It accepts the same `#[ttlv(tag = "...")]` attribute.

**Input requirements:**
- Must be an enum (not a struct/union)
- Must have `#[derive(num_derive::FromPrimitive)]` — the generated code calls
  `::num::FromPrimitive::from_u32(v)`

**Tag derivation:** enum type name used as-is → `Tag::EnumName`.
Override: `#[ttlv(tag = "OtherTag")]` on the enum.

---

## 2. Generated Code

Given:

```rust
#[derive(TtlvEnumDeserialize, num_derive::FromPrimitive)]
#[repr(i32)]
enum CryptographicAlgorithm {
    Aes = 3,
    TripleDes = 6,
}
```

Generates:

```rust
impl ::ttlv::__private::TtlvDeserialize for CryptographicAlgorithm {
    fn parse(
        reader: &mut ::ttlv::__private::Reader<'_>,
    ) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
        let token = reader.read()
            .ok_or(::ttlv::__private::TTLVError::EndOfTokenStream)??;
        let expected = ::ttlv::__private::Tag::CryptographicAlgorithm;
        if token.tag != expected {
            return Err(::ttlv::__private::TTLVError::UnexpectedTag {
                expected,
                actual: token.tag,
            });
        }
        match token.value {
            ::ttlv::__private::ValueType::Enumeration(v) => {
                ::num::FromPrimitive::from_u32(v).ok_or(
                    ::ttlv::__private::TTLVError::InvalidEnumValue {
                        tag: expected,
                        value: v,
                    },
                )
            }
            _ => Err(::ttlv::__private::TTLVError::WrongValueType { tag: token.tag }),
        }
    }
}
```

---

## 3. Required Changes

### `ttlv/src/error.rs`

Add one variant to `TTLVError`:

```rust
#[error("invalid enum value for tag {:?}: {}", tag, value)]
InvalidEnumValue { tag: Tag, value: u32 },
```

### `ttlv/src/lib.rs` — `__private` module

Expose `ValueType` so the generated match can reference it:

```rust
pub use crate::kmip_enums::ValueType;
```

### `ttlv_derive/src/lib.rs`

Add a new `#[proc_macro_derive(TtlvEnumDeserialize, attributes(ttlv))]` entry point.
The existing `find_ttlv_tag_attr` helper is reused for attribute parsing.
The existing `struct_tag_tokens` logic is reused (adapted for enum ident).

**No changes to the struct macro** — its unknown-type code path
(`<T as TtlvDeserialize>::parse(reader)?`) already works for enum types.

---

## 4. Composing with the Struct Macro

A struct field of an enum type requires no annotation:

```rust
#[derive(TtlvDeserialize)]
struct KeyBlock {
    cryptographic_algorithm: CryptographicAlgorithm,  // unknown type → T::parse(reader)?
}
```

The field name `cryptographic_algorithm` → `Tag::CryptographicAlgorithm` in the struct macro,
and `CryptographicAlgorithm::parse` also reads `Tag::CryptographicAlgorithm`. Both agree.

---

## 5. Testing

Added to `ttlv/tests/derive_tests.rs`:

- **Valid value** — bytes encoding `Enumeration(3)` under `Tag::CryptographicAlgorithm` parse
  to the expected variant
- **Unknown discriminant** — unrecognised u32 returns `TTLVError::InvalidEnumValue`
- **Wrong tag** — correct value type but wrong tag returns `TTLVError::UnexpectedTag`
- **Composition** — a `#[derive(TtlvDeserialize)]` struct with an enum field parses correctly
  end-to-end from raw bytes

---

## Out of Scope

- Enum variants with associated data (only unit variants are supported)
- Enums without `#[repr(i32)]` / `num_derive::FromPrimitive`
- `TtlvSerialize` for enum types (separate effort)
