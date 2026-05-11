# TtlvTaggedEnumDeserialize Derive Macro — Design Spec

**Date:** 2026-05-11
**Branch:** no_serde

## Context

The `ttlv` crate already has `TtlvDeserialize` (structs) and `TtlvEnumDeserialize` (integer-discriminated enums).
A third pattern exists in the KMIP protocol: enums whose variants are selected by reading an Enumeration
discriminator field first, then parsing the variant's payload using the inner type's own `TtlvDeserialize`
impl. `AttributesEnum`, `RequestBatchItem`, and `ResponseOperationEnum` in `protocol/src/lib.rs` all follow
this pattern.

This spec adds `#[derive(TtlvTaggedEnumDeserialize)]` to cover it.

---

## 1. Macro API

### Enum-level attributes

```rust
#[derive(TtlvTaggedEnumDeserialize)]
#[ttlv(tag = "Attribute", discriminator_tag = "AttributeName")]
pub enum AttributesEnum { ... }
```

| Attribute | Required | Meaning |
|---|---|---|
| `tag` | If enum name ≠ KMIP tag | Outer Structure tag (string → `Tag::Ident`) |
| `discriminator_tag` | Yes | Tag of the Enumeration field read as the discriminator |

If `tag` is omitted the enum's type name is used directly (same rule as struct macro).

### Variant-level attributes

```rust
#[ttlv(discriminator = Tag::CryptographicAlgorithm)]
CryptographicAlgorithm(CryptographicAlgorithm),
```

| Attribute | Required | Meaning |
|---|---|---|
| `discriminator` | Yes | Rust expression whose value (cast to `u32`) identifies this variant |
| `value_tag` | No | Override the inferred value tag (defaults to variant name in PascalCase → `Tag::VariantName`) |

The `discriminator` expression is emitted verbatim into a match guard:
`d if d == (#expr) as u32`. Callers may write `Tag::CryptographicAlgorithm`,
`Operation::Create`, or a raw integer literal.

### Value tag inference

The tag used to parse the variant's inner value is inferred from the variant name
(PascalCase → `Tag::VariantName`). This matches the convention already used for
struct fields in `TtlvDeserialize`. Override with `#[ttlv(value_tag = "OtherTag")]`
when the variant name does not match the KMIP tag name.

---

## 2. Generated Code

Given:

```rust
#[derive(TtlvTaggedEnumDeserialize)]
#[ttlv(tag = "Attribute", discriminator_tag = "AttributeName")]
pub enum AttributesEnum {
    #[ttlv(discriminator = Tag::CryptographicAlgorithm)]
    CryptographicAlgorithm(CryptographicAlgorithm),

    #[ttlv(discriminator = Tag::CryptographicLength)]
    CryptographicLength(i32),

    #[ttlv(discriminator = Tag::Name)]
    Name(Name),
}
```

Generates:

```rust
impl ::ttlv::__private::TtlvDeserialize for AttributesEnum {
    fn parse(
        reader: &mut ::ttlv::__private::Reader<'_>,
    ) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
        ::ttlv::__private::expect_structure_begin(reader, ::ttlv::__private::Tag::Attribute)?;

        let disc = ::ttlv::__private::expect_enumeration(reader, ::ttlv::__private::Tag::AttributeName)?;

        let result = match disc {
            d if d == (Tag::CryptographicAlgorithm) as u32 =>
                Self::CryptographicAlgorithm(
                    <CryptographicAlgorithm as ::ttlv::__private::TtlvDeserialize>::parse(reader)?
                ),
            d if d == (Tag::CryptographicLength) as u32 =>
                Self::CryptographicLength(
                    ::ttlv::__private::expect_integer(reader, ::ttlv::__private::Tag::CryptographicLength)?
                ),
            d if d == (Tag::Name) as u32 =>
                Self::Name(
                    <Name as ::ttlv::__private::TtlvDeserialize>::parse(reader)?
                ),
            v => return ::core::result::Result::Err(
                ::ttlv::__private::TTLVError::InvalidEnumValue {
                    tag: ::ttlv::__private::Tag::AttributeName,
                    value: v,
                }
            ),
        };

        ::ttlv::__private::expect_structure_end(reader, ::ttlv::__private::Tag::Attribute)?;
        ::core::result::Result::Ok(result)
    }
}
```

### Value dispatch rules

The per-variant value parsing reuses the same type-dispatch logic as the struct macro's `value_expr`:

| Rust type | Generated call |
|---|---|
| `i32` | `expect_integer(reader, Tag::VariantName)?` |
| `i64` | `expect_long_integer(reader, Tag::VariantName)?` |
| `bool` | `expect_boolean(reader, Tag::VariantName)?` |
| `u32` | `expect_enumeration(reader, Tag::VariantName)?` |
| `String` | `expect_text_string(reader, Tag::VariantName)?` |
| `DateTime<Utc>` | `expect_datetime(reader, Tag::VariantName)?` |
| `Vec<u8>` | `expect_byte_string(reader, Tag::VariantName)?` |
| Any other `T` | `<T as TtlvDeserialize>::parse(reader)?` |

---

## 3. Required Changes

### `ttlv_derive/src/lib.rs`

Add `#[proc_macro_derive(TtlvTaggedEnumDeserialize, attributes(ttlv))]` entry point and
`derive_tagged_enum_impl`.

Extend attribute parsing:
- Replace `find_ttlv_tag_attr` with a general `find_ttlv_str_attr(attrs, key)` for any
  `#[ttlv(key = "string")]` attribute. Update existing callers of `find_ttlv_tag_attr`
  to call `find_ttlv_str_attr(attrs, "tag")`. The new `discriminator_tag` and
  `value_tag` attributes also use this form.
- Add `find_ttlv_expr_attr(attrs, key)` returning `Option<syn::Expr>` for
  expression-valued attributes like `discriminator = Tag::CryptographicAlgorithm`.

The macro validates:
- Input must be an enum (not a struct/union)
- `discriminator_tag` must be present at enum level
- Every variant must have exactly one unnamed field (newtype style)
- Every variant must have a `discriminator` attribute

### `ttlv/src/lib.rs`

- Export `TtlvTaggedEnumDeserialize` from `ttlv_derive`
- Export `Tag` at the top-level public API (currently only in `__private`) so callers
  can write `ttlv::Tag::*` in `discriminator` annotations

### `protocol/src/lib.rs`

- Add `#[derive(TtlvDeserialize)]` to the `Name` struct (currently missing it; required
  because `AttributesEnum::Name(Name)` dispatches to `Name::parse`)
- Add `#[derive(TtlvTaggedEnumDeserialize)]` to `AttributesEnum` with the enum-level
  and per-variant attributes for all 12 variants

### `ttlv/tests/derive_tests.rs`

New integration tests (see Section 4).

---

## 4. Testing

A self-contained test enum defined inside `derive_tests.rs` (not pulling in `protocol`):

```rust
#[derive(TtlvEnumDeserialize, num_derive::FromPrimitive, PartialEq, Debug)]
#[repr(i32)]
enum TestAlgorithm { Aes = 3 }

#[derive(TtlvDeserialize, PartialEq, Debug)]
struct TestName { name_value: String, name_type: i32 }

#[derive(TtlvTaggedEnumDeserialize, PartialEq, Debug)]
#[ttlv(tag = "Attribute", discriminator_tag = "AttributeName")]
enum TestAttr {
    #[ttlv(discriminator = Tag::CryptographicLength)]
    CryptographicLength(i32),

    #[ttlv(discriminator = Tag::CryptographicAlgorithm)]
    CryptographicAlgorithm(TestAlgorithm),

    #[ttlv(discriminator = Tag::Name)]
    Name(TestName),
}
```

Test cases:

1. **Primitive variant** — bytes for `Attribute { AttributeName=CryptographicLength, CryptographicLength=256 }` → `TestAttr::CryptographicLength(256)`
2. **Enum variant** — bytes for `Attribute { AttributeName=CryptographicAlgorithm, CryptographicAlgorithm=Aes(3) }` → `TestAttr::CryptographicAlgorithm(TestAlgorithm::Aes)`
3. **Struct variant** — bytes for `Attribute { AttributeName=Name, Name { NameValue="hi", NameType=1 } }` → `TestAttr::Name(TestName { name_value: "hi", name_type: 1 })`
4. **Unknown discriminator** — unrecognised `AttributeName` Enumeration value → `TTLVError::InvalidEnumValue`
5. **Vec<TestAttr>** — a wrapping struct with a `Vec<TestAttr>` field (two attributes back-to-back), verifying the repeated-field path through the struct macro

---

## 5. Composing with Existing Macros

`RequestBatchItem` and `ResponseOperationEnum` follow the same pattern and can adopt
`TtlvTaggedEnumDeserialize` once their inner types (`CreateRequest`, `GetRequest`, etc.)
have `TtlvDeserialize` impls. That work is out of scope here; this spec delivers the
macro mechanism and validates it end-to-end with `AttributesEnum`.

---

## Out of Scope

- Enum variants with more than one field
- Variants without a `discriminator` attribute (no default inference)
- `TtlvSerialize` / serialization direction
- `RequestBatchItem` / `ResponseOperationEnum` end-to-end wiring (inner types lack `TtlvDeserialize`)
