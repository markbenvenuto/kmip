# TtlvEnumSerialize Derive Macro — Design Spec

**Date:** 2026-05-11
**Branch:** no_serde

## Context

The `TtlvSerialize` derive macro (spec: `2026-05-11-ttlv-serialize-design.md`) handles structs.
Its "nested T" fallthrough already calls `TtlvSerialize::serialize(value, writer)?` for any field
type it does not recognise as a primitive. This spec adds `#[derive(TtlvEnumSerialize)]` to fill
the gap: it generates `impl TtlvSerialize for T` for `#[repr(i32)]` KMIP enumeration types, so
enum fields in derived structs work without any additional annotation.

This macro is the direct serialization counterpart to `TtlvEnumDeserialize`
(spec: `2026-05-11-ttlv-enum-deserialize-design.md`).

---

## 1. The Derive Macro

`#[derive(TtlvEnumSerialize)]` is added to `ttlv_derive/src/lib.rs` alongside the three existing
macros. It accepts the same `#[ttlv(tag = "...")]` attribute.

**Input requirements:**
- Must be an enum (not a struct/union) — compile error if applied to a struct or union
- Must have `#[derive(num_derive::ToPrimitive)]` — the generated code calls
  `::num::ToPrimitive::to_u32(self)`

**Tag derivation:** enum type name used as-is → `Tag::EnumName`.
Override: `#[ttlv(tag = "OtherTag")]` on the enum.

---

## 2. Generated Code

Given:

```rust
#[derive(TtlvEnumSerialize, num_derive::ToPrimitive)]
enum CryptographicAlgorithm {
    Aes = 3,
    TripleDes = 6,
}
```

Generates:

```rust
impl ::ttlv::__private::TtlvSerialize for CryptographicAlgorithm {
    fn serialize(
        &self,
        writer: &mut dyn ::ttlv::__private::EncodedWriter,
    ) -> ::core::result::Result<(), ::ttlv::__private::TTLVError> {
        let v = ::num::ToPrimitive::to_u32(self)
            .ok_or(::ttlv::__private::TTLVError::EnumConvertFailed {
                tag: ::ttlv::__private::Tag::CryptographicAlgorithm,
            })?;
        ::ttlv::__private::ser_write_enumeration(
            writer,
            ::ttlv::__private::Tag::CryptographicAlgorithm,
            v,
        )
    }
}
```

---

## 3. Required Changes

### `ttlv/src/error.rs`

Add one variant to `TTLVError`:

```rust
#[error("enum variant for tag {:?} cannot be converted to u32", tag)]
EnumConvertFailed { tag: Tag },
```

### `ttlv/src/lib.rs` — `__private` module

Expose `ToPrimitive` for use in generated code:

```rust
pub use ::num::ToPrimitive;
```

### `ttlv/src/lib.rs` — public re-exports

```rust
pub use ttlv_derive::TtlvEnumSerialize;
```

### `ttlv_derive/Cargo.toml`

No changes needed. `num-traits` (which provides `ToPrimitive`) is already a transitive dependency
via `num_derive` used elsewhere in the crate.

### `ttlv_derive/src/lib.rs`

New entry point alongside the existing three:

```rust
#[proc_macro_derive(TtlvEnumSerialize, attributes(ttlv))]
pub fn derive_ttlv_enum_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    enum_serialize_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}
```

`enum_serialize_impl` reuses the existing `struct_tag_tokens` and `find_ttlv_tag_attr` helpers
(no duplication). It guards that the input is `Data::Enum`, returning a `syn::Error` compile
error otherwise.

**No changes** to the `TtlvSerialize` struct macro, `EncodedWriter` trait, `ser.rs` helpers,
`TtlvDeserialize`, or `TtlvEnumDeserialize`.

---

## 4. Composing with the Struct Macro

A struct field of an enum type requires no annotation:

```rust
#[derive(TtlvDeserialize, TtlvSerialize)]
struct KeyBlock {
    cryptographic_algorithm: CryptographicAlgorithm,  // nested-T fallthrough
    cryptographic_length: i32,
}
```

The field name `cryptographic_algorithm` → `Tag::CryptographicAlgorithm` in the struct macro,
and `CryptographicAlgorithm::serialize` also writes `Tag::CryptographicAlgorithm`. Both agree
by KMIP naming convention. The struct serializer's existing "nested T" fallthrough
(`TtlvSerialize::serialize(value, writer)?`) handles enum fields with no modifications.

---

## 5. Testing

Added to `ttlv/tests/derive_tests.rs`:

| Test | What it checks |
|---|---|
| `test_enum_serialize_known_bytes` | Serialized bytes for a variant match expected TTLV binary |
| `test_enum_serialize_round_trip` | Serialize then deserialize (via `TtlvEnumDeserialize`) returns original variant |
| `test_enum_serialize_in_struct` | A `#[derive(TtlvSerialize)]` struct with an enum field serializes correctly end-to-end |
| `test_enum_serialize_tag_override` | `#[ttlv(tag = "OtherTag")]` on the enum uses the overridden tag |

`test_enum_serialize_round_trip` depends on `TtlvEnumDeserialize` being implemented. If that
has not yet landed, mark it `#[ignore]` until it does.

---

## Out of Scope

- Enum variants with associated data (only unit variants are supported)
- Enums without `num_derive::ToPrimitive`
- Passing the tag from the parent struct field (enum always owns its tag)
- `TtlvDeserialize` for enum types (covered by `TtlvEnumDeserialize`)
