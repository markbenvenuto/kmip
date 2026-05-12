# TtlvTaggedEnumDeserialize: `discriminator_enum` Extension

**Date:** 2026-05-11  
**Status:** Approved

## Problem

`TtlvTaggedEnumDeserialize` currently requires every enum variant to carry an explicit `#[ttlv(discriminator = <expr>)]` annotation. For `RequestBatchItem`, this means 11 boilerplate annotations of the form `#[ttlv(discriminator = Operation::Create)]`, `#[ttlv(discriminator = Operation::Get)]`, etc.

The discriminator values come from the `Operation` enum, whose variant names match the `RequestBatchItem` variant names exactly. The annotation is redundant information.

## Goal

Allow the discriminator enum type to be specified once at the enum level. The macro then auto-derives `<EnumType>::<VariantName>` as the discriminator expression for each variant, with per-variant overrides still available when the names don't match.

## New Attribute

```
#[ttlv(discriminator_enum = "TypeName")]
```

Applied at the enum (not variant) level. `TypeName` must be a plain identifier (not a path like `crate::foo::TypeName`) for the discriminator enum type. The type must be in scope at the derive site.

## Attribute Parsing

In `derive_tagged_enum_impl` (`ttlv_derive/src/lib.rs`), after reading `disc_tag_str`:

```rust
let disc_enum_ident: Option<syn::Ident> =
    find_ttlv_str_attr(&input.attrs, "discriminator_enum")?
        .map(|s| syn::Ident::new(&s, name.span()));
```

`disc_enum_ident` is threaded into `variant_match_arm` as a new parameter.

## Discriminator Value Resolution (per variant)

Priority order in `variant_match_arm(variant, disc_enum_ident: Option<&syn::Ident>)`:

1. **Explicit override** — variant has `#[ttlv(discriminator = <expr>)]` → use as-is (current behavior unchanged)
2. **Auto-derive** — no per-variant annotation, `disc_enum_ident` is `Some(ident)` → generate `<ident>::<VariantName>` as the discriminator expression
3. **Error** — no per-variant annotation and `disc_enum_ident` is `None` → compile error (current behavior unchanged)

The generated match arm is identical in all cases:

```rust
d if d == (#disc_expr) as u32 => Self::#variant_name(#val_expr)
```

## Usage

### RequestBatchItem (new)

```rust
#[derive(TtlvTaggedEnumDeserialize)]
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
}
```

Wire format: `BatchItem` structure → `Operation` enumeration (discriminator) → `RequestPayload` structure (payload). All `*Request` types already have `#[ttlv(tag = "RequestPayload")]`.

### AttributesEnum (unchanged)

`AttributesEnum` uses per-variant `#[ttlv(discriminator = Tag::...)]` with no `discriminator_enum` attribute. All existing variants take the explicit-override path; no behavioral change.

## Testing

A new test in `ttlv/tests/derive_tests.rs`:

- Define a small test enum with `discriminator_enum = "SomeOp"` and at least two variants: one auto-derived, one with an explicit override
- Encode minimal TTLV wire bytes for each case
- Assert correct variant is returned for auto-derive path
- Assert correct variant is returned for override path

## Files Changed

| File | Change |
|------|--------|
| `ttlv_derive/src/lib.rs` | Add `discriminator_enum` parsing; thread `disc_enum_ident` into `variant_match_arm`; update resolver logic |
| `ttlv/tests/derive_tests.rs` | New integration tests for `discriminator_enum` |
| `protocol/src/lib.rs` | Add `TtlvTaggedEnumDeserialize` + `discriminator_enum` attrs to `RequestBatchItem` |
