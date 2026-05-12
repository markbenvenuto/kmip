# TtlvTaggedEnumDeserialize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `#[derive(TtlvTaggedEnumDeserialize)]` proc macro that generates `impl TtlvDeserialize` for enums whose variants are selected by reading an Enumeration discriminator field, then parsing the inner type.

**Architecture:** The macro reads an outer TTLV Structure, reads a discriminator Enumeration field whose tag is specified at enum level, matches the discriminator value against per-variant `#[ttlv(discriminator = expr)]` annotations, then parses the inner value using the same type-dispatch logic as the existing struct macro. Inner value tag is inferred from the variant name (PascalCase → `Tag::VariantName`).

**Tech Stack:** Rust, `syn 2`, `quote 1`, `proc-macro2 1`; existing helpers in `ttlv_derive/src/lib.rs`.

---

## File Map

| File | Change |
|---|---|
| `ttlv_derive/src/lib.rs` | Add `TtlvTaggedEnumDeserialize` entry point, `derive_tagged_enum_impl`, `variant_match_arm`; replace `find_ttlv_tag_attr` with `find_ttlv_str_attr(attrs, key)` + add `find_ttlv_expr_attr(attrs, key)` |
| `ttlv/src/lib.rs` | Export `TtlvTaggedEnumDeserialize` and `Tag` at top level |
| `ttlv/tests/derive_tests.rs` | Add `TestName`, `TestAttr`, `TestTemplate` and 5 new tests |
| `protocol/src/lib.rs` | Add `TtlvTaggedEnumDeserialize` derive + `#[ttlv(...)]` attrs to `AttributesEnum` |

---

## Task 1 — Refactor attribute-parsing helpers in `ttlv_derive/src/lib.rs`

**Files:**
- Modify: `ttlv_derive/src/lib.rs`

- [ ] **Step 1: Replace `find_ttlv_tag_attr` with `find_ttlv_str_attr` + add `find_ttlv_expr_attr`**

Replace the body of `find_ttlv_tag_attr` (currently lines 126–143) and add a new function after it:

```rust
fn find_ttlv_tag_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<String>> {
    find_ttlv_str_attr(attrs, "tag")
}

fn find_ttlv_str_attr(attrs: &[syn::Attribute], key: &str) -> syn::Result<Option<String>> {
    for attr in attrs {
        if !attr.path().is_ident("ttlv") {
            continue;
        }
        let nv: syn::MetaNameValue = attr.parse_args()?;
        if nv.path.is_ident(key) {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = nv.value
            {
                return Ok(Some(s.value()));
            }
        }
    }
    Ok(None)
}

fn find_ttlv_expr_attr(attrs: &[syn::Attribute], key: &str) -> syn::Result<Option<syn::Expr>> {
    for attr in attrs {
        if !attr.path().is_ident("ttlv") {
            continue;
        }
        let nv: syn::MetaNameValue = attr.parse_args()?;
        if nv.path.is_ident(key) {
            return Ok(Some(nv.value));
        }
    }
    Ok(None)
}
```

- [ ] **Step 2: Verify existing tests still pass**

```bash
cargo test -p ttlv
```

Expected: all 11 tests pass, 0 failed.

- [ ] **Step 3: Commit**

```bash
git add ttlv_derive/src/lib.rs
git commit -m "Generalise ttlv attr parser: find_ttlv_str_attr + find_ttlv_expr_attr"
```

---

## Task 2 — Implement the `TtlvTaggedEnumDeserialize` macro

**Files:**
- Modify: `ttlv_derive/src/lib.rs`

- [ ] **Step 1: Add the proc-macro entry point and `derive_tagged_enum_impl` after `derive_enum_impl`**

Insert after the closing `}` of `derive_enum_impl` (currently ends around line 58):

```rust
#[proc_macro_derive(TtlvTaggedEnumDeserialize, attributes(ttlv))]
pub fn derive_ttlv_tagged_enum_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_tagged_enum_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
}

fn derive_tagged_enum_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

    let variants = match &input.data {
        Data::Enum(e) => &e.variants,
        _ => return Err(syn::Error::new_spanned(
            name,
            "TtlvTaggedEnumDeserialize can only be derived for enums",
        )),
    };

    let struct_tag = struct_tag_tokens(&input)?;

    let disc_tag_str = find_ttlv_str_attr(&input.attrs, "discriminator_tag")?
        .ok_or_else(|| syn::Error::new_spanned(
            name,
            "TtlvTaggedEnumDeserialize requires #[ttlv(discriminator_tag = \"...\")]",
        ))?;
    let disc_tag_ident = syn::Ident::new(&disc_tag_str, name.span());
    let disc_tag = quote! { ::ttlv::__private::Tag::#disc_tag_ident };

    let match_arms: Vec<proc_macro2::TokenStream> = variants
        .iter()
        .map(variant_match_arm)
        .collect::<syn::Result<_>>()?;

    let expanded = quote! {
        impl ::ttlv::__private::TtlvDeserialize for #name {
            fn parse(
                reader: &mut ::ttlv::__private::Reader<'_>,
            ) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
                ::ttlv::__private::expect_structure_begin(reader, #struct_tag)?;
                let disc = ::ttlv::__private::expect_enumeration(reader, #disc_tag)?;
                let result = match disc {
                    #(#match_arms,)*
                    v => return ::core::result::Result::Err(
                        ::ttlv::__private::TTLVError::InvalidEnumValue {
                            tag: #disc_tag,
                            value: v,
                        }
                    ),
                };
                ::ttlv::__private::expect_structure_end(reader, #struct_tag)?;
                ::core::result::Result::Ok(result)
            }
        }
    };

    Ok(expanded.into())
}

fn variant_match_arm(variant: &syn::Variant) -> syn::Result<proc_macro2::TokenStream> {
    let variant_name = &variant.ident;

    let inner_ty = match &variant.fields {
        syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0].ty,
        _ => return Err(syn::Error::new_spanned(
            variant_name,
            "TtlvTaggedEnumDeserialize variants must have exactly one unnamed field",
        )),
    };

    let disc_expr = find_ttlv_expr_attr(&variant.attrs, "discriminator")?
        .ok_or_else(|| syn::Error::new_spanned(
            variant_name,
            "TtlvTaggedEnumDeserialize variants must have #[ttlv(discriminator = ...)]",
        ))?;

    let value_tag = if let Some(tag_str) = find_ttlv_str_attr(&variant.attrs, "value_tag")? {
        let ident = syn::Ident::new(&tag_str, variant_name.span());
        quote! { ::ttlv::__private::Tag::#ident }
    } else {
        let ident = syn::Ident::new(&variant_name.to_string(), variant_name.span());
        quote! { ::ttlv::__private::Tag::#ident }
    };

    let val_expr = value_expr(inner_ty, &value_tag)?;

    Ok(quote! {
        d if d == (#disc_expr) as u32 => Self::#variant_name(#val_expr)
    })
}
```

- [ ] **Step 2: Build to verify it compiles**

```bash
cargo build -p ttlv_derive
```

Expected: compiles with no errors (warnings about unused `derive_ttlv_tagged_enum_deserialize` are fine).

- [ ] **Step 3: Commit**

```bash
git add ttlv_derive/src/lib.rs
git commit -m "Add TtlvTaggedEnumDeserialize proc macro"
```

---

## Task 3 — Export `Tag` and `TtlvTaggedEnumDeserialize` from `ttlv/src/lib.rs`

**Files:**
- Modify: `ttlv/src/lib.rs`

- [ ] **Step 1: Add top-level exports**

The current content of `ttlv/src/lib.rs`:
```rust
mod de;
mod error;
mod kmip_enums;
mod ser;
mod ser_xml;

pub use de::{Reader, TtlvDeserialize};
pub use error::TTLVError;
pub use ttlv_derive::TtlvDeserialize;

#[doc(hidden)]
pub mod __private {
    pub use crate::de::{
        Reader, TtlvDeserialize, expect_boolean, expect_byte_string, expect_datetime,
        expect_enumeration, expect_integer, expect_long_integer,
        expect_structure_begin, expect_structure_end, expect_text_string,
    };
    pub use crate::error::TTLVError;
    pub use crate::kmip_enums::{Tag, ValueType};
}
```

Change the `pub use ttlv_derive::...` line and add `pub use kmip_enums::Tag`:

```rust
mod de;
mod error;
mod kmip_enums;
mod ser;
mod ser_xml;

pub use de::{Reader, TtlvDeserialize};
pub use error::TTLVError;
pub use kmip_enums::Tag;
pub use ttlv_derive::{TtlvDeserialize, TtlvEnumDeserialize, TtlvTaggedEnumDeserialize};

#[doc(hidden)]
pub mod __private {
    pub use crate::de::{
        Reader, TtlvDeserialize, expect_boolean, expect_byte_string, expect_datetime,
        expect_enumeration, expect_integer, expect_long_integer,
        expect_structure_begin, expect_structure_end, expect_text_string,
    };
    pub use crate::error::TTLVError;
    pub use crate::kmip_enums::{Tag, ValueType};
}
```

- [ ] **Step 2: Build to verify**

```bash
cargo build -p ttlv
```

Expected: compiles with no errors.

- [ ] **Step 3: Commit**

```bash
git add ttlv/src/lib.rs
git commit -m "Export Tag and TtlvTaggedEnumDeserialize from ttlv crate"
```

---

## Task 4 — Write integration tests

**Files:**
- Modify: `ttlv/tests/derive_tests.rs`

- [ ] **Step 1: Add imports and test types to the top of `derive_tests.rs`**

Change the existing `use ttlv::{...}` import line to:

```rust
use ttlv::{Reader, Tag, TtlvDeserialize, TtlvEnumDeserialize, TtlvTaggedEnumDeserialize, TTLVError};
```

Then add the following type definitions **after** the existing `CryptographicAlgorithm` enum definition (which currently has `Aes = 3, TripleDes = 6`):

```rust
// ── TtlvTaggedEnumDeserialize ─────────────────────────────────────────────────

#[derive(TtlvDeserialize, PartialEq, Debug)]
struct TestName {
    name_type: i32,     // Tag::NameType = 0x420054 — lower tag, must come first in TTLV
    name_value: String, // Tag::NameValue = 0x420055 — higher tag, comes second
}

#[derive(TtlvTaggedEnumDeserialize, PartialEq, Debug)]
#[ttlv(tag = "Attribute", discriminator_tag = "AttributeName")]
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
```

- [ ] **Step 2: Add 5 test functions at the end of the file**

```rust
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
    // Attribute { AttributeName=0x99999999 (unknown) }
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
```

- [ ] **Step 3: Run tests to verify all pass**

```bash
cargo test -p ttlv
```

Expected: 16 tests pass (11 existing + 5 new), 0 failed.

- [ ] **Step 4: Commit**

```bash
git add ttlv/tests/derive_tests.rs
git commit -m "Add TtlvTaggedEnumDeserialize integration tests"
```

---

## Task 5 — Apply `TtlvTaggedEnumDeserialize` to `AttributesEnum` in `protocol/src/lib.rs`

**Files:**
- Modify: `protocol/src/lib.rs`

- [ ] **Step 1: Add imports at the top of `protocol/src/lib.rs`**

Find the existing import lines (around lines 24–26):
```rust
use ttlv::TtlvEnumDeserialize;
use ttlv::kmip_enums::ItemType;
use ttlv_derive::TtlvDeserialize;
```

Add two lines:
```rust
use ttlv::TtlvEnumDeserialize;
use ttlv::TtlvTaggedEnumDeserialize;
use ttlv::Tag;
use ttlv::kmip_enums::ItemType;
use ttlv_derive::TtlvDeserialize;
```

- [ ] **Step 2: Annotate `AttributesEnum` (currently at line ~851)**

Replace the current definition:
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    rename = "Attribute",
    tag = "AttributeName",
    content = "AttributeValue"
)]
pub enum AttributesEnum {
    #[serde(rename = "Cryptographic Algorithm")]
    CryptographicAlgorithm(CryptographicAlgorithm),

    #[serde(rename = "Cryptographic Length")]
    CryptographicLength(i32),

    #[serde(rename = "Cryptographic Usage Mask")]
    CryptographicUsageMask(i32),

    #[serde(with = "my_date_format", rename = "Activation Date")]
    ActivationDate(DateTime<Utc>),

    #[serde(with = "my_date_format", rename = "Deactivation Date")]
    DeactivationDate(DateTime<Utc>),

    #[serde(rename = "Name")]
    Name(Name),

    #[serde(rename = "Cryptographic Parameters")]
    CryptographicParameters(CryptographicParameters),

    #[serde(rename = "State")]
    State(State),

    #[serde(with = "my_date_format", rename = "Initial Date")]
    InitialDate(DateTime<Utc>),

    #[serde(with = "my_date_format", rename = "Last Change Date")]
    LastChangeDate(DateTime<Utc>),

    #[serde(rename = "Object Type")]
    ObjectType(ObjectType),

    #[serde(rename = "Unique Identifier")]
    UniqueIdentifier(String),
}
```

With:
```rust
#[derive(Serialize, Deserialize, Debug, Clone, TtlvTaggedEnumDeserialize)]
#[serde(
    rename = "Attribute",
    tag = "AttributeName",
    content = "AttributeValue"
)]
#[ttlv(tag = "Attribute", discriminator_tag = "AttributeName")]
pub enum AttributesEnum {
    #[serde(rename = "Cryptographic Algorithm")]
    #[ttlv(discriminator = Tag::CryptographicAlgorithm)]
    CryptographicAlgorithm(CryptographicAlgorithm),

    #[serde(rename = "Cryptographic Length")]
    #[ttlv(discriminator = Tag::CryptographicLength)]
    CryptographicLength(i32),

    #[serde(rename = "Cryptographic Usage Mask")]
    #[ttlv(discriminator = Tag::CryptographicUsageMask)]
    CryptographicUsageMask(i32),

    #[serde(with = "my_date_format", rename = "Activation Date")]
    #[ttlv(discriminator = Tag::ActivationDate)]
    ActivationDate(DateTime<Utc>),

    #[serde(with = "my_date_format", rename = "Deactivation Date")]
    #[ttlv(discriminator = Tag::DeactivationDate)]
    DeactivationDate(DateTime<Utc>),

    #[serde(rename = "Name")]
    #[ttlv(discriminator = Tag::Name)]
    Name(Name),

    #[serde(rename = "Cryptographic Parameters")]
    #[ttlv(discriminator = Tag::CryptographicParameters)]
    CryptographicParameters(CryptographicParameters),

    #[serde(rename = "State")]
    #[ttlv(discriminator = Tag::State)]
    State(State),

    #[serde(with = "my_date_format", rename = "Initial Date")]
    #[ttlv(discriminator = Tag::InitialDate)]
    InitialDate(DateTime<Utc>),

    #[serde(with = "my_date_format", rename = "Last Change Date")]
    #[ttlv(discriminator = Tag::LastChangeDate)]
    LastChangeDate(DateTime<Utc>),

    #[serde(rename = "Object Type")]
    #[ttlv(discriminator = Tag::ObjectType)]
    ObjectType(ObjectType),

    #[serde(rename = "Unique Identifier")]
    #[ttlv(discriminator = Tag::UniqueIdentifier)]
    UniqueIdentifier(String),
}
```

- [ ] **Step 3: Build the protocol crate to verify no compile errors**

```bash
cargo build -p protocol
```

Expected: compiles (warnings about unused imports are fine; there must be no errors).

- [ ] **Step 4: Run all ttlv tests one more time to confirm nothing regressed**

```bash
cargo test -p ttlv
```

Expected: 16 tests pass, 0 failed.

- [ ] **Step 5: Commit**

```bash
git add protocol/src/lib.rs
git commit -m "Apply TtlvTaggedEnumDeserialize to AttributesEnum"
```

---

## Self-Review

**Spec coverage:**
- ✓ New `TtlvTaggedEnumDeserialize` macro (Task 2)
- ✓ `find_ttlv_str_attr` + `find_ttlv_expr_attr` helpers (Task 1)
- ✓ `Tag` exported at ttlv top level (Task 3)
- ✓ `TtlvTaggedEnumDeserialize` exported (Task 3)
- ✓ `Name` struct already has `TtlvDeserialize` (confirmed in codebase — no change needed)
- ✓ `AttributesEnum` annotated (Task 5)
- ✓ Primitive variant test (Task 4 — `test_tagged_enum_primitive_variant`)
- ✓ Enum variant test (Task 4 — `test_tagged_enum_enum_variant`)
- ✓ Struct variant test (Task 4 — `test_tagged_enum_struct_variant`)
- ✓ Unknown discriminator test (Task 4 — `test_tagged_enum_unknown_discriminator`)
- ✓ `Vec<TestAttr>` test (Task 4 — `test_tagged_enum_vec_field`)
