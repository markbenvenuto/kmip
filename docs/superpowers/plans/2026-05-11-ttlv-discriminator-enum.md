# TtlvTaggedEnumDeserialize `discriminator_enum` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `#[ttlv(discriminator_enum = "TypeName")]` enum-level attribute to `TtlvTaggedEnumDeserialize` so that per-variant `#[ttlv(discriminator = ...)]` annotations can be auto-derived from the variant name, enabling `RequestBatchItem` to use `Operation` as its discriminator without boilerplate.

**Architecture:** The proc-macro reads the new `discriminator_enum` string attribute from the enum, threads the resulting `syn::Ident` into `variant_match_arm`, and uses it as a fallback when a variant has no explicit `discriminator` annotation. Existing per-variant annotations take priority; absence of both is a compile error.

**Tech Stack:** Rust proc-macros (`syn`, `quote`, `proc_macro2`)

---

## File Map

| File | Change |
|------|--------|
| `ttlv_derive/src/lib.rs` | Parse `discriminator_enum`; update `variant_match_arm` signature and resolution logic |
| `ttlv/tests/derive_tests.rs` | New integration tests for auto-derive and explicit-override paths |
| `protocol/src/lib.rs` | Add `TtlvTaggedEnumDeserialize` derive + `ttlv` attrs to `RequestBatchItem` |

---

### Task 1: Write failing integration tests

**Files:**
- Modify: `ttlv/tests/derive_tests.rs`

- [ ] **Step 1: Add test types after the existing `TtlvTaggedEnumDeserialize` section (after line 304)**

Append to `ttlv/tests/derive_tests.rs`:

```rust
// ── TtlvTaggedEnumDeserialize: discriminator_enum auto-derive ─────────────────

#[repr(i32)]
enum TestOp {
    Alpha = 1,
    Beta = 2,
    Gamma = 3,
}

#[derive(TtlvDeserialize, PartialEq, Debug)]
#[ttlv(tag = "RequestPayload")]
struct TestPayload {
    batch_count: i32,
}

#[derive(TtlvTaggedEnumDeserialize, PartialEq, Debug)]
#[ttlv(tag = "BatchItem")]
#[ttlv(discriminator_tag = "Operation")]
#[ttlv(discriminator_enum = "TestOp")]
enum TestItem {
    Alpha(TestPayload),               // auto-derive: TestOp::Alpha as u32 = 1
    Beta(TestPayload),                // auto-derive: TestOp::Beta as u32 = 2
    #[ttlv(discriminator = TestOp::Gamma)]
    Renamed(TestPayload),             // explicit override: TestOp::Gamma as u32 = 3
}

#[test]
fn test_discriminator_enum_auto_derive_alpha() {
    // BatchItem { Operation=1 (Alpha), RequestPayload { BatchCount=42 } }
    let bytes = [
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x28, // BatchItem struct, len=40
        0x42, 0x00, 0x5C, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, // Operation Enumeration = 1 (Alpha)
        0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x10, // RequestPayload struct, len=16
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00,
        0x00, 0x00, // BatchCount Integer = 42
    ];
    let mut reader = Reader::new(&bytes);
    let item = TestItem::parse(&mut reader).unwrap();
    assert_eq!(item, TestItem::Alpha(TestPayload { batch_count: 42 }));
}

#[test]
fn test_discriminator_enum_auto_derive_beta() {
    // BatchItem { Operation=2 (Beta), RequestPayload { BatchCount=7 } }
    let bytes = [
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x28, // BatchItem struct, len=40
        0x42, 0x00, 0x5C, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, // Operation Enumeration = 2 (Beta)
        0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x10, // RequestPayload struct, len=16
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
        0x00, 0x00, // BatchCount Integer = 7
    ];
    let mut reader = Reader::new(&bytes);
    let item = TestItem::parse(&mut reader).unwrap();
    assert_eq!(item, TestItem::Beta(TestPayload { batch_count: 7 }));
}

#[test]
fn test_discriminator_enum_explicit_override() {
    // BatchItem { Operation=3 (Gamma), RequestPayload { BatchCount=99 } }
    // Gamma maps to variant Renamed via explicit #[ttlv(discriminator = TestOp::Gamma)]
    let bytes = [
        0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x28, // BatchItem struct, len=40
        0x42, 0x00, 0x5C, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, // Operation Enumeration = 3 (Gamma)
        0x42, 0x00, 0x79, 0x01, 0x00, 0x00, 0x00, 0x10, // RequestPayload struct, len=16
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00,
        0x00, 0x00, // BatchCount Integer = 99
    ];
    let mut reader = Reader::new(&bytes);
    let item = TestItem::parse(&mut reader).unwrap();
    assert_eq!(item, TestItem::Renamed(TestPayload { batch_count: 99 }));
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cargo test -p ttlv test_discriminator_enum -- --nocapture 2>&1 | head -40
```

Expected: compile error — `TtlvTaggedEnumDeserialize` doesn't know `discriminator_enum` yet, OR runtime error if it compiles. Either form of failure is acceptable; we just need to confirm the tests don't accidentally pass.

---

### Task 2: Implement `discriminator_enum` in the proc-macro

**Files:**
- Modify: `ttlv_derive/src/lib.rs`

- [ ] **Step 1: Parse `discriminator_enum` in `derive_tagged_enum_impl`**

In `ttlv_derive/src/lib.rs`, replace the `match_arms` block in `derive_tagged_enum_impl` (lines 95–98):

```rust
    let match_arms: Vec<proc_macro2::TokenStream> = variants
        .iter()
        .map(variant_match_arm)
        .collect::<syn::Result<_>>()?;
```

with:

```rust
    let disc_enum_ident: Option<syn::Ident> =
        find_ttlv_str_attr(&input.attrs, "discriminator_enum")?
            .map(|s| syn::Ident::new(&s, name.span()));

    let match_arms: Vec<proc_macro2::TokenStream> = variants
        .iter()
        .map(|v| variant_match_arm(v, disc_enum_ident.as_ref()))
        .collect::<syn::Result<_>>()?;
```

- [ ] **Step 2: Update `variant_match_arm` signature and discriminator resolution**

Replace the entire `variant_match_arm` function (lines 125–158):

```rust
fn variant_match_arm(variant: &syn::Variant) -> syn::Result<proc_macro2::TokenStream> {
    let variant_name = &variant.ident;

    let inner_ty = match &variant.fields {
        syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0].ty,
        _ => {
            return Err(syn::Error::new_spanned(
                variant_name,
                "TtlvTaggedEnumDeserialize variants must have exactly one unnamed field",
            ));
        }
    };

    let disc_expr = find_ttlv_expr_attr(&variant.attrs, "discriminator")?.ok_or_else(|| {
        syn::Error::new_spanned(
            variant_name,
            "TtlvTaggedEnumDeserialize variants must have #[ttlv(discriminator = ...)]",
        )
    })?;

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

with:

```rust
fn variant_match_arm(
    variant: &syn::Variant,
    disc_enum_ident: Option<&syn::Ident>,
) -> syn::Result<proc_macro2::TokenStream> {
    let variant_name = &variant.ident;

    let inner_ty = match &variant.fields {
        syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0].ty,
        _ => {
            return Err(syn::Error::new_spanned(
                variant_name,
                "TtlvTaggedEnumDeserialize variants must have exactly one unnamed field",
            ));
        }
    };

    let disc_expr: proc_macro2::TokenStream =
        match find_ttlv_expr_attr(&variant.attrs, "discriminator")? {
            Some(expr) => quote! { #expr },
            None => match disc_enum_ident {
                Some(enum_ident) => quote! { #enum_ident::#variant_name },
                None => {
                    return Err(syn::Error::new_spanned(
                        variant_name,
                        "TtlvTaggedEnumDeserialize variants must have #[ttlv(discriminator = ...)] \
                         or the enum must have #[ttlv(discriminator_enum = \"...\")]",
                    ));
                }
            },
        };

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

- [ ] **Step 3: Run the new tests — expect them to pass**

```bash
cargo test -p ttlv test_discriminator_enum -- --nocapture
```

Expected output:
```
test test_discriminator_enum_auto_derive_alpha ... ok
test test_discriminator_enum_auto_derive_beta ... ok
test test_discriminator_enum_explicit_override ... ok
```

- [ ] **Step 4: Run the full ttlv test suite — no regressions**

```bash
cargo test -p ttlv -- --nocapture
```

Expected: all tests pass (existing `AttributesEnum`-style tests unaffected).

- [ ] **Step 5: Commit**

```bash
git add ttlv_derive/src/lib.rs ttlv/tests/derive_tests.rs
git commit -m "feat(ttlv_derive): add discriminator_enum auto-derive to TtlvTaggedEnumDeserialize"
```

---

### Task 3: Apply to `RequestBatchItem` in the protocol crate

**Files:**
- Modify: `protocol/src/lib.rs`

- [ ] **Step 1: Add `TtlvTaggedEnumDeserialize` to `RequestBatchItem`**

In `protocol/src/lib.rs`, replace lines 1253–1269:

```rust
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "BatchItem", tag = "Operation", content = "RequestPayload")]
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
    // Revoke(RevokeRequest),
    // TODO - add support for: Unique Batch Item ID, will require custom deserializer, serializer
}
```

with:

```rust
#[derive(Serialize, Deserialize, Debug, TtlvTaggedEnumDeserialize)]
#[serde(rename = "BatchItem", tag = "Operation", content = "RequestPayload")]
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
    // Revoke(RevokeRequest),
    // TODO - add support for: Unique Batch Item ID, will require custom deserializer, serializer
}
```

- [ ] **Step 2: Build the protocol crate**

```bash
cargo build -p protocol 2>&1
```

Expected: compiles with no errors. If `TtlvTaggedEnumDeserialize` is not in scope, confirm `use ttlv::TtlvTaggedEnumDeserialize;` is present at the top of `protocol/src/lib.rs` (it already is at line 26).

- [ ] **Step 3: Run the full workspace test suite**

```bash
cargo test --workspace 2>&1
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add protocol/src/lib.rs
git commit -m "feat(protocol): derive TtlvTaggedEnumDeserialize for RequestBatchItem"
```
