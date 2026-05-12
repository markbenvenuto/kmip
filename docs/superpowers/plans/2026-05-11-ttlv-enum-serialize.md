# TtlvEnumSerialize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `#[derive(TtlvEnumSerialize)]` proc macro that generates `impl TtlvSerialize for MyEnum` for KMIP enumeration types, enabling enum fields in `#[derive(TtlvSerialize)]` structs to work without any additional annotation.

**Architecture:** The macro lives in `ttlv_derive/src/lib.rs` alongside the three existing macros. It reuses the existing `struct_tag_tokens` helper to derive the TTLV tag from the enum type name (e.g. `CryptographicAlgorithm` → `Tag::CryptographicAlgorithm`), calls `num::ToPrimitive::to_u32(self)` to convert the variant to a wire value, and delegates to the existing `ser_write_enumeration` helper. The struct serializer's existing "nested T" fallthrough (`TtlvSerialize::serialize(value, writer)?`) then handles enum fields automatically with no struct-macro changes required.

**Tech Stack:** Rust proc macros (`syn 2`, `quote`, `proc-macro2`), `num` crate (`ToPrimitive`), `thiserror`

**Spec:** `docs/superpowers/specs/2026-05-11-ttlv-enum-serialize-design.md`

---

### File Map

| File | Change |
|---|---|
| `ttlv/src/error.rs` | Add `EnumConvertFailed` variant to `TTLVError` |
| `ttlv/src/lib.rs` | Expose `ToPrimitive` in `__private`; add `pub use ttlv_derive::TtlvEnumSerialize` |
| `ttlv_derive/src/lib.rs` | Add `derive_ttlv_enum_serialize` entry point + `enum_serialize_impl` function |
| `ttlv/tests/derive_tests.rs` | Add four tests for the new macro |

---

### Task 1: Add EnumConvertFailed error variant and expose ToPrimitive

**Files:**
- Modify: `ttlv/src/error.rs`
- Modify: `ttlv/src/lib.rs`

- [ ] **Step 1: Add `EnumConvertFailed` to `TTLVError` in `ttlv/src/error.rs`**

  At the end of the `TTLVError` enum, after the `XmlReadError` variant, add one new variant. The bottom of the enum should read:

  ```rust
      #[error("invalid xml read")]
      XmlReadError,

      #[error("enum variant for tag {:?} cannot be converted to u32", tag)]
      EnumConvertFailed { tag: Tag },
  }
  ```

- [ ] **Step 2: Verify compilation**

  ```bash
  cd /home/mark/projects/kmip && cargo build -p ttlv 2>&1 | tail -5
  ```

  Expected: `Finished` with no errors.

- [ ] **Step 3: Add `ToPrimitive` re-export to `__private` in `ttlv/src/lib.rs`**

  In the `__private` module, add one line after the existing `pub use crate::ser::{...}` block:

  ```rust
  #[doc(hidden)]
  pub mod __private {
      pub use crate::de::{
          Reader, TtlvDeserialize, expect_boolean, expect_byte_string, expect_datetime,
          expect_enumeration, expect_integer, expect_long_integer, expect_structure_begin,
          expect_structure_end, expect_text_string,
      };
      pub use crate::error::TTLVError;
      pub use crate::kmip_enums::Tag;
      pub use crate::ser::{
          EncodedWriter, TtlvSerialize,
          ser_write_boolean, ser_write_byte_string, ser_write_datetime,
          ser_write_enumeration, ser_write_integer, ser_write_long_integer,
          ser_write_structure_begin, ser_write_structure_end, ser_write_text_string,
      };
      pub use ::num::ToPrimitive;
  }
  ```

- [ ] **Step 4: Verify compilation**

  ```bash
  cd /home/mark/projects/kmip && cargo build -p ttlv 2>&1 | tail -5
  ```

  Expected: `Finished` with no errors.

- [ ] **Step 5: Commit**

  ```bash
  cd /home/mark/projects/kmip
  git add ttlv/src/error.rs ttlv/src/lib.rs
  git commit -m "Add EnumConvertFailed error variant and expose ToPrimitive in __private"
  ```

---

### Task 2: Implement TtlvEnumSerialize macro and tests

**Files:**
- Modify: `ttlv_derive/src/lib.rs`
- Modify: `ttlv/src/lib.rs`
- Modify: `ttlv/tests/derive_tests.rs`

- [ ] **Step 1: Write the failing tests in `ttlv/tests/derive_tests.rs`**

  Add the following at the end of the file. The tests will not compile until the macro is added in Step 2.

  ```rust
  // ── TtlvEnumSerialize tests ──────────────────────────────────────────────────

  #[derive(ttlv::TtlvEnumSerialize, num_derive::ToPrimitive, Debug, PartialEq, Clone, Copy)]
  enum CryptographicAlgorithm {
      Aes = 3,
      TripleDes = 6,
  }

  #[test]
  fn test_enum_serialize_known_bytes() {
      // CryptographicAlgorithm::Aes = 3, Tag::CryptographicAlgorithm = 0x420028
      // Expected wire format:
      //   tag:    0x42 0x00 0x28
      //   type:   0x05  (Enumeration)
      //   length: 0x00 0x00 0x00 0x04
      //   value:  0x00 0x00 0x00 0x03
      //   pad:    0x00 0x00 0x00 0x00
      let expected: &[u8] = &[
          0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
          0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ];
      let mut writer = NestedWriter::new();
      CryptographicAlgorithm::Aes.serialize(&mut writer).unwrap();
      assert_eq!(writer.get_vector(), expected);
  }

  #[derive(TtlvSerialize)]
  #[ttlv(tag = "BatchItem")]
  struct CryptoParamsSer {
      cryptographic_algorithm: CryptographicAlgorithm,
  }

  #[test]
  fn test_enum_serialize_in_struct() {
      // BatchItem (0x42000F) structure containing CryptographicAlgorithm::Aes
      // Structure header:  tag 0x42000F, type Structure (0x01), length 0x10 (16)
      // Enum field:        tag 0x420028, type Enum (0x05), length 4, value 3, pad 4
      let expected: &[u8] = &[
          0x42, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x10,
          0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
          0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ];
      let params = CryptoParamsSer {
          cryptographic_algorithm: CryptographicAlgorithm::Aes,
      };
      let mut writer = NestedWriter::new();
      params.serialize(&mut writer).unwrap();
      assert_eq!(writer.get_vector(), expected);
  }

  #[derive(ttlv::TtlvEnumSerialize, num_derive::ToPrimitive, Debug, PartialEq, Clone, Copy)]
  #[ttlv(tag = "BatchCount")]
  enum CryptoAlgorithmAlt {
      Aes = 3,
  }

  #[test]
  fn test_enum_serialize_tag_override() {
      // Same variant value (3) but Tag::BatchCount (0x42000D) used via #[ttlv(tag)]
      let expected: &[u8] = &[
          0x42, 0x00, 0x0D, 0x05, 0x00, 0x00, 0x00, 0x04,
          0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ];
      let mut writer = NestedWriter::new();
      CryptoAlgorithmAlt::Aes.serialize(&mut writer).unwrap();
      assert_eq!(writer.get_vector(), expected);
  }

  // test_enum_serialize_round_trip: skipped until TtlvEnumDeserialize is implemented
  ```

- [ ] **Step 2: Verify that tests fail to compile (macro not yet defined)**

  ```bash
  cd /home/mark/projects/kmip && cargo test -p ttlv test_enum_serialize 2>&1 | grep -E "error|cannot find" | head -5
  ```

  Expected: error like `error[E0433]: failed to resolve: could not find 'TtlvEnumSerialize' in 'ttlv'`.

- [ ] **Step 3: Add the `derive_ttlv_enum_serialize` entry point to `ttlv_derive/src/lib.rs`**

  After the existing `derive_ttlv_deserialize` function (after line ~19), add the new entry point:

  ```rust
  #[proc_macro_derive(TtlvEnumSerialize, attributes(ttlv))]
  pub fn derive_ttlv_enum_serialize(input: TokenStream) -> TokenStream {
      let input = parse_macro_input!(input as DeriveInput);
      enum_serialize_impl(input).unwrap_or_else(|e| e.to_compile_error().into())
  }
  ```

- [ ] **Step 4: Add the `enum_serialize_impl` function to `ttlv_derive/src/lib.rs`**

  Add this function after the `serialize_impl` function (at the end of the file, before or after the helper functions — it doesn't matter):

  ```rust
  // ── TtlvEnumSerialize implementation ─────────────────────────────────────────

  fn enum_serialize_impl(input: DeriveInput) -> syn::Result<TokenStream> {
      let name = &input.ident;

      match &input.data {
          Data::Enum(_) => {}
          _ => {
              return Err(syn::Error::new_spanned(
                  name,
                  "TtlvEnumSerialize can only be derived for enums",
              ));
          }
      }

      let enum_tag = struct_tag_tokens(&input)?;

      let expanded = quote! {
          impl ::ttlv::__private::TtlvSerialize for #name {
              fn serialize(
                  &self,
                  writer: &mut dyn ::ttlv::__private::EncodedWriter,
              ) -> ::core::result::Result<(), ::ttlv::__private::TTLVError> {
                  let v = ::ttlv::__private::ToPrimitive::to_u32(self)
                      .ok_or(::ttlv::__private::TTLVError::EnumConvertFailed {
                          tag: #enum_tag,
                      })?;
                  ::ttlv::__private::ser_write_enumeration(writer, #enum_tag, v)
              }
          }
      };

      Ok(expanded.into())
  }
  ```

- [ ] **Step 5: Add `pub use ttlv_derive::TtlvEnumSerialize` to `ttlv/src/lib.rs`**

  After the existing `pub use ttlv_derive::TtlvSerialize;` line, add:

  ```rust
  pub use ttlv_derive::TtlvEnumSerialize;
  ```

- [ ] **Step 6: Run all tests and verify they pass**

  ```bash
  cd /home/mark/projects/kmip && cargo test -p ttlv 2>&1 | tail -20
  ```

  Expected: all existing tests pass plus the three new ones:
  ```
  test test_enum_serialize_known_bytes ... ok
  test test_enum_serialize_in_struct ... ok
  test test_enum_serialize_tag_override ... ok
  ```

- [ ] **Step 7: Commit**

  ```bash
  cd /home/mark/projects/kmip
  git add ttlv_derive/src/lib.rs ttlv/src/lib.rs ttlv/tests/derive_tests.rs
  git commit -m "Implement TtlvEnumSerialize derive macro"
  ```
