# Design: `Reader` Trait + `TtlvReader` Rename

**Date:** 2026-05-12
**Branch:** no_serde

## Goal

Introduce a `Reader` trait so that both `TtlvReader` (binary TTLV) and `XmlReader` (XML TTLV) are interchangeable wherever deserialization happens. The concrete binary reader struct is renamed from `Reader` to `TtlvReader` to free up the name for the trait.

## Trait Definition

In `ttlv/src/de.rs`, add an object-safe trait (no lifetime parameter — the lifetime is an impl detail of the concrete structs):

```rust
pub trait Reader {
    fn read(&mut self) -> Option<TTLVResult<Value>>;
    fn peek_tag(&mut self) -> Option<Tag>;
}
```

## Changes by File

### `ttlv/src/de.rs`
- Rename `pub struct Reader<'a>` → `pub struct TtlvReader<'a>` (update all internal uses)
- Add the `Reader` trait (above)
- Add `impl<'a> Reader for TtlvReader<'a>` (delegates to the existing method bodies)
- Change `TtlvDeserialize::parse` signature: `fn parse(reader: &mut dyn Reader) -> TTLVResult<Self>`

### `ttlv/src/de_xml.rs`
- Add `peeked: Option<TTLVResult<Value>>` field to `XmlReader<'a>`
- Implement `peek_tag()`: store the next `read()` result in `peeked`, return the tag if `Some(Ok(v))`; return `None` on EOF or error
- Add `impl<'a> Reader for XmlReader<'a>`

### `ttlv/src/parser.rs`
- All 8 `expect_*` helper functions: change parameter from `reader: &mut Reader<'_>` to `reader: &mut dyn Reader`

### `ttlv/src/lib.rs`
- `pub use de::{Reader, TtlvDeserialize}` — `Reader` now re-exports the trait
- Add `TtlvReader` to the public re-exports
- `__private` module: update `pub use crate::de::{Reader, TtlvDeserialize}` — `Reader` is the trait
- `from_bytes`: change `Reader::new(buf)` → `TtlvReader::new(buf)`

### `ttlv_derive/src/lib.rs`
- All generated `fn parse` signatures: `reader: &mut ::ttlv::__private::Reader<'_>` → `reader: &mut dyn ::ttlv::__private::Reader`
- Generated call sites (`reader.read()`, `reader.peek_tag()`) are unchanged

### `ttlv/tests/derive_tests.rs`
- All `Reader::new(...)` → `TtlvReader::new(...)`
- Update `use ttlv::{..., Reader, ...}` to import `TtlvReader` instead (or both if the trait is also needed)

### `protocol/src/lib.rs`
- Remove `use ttlv::Reader` (unused after derive macros no longer require it in scope)

## Edge Cases

- `XmlReader::peek_tag()` must return `None` on EOF (when `read()` returns `None`), matching `TtlvReader` behavior
- The `Reader` trait is object-safe: no generics, no associated types, all methods take `&mut self`

## Testing

No new tests required. The existing suite in `ttlv/tests/derive_tests.rs` and `ttlv/src/de.rs` covers all read paths and confirms correctness after the rename. `cargo test --workspace` must pass.
