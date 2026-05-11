# XML Reader Design for ttlv Crate

**Date:** 2026-05-11
**Goal:** Add an `XmlReader` to the `ttlv` crate that reads KMIP XML (e.g., `MSGENC-HTTPS-M-1-14.xml`) and produces a stream of `kmip_enums::Value`, mirroring the binary `Reader` in `ttlv/src/de.rs`.

---

## 1. Scope

Three files change:

| File | Change |
|---|---|
| `ttlv/src/de_xml.rs` | New file — all XML reading logic |
| `ttlv/src/lib.rs` | Add `pub mod de_xml;` |
| `ttlv/src/error.rs` | Add one new `TTLVError` variant |

Public surface of `de_xml.rs`:
- `EnumResolver` trait
- `XmlReader<'a>` struct — `new(buf, resolver)` + `read() -> Option<TTLVResult<Value>>`
- `read_to_end(buf, resolver) -> TTLVResult<Vec<Value>>` free function

---

## 2. EnumResolver Trait

```rust
pub trait EnumResolver {
    fn resolve(&self, tag: Tag, value: &str) -> TTLVResult<u32>;
}
```

The ttlv crate defines the trait; callers (the `protocol` crate or tests) provide implementations. The resolver maps `(Tag, name_string)` to a raw KMIP enumeration `u32`, e.g. `(Tag::Operation, "Query") → 0x00000018`.

A new error variant is added to `TTLVError` in `error.rs`:

```rust
#[error("unresolved enumeration: tag {:?}, value {}", tag, value)]
UnresolvedEnumeration { tag: Tag, value: String },
```

Implementations that cannot resolve a given `(tag, value)` pair return this error.

---

## 3. XmlReader Struct

```rust
pub struct XmlReader<'a> {
    reader: EventReader<Cursor<&'a [u8]>>,
    struct_stack: Vec<(Tag, u64)>,   // (tag, depth-when-opened)
    depth: u64,
    enum_resolver: &'a dyn EnumResolver,
}

impl<'a> XmlReader<'a> {
    pub fn new(buf: &'a [u8], resolver: &'a dyn EnumResolver) -> Self { ... }
    pub fn read(&mut self) -> Option<TTLVResult<Value>> { ... }
}
```

Uses `xml-rs` (`xml::reader::EventReader`) already present in the crate's dependencies.

---

## 4. State Machine

### Depth tracking

`depth` starts at `0`. Every `StartElement` increments it; every `EndElement` decrements it. The `struct_stack` records `(tag, depth-at-open)` for every structure element entered.

**Distinguishing leaf vs. structure `EndElement`:**

- **Leaf end**: `struct_stack` is empty, or `depth > struct_stack.last().depth` — just decrement and continue the loop.
- **Structure end**: `depth == struct_stack.last().depth` — pop the stack, decrement, and emit `ValueType::StructureEnd`.

Example:

```
StartElement(RequestHeader)          depth 2→3  push (RequestHeader,3)  emit StructureBegin(0)
StartElement(BatchCount type=Integer) depth 3→4                          emit Integer(1)
EndElement(BatchCount)               4 ≠ 3  → leaf end  depth 4→3       continue
EndElement(RequestHeader)            3 == 3 → struct end  depth 3→2     emit StructureEnd
```

### KMIP root skip

When `StartElement` with `local_name == "KMIP"` is encountered, increment `depth` but do not push to `struct_stack` and do not emit any `Value`. Its `EndElement` falls through as a no-op (stack is empty at that depth).

---

## 5. Value Parsing

| XML `type` attribute | Parsing strategy |
|---|---|
| `Integer` | `value.parse::<i32>()` |
| `LongInteger` | `value.parse::<i64>()` |
| `Enumeration` | Starts with `0x`/`0X` → `u32::from_str_radix(hex, 16)`; otherwise → `enum_resolver.resolve(tag, value)` |
| `Boolean` | Case-insensitive `"true"` / `"false"` |
| `TextString` | value string as-is |
| `ByteString` | `hex::decode(value)` |
| `DateTime` | `"$NOW"` → `0i64` (sentinel); otherwise parse RFC3339 via chrono → `.timestamp()` |
| `Interval` | `value.parse::<u32>()` |
| `BigInteger` | Not in `ValueType` — return `TTLVError::XmlError` |

`StructureBegin` uses length `0`. XML has no byte lengths; consumers pattern-match on `StructureBegin(_)` and never inspect the length field for XML-sourced data.

---

## 6. Convenience Function

```rust
pub fn read_to_end(buf: &[u8], resolver: &dyn EnumResolver) -> TTLVResult<Vec<Value>> {
    let mut reader = XmlReader::new(buf, resolver);
    let mut values = Vec::new();
    loop {
        match reader.read() {
            None => return Ok(values),
            Some(Ok(v)) => values.push(v),
            Some(Err(e)) => return Err(e),
        }
    }
}
```

Mirrors the private `read_to_end` in `de.rs`.

---

## 7. Error Handling

All parse failures (unknown tag name, unknown type string, bad integer/hex/datetime format, unresolved enum) return `Err(TTLVError)`. The `xml-rs` reader errors map to `TTLVError::XmlError`.

---

## 8. Testing

A unit test in `de_xml.rs` reads the content of `MSGENC-HTTPS-M-1-14.xml` via `include_bytes!("../../MSGENC-HTTPS-M-1-14.xml")` through a minimal `EnumResolver` stub that returns `0` for all enumerations, and asserts that:

- The first token is `StructureBegin` with tag `RequestMessage`
- The stream contains the expected `StructureBegin`/`StructureEnd` pairs at the correct nesting depth
- Leaf values (integers, text strings, enumerations) match the expected values from the XML
- `$NOW` DateTime produces `ValueType::DateTime(0)`
