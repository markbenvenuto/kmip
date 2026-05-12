# Reader Trait + TtlvReader Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the concrete `Reader<'a>` struct to `TtlvReader<'a>`, introduce a `Reader` trait with `read()` and `peek_tag()`, implement it on both `TtlvReader` and `XmlReader`, and update all call sites so every function that accepts a reader uses `&mut dyn Reader`.

**Architecture:** The `Reader` trait lives in `ttlv/src/de.rs` alongside `TtlvReader`. `XmlReader` in `de_xml.rs` gets a `peeked` field and implements the trait. `TtlvDeserialize::parse` and all `parser.rs` helpers accept `&mut dyn Reader`. Derive macro generated code is updated to match.

**Tech Stack:** Rust, ttlv/ttlv_derive workspace crates.

---

### Task 1: Update `ttlv/src/de.rs` — rename struct, add trait, impl

**Files:**
- Modify: `ttlv/src/de.rs:17-19` (TtlvDeserialize trait)
- Modify: `ttlv/src/de.rs:436-503` (Reader struct and impl)

- [ ] **Step 1: Verify the baseline passes**

```bash
cargo test -p ttlv
```
Expected: all tests pass.

- [ ] **Step 2: Add the `Reader` trait and rename the struct**

Replace the `TtlvDeserialize` trait and the `Reader` struct/impl block (lines 17–503 of `de.rs`) with the following. The `read_inner` body is unchanged — only the struct name and the method organisation change.

```rust
pub trait Reader {
    fn read(&mut self) -> Option<TTLVResult<Value>>;
    fn peek_tag(&mut self) -> Option<Tag>;
}

pub trait TtlvDeserialize: Sized {
    fn parse(reader: &mut dyn Reader) -> TTLVResult<Self>;
}
```

Then rename the struct and split its impl:

```rust
pub struct TtlvReader<'a> {
    len: u64,
    cur: Cursor<&'a [u8]>,
    end_positions: Vec<(Tag, u64)>,
    peeked: Option<TTLVResult<Value>>,
}

impl<'a> TtlvReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            len: buf.len() as u64,
            cur: Cursor::new(buf),
            end_positions: Vec::new(),
            peeked: None,
        }
    }

    fn read_inner(&mut self) -> Option<TTLVResult<Value>> {
        let position = self.cur.position();

        if !self.end_positions.is_empty()
            && self.end_positions[self.end_positions.len() - 1].1 == position
        {
            let end = self.end_positions[self.end_positions.len() - 1];
            self.end_positions.pop();

            return Some(Ok(Value {
                tag: end.0,
                value: ValueType::StructureEnd,
            }));
        }

        if position == self.len {
            return None;
        }

        let value = read_value(&mut self.cur);
        match value {
            Err(_) => Some(value),
            Ok(x) => {
                if let ValueType::StructureBegin(struct_length) = x.value {
                    let position = self.cur.position();
                    self.end_positions
                        .push((x.tag, position + struct_length as u64));
                };

                Some(Ok(x))
            }
        }
    }
}

impl<'a> Reader for TtlvReader<'a> {
    fn read(&mut self) -> Option<TTLVResult<Value>> {
        if self.peeked.is_some() {
            return self.peeked.take();
        }
        self.read_inner()
    }

    fn peek_tag(&mut self) -> Option<Tag> {
        if self.peeked.is_none() {
            self.peeked = self.read_inner();
        }
        self.peeked.as_ref()?.as_ref().ok().map(|v| v.tag)
    }
}
```

- [ ] **Step 3: Update the internal `read_to_end` helper and the test module imports/signatures**

In the (non-test) `read_to_end` function around line 505, change:
```rust
// before
let mut reader = Reader::new(buf);
// after
let mut reader = TtlvReader::new(buf);
```

In the `#[cfg(test)]` module, update the `use` line:
```rust
// before
de::{Reader, read_to_end, to_print},
// after
de::{TtlvReader, Reader, read_to_end, to_print},
```

Update the two helper function signatures inside the test module:
```rust
// before
fn parse_request_header(reader: &mut Reader<'_>) -> Result<RequestHeader, TTLVError> {
fn parse_request_message(reader: &mut Reader<'_>) -> Result<RequestMessage, TTLVError> {
// after
fn parse_request_header(reader: &mut dyn Reader) -> Result<RequestHeader, TTLVError> {
fn parse_request_message(reader: &mut dyn Reader) -> Result<RequestMessage, TTLVError> {
```

Update the one `Reader::new` call in the test body (around line 881):
```rust
// before
let mut reader = Reader::new(&bytes);
// after
let mut reader = TtlvReader::new(&bytes);
```

- [ ] **Step 4: Check the ttlv crate compiles (errors expected from dependent code, but de.rs itself must be clean)**

```bash
cargo check -p ttlv 2>&1 | head -40
```
Expected: errors in `parser.rs`, `lib.rs`, `de_xml.rs` but NOT in `de.rs` itself.

---

### Task 2: Update `ttlv/src/de_xml.rs` — add peeked field, implement Reader trait

**Files:**
- Modify: `ttlv/src/de_xml.rs:1-30` (imports and struct definition)
- Modify: `ttlv/src/de_xml.rs:22-107` (impl block)

- [ ] **Step 1: Add the `Reader` import at the top of `de_xml.rs`**

After the existing `use crate::error::TTLVError;` line, add:
```rust
use crate::de::Reader;
```

- [ ] **Step 2: Add the `peeked` field to `XmlReader`**

```rust
// before
pub struct XmlReader<'a> {
    reader: EventReader<Cursor<&'a [u8]>>,
    struct_stack: Vec<(Tag, u64)>,
    depth: u64,
    enum_resolver: &'a dyn EnumResolver,
}
// after
pub struct XmlReader<'a> {
    reader: EventReader<Cursor<&'a [u8]>>,
    struct_stack: Vec<(Tag, u64)>,
    depth: u64,
    enum_resolver: &'a dyn EnumResolver,
    peeked: Option<TTLVResult<Value>>,
}
```

- [ ] **Step 3: Initialise `peeked` in `XmlReader::new`**

```rust
// before
pub fn new(buf: &'a [u8], resolver: &'a dyn EnumResolver) -> Self {
    Self {
        reader: EventReader::new(Cursor::new(buf)),
        struct_stack: Vec::new(),
        depth: 0,
        enum_resolver: resolver,
    }
}
// after
pub fn new(buf: &'a [u8], resolver: &'a dyn EnumResolver) -> Self {
    Self {
        reader: EventReader::new(Cursor::new(buf)),
        struct_stack: Vec::new(),
        depth: 0,
        enum_resolver: resolver,
        peeked: None,
    }
}
```

- [ ] **Step 4: Rename `pub fn read` to `fn read_inner` in the `XmlReader` inherent impl**

```rust
// before
pub fn read(&mut self) -> Option<TTLVResult<Value>> {
// after
fn read_inner(&mut self) -> Option<TTLVResult<Value>> {
```

- [ ] **Step 5: Add the `Reader` trait impl for `XmlReader`**

Add this block after the closing `}` of `impl<'a> XmlReader<'a>`:

```rust
impl<'a> Reader for XmlReader<'a> {
    fn read(&mut self) -> Option<TTLVResult<Value>> {
        if self.peeked.is_some() {
            return self.peeked.take();
        }
        self.read_inner()
    }

    fn peek_tag(&mut self) -> Option<Tag> {
        if self.peeked.is_none() {
            self.peeked = self.read_inner();
        }
        self.peeked.as_ref()?.as_ref().ok().map(|v| v.tag)
    }
}
```

- [ ] **Step 6: Add `Reader` import to the test module inside `de_xml.rs`**

The test module already has `use super::*;`. Add below it:
```rust
use crate::de::Reader;
```

- [ ] **Step 7: Check `de_xml.rs` compiles cleanly**

```bash
cargo check -p ttlv 2>&1 | grep "de_xml"
```
Expected: no errors mentioning `de_xml.rs`.

---

### Task 3: Update `ttlv/src/parser.rs` — 9 function signatures

**Files:**
- Modify: `ttlv/src/parser.rs` (all 9 `expect_*` functions)

- [ ] **Step 1: Update all 9 function signatures**

Change every occurrence of `reader: &mut Reader<'_>` to `reader: &mut dyn Reader` in `parser.rs`. There are exactly 9 functions to update:

```rust
// before (same pattern for all 9)
pub fn expect_structure_begin(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<()> {
pub fn expect_structure_end(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<()> {
pub fn expect_integer(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<i32> {
pub fn expect_text_string(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<String> {
pub fn expect_long_integer(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<i64> {
pub fn expect_boolean(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<bool> {
pub fn expect_byte_string(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<Vec<u8>> {
pub fn expect_enumeration(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<u32> {
pub fn expect_datetime(reader: &mut Reader<'_>, expected_tag: Tag) -> TTLVResult<DateTime<Utc>> {

// after (same pattern for all 9)
pub fn expect_structure_begin(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<()> {
pub fn expect_structure_end(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<()> {
pub fn expect_integer(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<i32> {
pub fn expect_text_string(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<String> {
pub fn expect_long_integer(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<i64> {
pub fn expect_boolean(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<bool> {
pub fn expect_byte_string(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<Vec<u8>> {
pub fn expect_enumeration(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<u32> {
pub fn expect_datetime(reader: &mut dyn Reader, expected_tag: Tag) -> TTLVResult<DateTime<Utc>> {
```

Also update the `use crate::Reader;` import at the top of `parser.rs` — it still points to the right name since `Reader` is now the trait, but verify the import is still present.

- [ ] **Step 2: Check `parser.rs` compiles**

```bash
cargo check -p ttlv 2>&1 | grep "parser"
```
Expected: no errors mentioning `parser.rs`.

---

### Task 4: Update `ttlv/src/lib.rs` — re-exports and `from_bytes`

**Files:**
- Modify: `ttlv/src/lib.rs:12` (pub use)
- Modify: `ttlv/src/lib.rs:31` (__private module)
- Modify: `ttlv/src/lib.rs:55` (from_bytes body)

- [ ] **Step 1: Add `TtlvReader` to the public re-export**

```rust
// before
pub use de::{Reader, TtlvDeserialize};
// after
pub use de::{Reader, TtlvDeserialize, TtlvReader};
```

- [ ] **Step 2: The `__private` module re-export is already correct** — `pub use crate::de::{Reader, TtlvDeserialize}` will now export the trait. No change needed.

- [ ] **Step 3: Update `from_bytes` to use `TtlvReader::new`**

```rust
// before
pub fn from_bytes<T: TtlvDeserialize>(buf: &[u8]) -> Result<T, TTLVError> {
    let mut reader = Reader::new(&buf);
    T::parse(&mut reader)
}
// after
pub fn from_bytes<T: TtlvDeserialize>(buf: &[u8]) -> Result<T, TTLVError> {
    let mut reader = TtlvReader::new(buf);
    T::parse(&mut reader)
}
```

- [ ] **Step 4: Check ttlv crate compiles cleanly**

```bash
cargo check -p ttlv
```
Expected: no errors in the `ttlv` crate (errors may still exist in `ttlv_derive` consumers and `protocol`).

---

### Task 5: Update `ttlv_derive/src/lib.rs` — generated parse signatures

**Files:**
- Modify: `ttlv_derive/src/lib.rs:50`, `178`, `329`

There are exactly 3 occurrences of `reader: &mut ::ttlv::__private::Reader<'_>` in the derive macro. All become `reader: &mut dyn ::ttlv::__private::Reader`.

- [ ] **Step 1: Update occurrence at line 50 (inside `derive_enum_impl`)**

```rust
// before
fn parse(reader: &mut ::ttlv::__private::Reader<'_>) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
// after
fn parse(reader: &mut dyn ::ttlv::__private::Reader) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
```

- [ ] **Step 2: Update occurrence at line 178 (inside `derive_tagged_enum_impl`, multi-line form)**

```rust
// before
fn parse(
    reader: &mut ::ttlv::__private::Reader<'_>,
) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
// after
fn parse(
    reader: &mut dyn ::ttlv::__private::Reader,
) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
```

- [ ] **Step 3: Update occurrence at line 329 (inside `derive_impl`)**

```rust
// before
fn parse(reader: &mut ::ttlv::__private::Reader<'_>) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
// after
fn parse(reader: &mut dyn ::ttlv::__private::Reader) -> ::core::result::Result<Self, ::ttlv::__private::TTLVError> {
```

- [ ] **Step 4: Check the derive crate and its dependents compile**

```bash
cargo check -p ttlv_derive && cargo check -p protocol
```
Expected: clean for both.

---

### Task 6: Update `ttlv/tests/derive_tests.rs` and remove unused import in `protocol`

**Files:**
- Modify: `ttlv/tests/derive_tests.rs:2`
- Modify: `ttlv/tests/derive_tests.rs` (all `Reader::new` calls)
- Modify: `protocol/src/lib.rs:13`

- [ ] **Step 1: Update the import line in `derive_tests.rs`**

```rust
// before
use ttlv::{NestedWriter, Reader, Tag, TtlvDeserialize, TtlvEnumDeserialize, TtlvEnumSerialize, TtlvSerialize, TtlvTaggedEnumDeserialize, TtlvTaggedEnumSerialize, TTLVError};
// after
use ttlv::{NestedWriter, TtlvReader, Tag, TtlvDeserialize, TtlvEnumDeserialize, TtlvEnumSerialize, TtlvSerialize, TtlvTaggedEnumDeserialize, TtlvTaggedEnumSerialize, TTLVError};
```

- [ ] **Step 2: Replace all `Reader::new(` with `TtlvReader::new(` in `derive_tests.rs`**

There are ~28 occurrences. Use a global search-and-replace: every `Reader::new(` → `TtlvReader::new(`. The test file has no other uses of the name `Reader`.

- [ ] **Step 3: Remove the unused import in `protocol/src/lib.rs`**

```rust
// before (line 13)
use ttlv::Reader;
// after — delete the line entirely
```

- [ ] **Step 4: Check everything compiles**

```bash
cargo check --workspace
```
Expected: zero errors.

---

### Task 7: Run full test suite and commit

**Files:** none modified

- [ ] **Step 1: Run the full test suite**

```bash
cargo test --workspace
```
Expected: all tests pass, zero failures.

- [ ] **Step 2: Commit**

```bash
git add ttlv/src/de.rs ttlv/src/de_xml.rs ttlv/src/parser.rs ttlv/src/lib.rs \
        ttlv_derive/src/lib.rs ttlv/tests/derive_tests.rs protocol/src/lib.rs
git commit -m "refactor(ttlv): rename Reader struct to TtlvReader, introduce Reader trait"
```
