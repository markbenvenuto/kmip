# ConversationNormalizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `ConversationNormalizer` struct to `tests_e2e/src/test/util.rs` that resolves `$NOW`/`$UNIQUE_IDENTIFIER_N` placeholders and normalizes `DigestValue` fields, then wire it into `run_e2e_xml_conversation` and add two new e2e tests driven from the OASIS XML files.

**Architecture:** `ConversationNormalizer` owns a `HashMap<String, String>` variable map. Its `apply_to_request` method substitutes known variables before each request is sent; `apply_to_response` extracts new variable bindings from the actual response, applies them to the expected response, and normalizes `DigestValue` on both sides. Three private pure functions (`extract_variables`, `apply_var_substitution`, `normalize_digest_values`) do the actual work and are unit-tested in isolation.

**Tech Stack:** Rust, `regex` crate (new dep), `lazy_static` (already in workspace), `cargo test -p tests_e2e`

---

### Task 1: Add `regex` to workspace and `tests_e2e` dependencies

**Files:**
- Modify: `Cargo.toml` (workspace)
- Modify: `tests_e2e/Cargo.toml`

- [ ] **Step 1: Add regex to workspace dependencies**

In `/home/mark/projects/kmip/Cargo.toml`, add to the `[workspace.dependencies]` section (keep alphabetical order, add after `quick-xml`):

```toml
regex = "1"
```

- [ ] **Step 2: Add regex to tests_e2e dependencies**

In `/home/mark/projects/kmip/tests_e2e/Cargo.toml`, add to `[dependencies]` (keep alphabetical order):

```toml
regex = { workspace = true }
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo check -p tests_e2e
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml tests_e2e/Cargo.toml
git commit -m "Add regex dependency to tests_e2e"
```

---

### Task 2: Add `extract_variables` helper with unit tests (TDD)

**Files:**
- Modify: `tests_e2e/src/test/util.rs`

- [ ] **Step 1: Add imports to util.rs**

At the top of `tests_e2e/src/test/util.rs`, extend the existing `use std::` block and add new imports:

```rust
use std::{
    collections::HashMap,
    env,
    io::Cursor,
    net,
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Barrier, Mutex},
    thread,
};

use lazy_static::lazy_static;
use regex::Regex;
```

- [ ] **Step 2: Write the failing unit tests for `extract_variables`**

Add this `#[cfg(test)]` block at the very end of `tests_e2e/src/test/util.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_extract_timestamp() {
        let xml = r#"<TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>"#;
        let mut var_map = HashMap::new();
        extract_variables(xml, &mut var_map);
        assert_eq!(
            var_map.get("$NOW"),
            Some(&"1970-01-01T00:02:03+00:00".to_string())
        );
    }

    #[test]
    fn test_extract_unique_identifier() {
        let xml = r#"<UniqueIdentifier type="TextString" value="abc-123"/>"#;
        let mut var_map = HashMap::new();
        extract_variables(xml, &mut var_map);
        assert_eq!(
            var_map.get("$UNIQUE_IDENTIFIER_0"),
            Some(&"abc-123".to_string())
        );
    }

    #[test]
    fn test_extract_two_unique_identifiers() {
        let xml = r#"
            <UniqueIdentifier type="TextString" value="id-one"/>
            <UniqueIdentifier type="TextString" value="id-two"/>
        "#;
        let mut var_map = HashMap::new();
        extract_variables(xml, &mut var_map);
        assert_eq!(var_map.get("$UNIQUE_IDENTIFIER_0"), Some(&"id-one".to_string()));
        assert_eq!(var_map.get("$UNIQUE_IDENTIFIER_1"), Some(&"id-two".to_string()));
    }

    #[test]
    fn test_now_not_overwritten_on_second_call() {
        let xml = r#"<TimeStamp type="DateTime" value="second-value"/>"#;
        let mut var_map = HashMap::new();
        var_map.insert("$NOW".to_string(), "first-value".to_string());
        extract_variables(xml, &mut var_map);
        assert_eq!(var_map.get("$NOW"), Some(&"first-value".to_string()));
    }

    #[test]
    fn test_uid_not_added_twice_for_same_value() {
        let xml = r#"
            <UniqueIdentifier type="TextString" value="same-id"/>
            <UniqueIdentifier type="TextString" value="same-id"/>
        "#;
        let mut var_map = HashMap::new();
        extract_variables(xml, &mut var_map);
        assert_eq!(var_map.get("$UNIQUE_IDENTIFIER_0"), Some(&"same-id".to_string()));
        assert!(var_map.get("$UNIQUE_IDENTIFIER_1").is_none());
    }
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
cargo test -p tests_e2e test_extract 2>&1 | grep -E "error|FAILED|not found"
```

Expected: compile error — `extract_variables` not defined yet.

- [ ] **Step 4: Implement `extract_variables`**

Add before the `#[cfg(test)]` block in `tests_e2e/src/test/util.rs`:

```rust
fn extract_variables(xml: &str, var_map: &mut HashMap<String, String>) {
    lazy_static! {
        static ref TIMESTAMP_RE: Regex =
            Regex::new(r#"TimeStamp\s+type="DateTime"\s+value="([^"]*)""#).unwrap();
        static ref UID_RE: Regex =
            Regex::new(r#"UniqueIdentifier\s+type="TextString"\s+value="([^"]*)""#).unwrap();
    }

    if !var_map.contains_key("$NOW") {
        if let Some(caps) = TIMESTAMP_RE.captures(xml) {
            var_map.insert("$NOW".to_string(), caps[1].to_string());
        }
    }

    let mut counter = var_map
        .keys()
        .filter(|k| k.starts_with("$UNIQUE_IDENTIFIER_"))
        .count();

    for caps in UID_RE.captures_iter(xml) {
        let value = caps[1].to_string();
        // Check var_map.values() each iteration so insertions within this loop are visible
        if !var_map.values().any(|v| v == &value) {
            var_map.insert(format!("$UNIQUE_IDENTIFIER_{}", counter), value);
            counter += 1;
        }
    }
}
```

- [ ] **Step 5: Run tests and confirm they pass**

```bash
cargo test -p tests_e2e test_extract
```

Expected output: 5 tests pass, no failures.

- [ ] **Step 6: Commit**

```bash
git add tests_e2e/src/test/util.rs
git commit -m "Add extract_variables helper with unit tests"
```

---

### Task 3: Add `apply_var_substitution` helper with unit tests (TDD)

**Files:**
- Modify: `tests_e2e/src/test/util.rs`

- [ ] **Step 1: Write failing unit tests**

Inside the existing `mod tests` block in `tests_e2e/src/test/util.rs`, add:

```rust
    #[test]
    fn test_apply_var_substitution_replaces_all() {
        let mut var_map = HashMap::new();
        var_map.insert("$NOW".to_string(), "1970-01-01T00:02:03+00:00".to_string());
        var_map.insert("$UNIQUE_IDENTIFIER_0".to_string(), "abc-123".to_string());

        let xml = r#"<TimeStamp type="DateTime" value="$NOW"/><UniqueIdentifier type="TextString" value="$UNIQUE_IDENTIFIER_0"/>"#;
        let result = apply_var_substitution(xml, &var_map);

        assert!(result.contains(r#"value="1970-01-01T00:02:03+00:00""#));
        assert!(result.contains(r#"value="abc-123""#));
        assert!(!result.contains("$NOW"));
        assert!(!result.contains("$UNIQUE_IDENTIFIER_0"));
    }

    #[test]
    fn test_apply_var_substitution_empty_map_is_noop() {
        let var_map = HashMap::new();
        let xml = r#"<UniqueIdentifier type="TextString" value="$UNIQUE_IDENTIFIER_0"/>"#;
        let result = apply_var_substitution(xml, &var_map);
        assert_eq!(result, xml);
    }
```

- [ ] **Step 2: Run to confirm compile failure**

```bash
cargo test -p tests_e2e test_apply_var 2>&1 | grep -E "error|FAILED"
```

Expected: compile error — `apply_var_substitution` not defined.

- [ ] **Step 3: Implement `apply_var_substitution`**

Add after `extract_variables` in `tests_e2e/src/test/util.rs`:

```rust
fn apply_var_substitution(xml: &str, var_map: &HashMap<String, String>) -> String {
    let mut result = xml.to_string();
    for (var, value) in var_map {
        result = result.replace(var.as_str(), value.as_str());
    }
    result
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cargo test -p tests_e2e test_apply_var
```

Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests_e2e/src/test/util.rs
git commit -m "Add apply_var_substitution helper with unit tests"
```

---

### Task 4: Add `normalize_digest_values` helper with unit tests (TDD)

**Files:**
- Modify: `tests_e2e/src/test/util.rs`

- [ ] **Step 1: Write failing unit tests**

Inside the existing `mod tests` block, add:

```rust
    #[test]
    fn test_normalize_digest_values_replaces_hash() {
        let xml = r#"<DigestValue type="ByteString" value="bc12861408b8ac72cdb3b2748ad342b7dc519bd109046a1b931fdaed73591f29"/>"#;
        let result = normalize_digest_values(xml);
        assert_eq!(
            result,
            r#"<DigestValue type="ByteString" value="NORMALIZED_FOR_TEST"/>"#
        );
    }

    #[test]
    fn test_normalize_digest_values_noop_on_other_elements() {
        let xml = r#"<SomeElement type="ByteString" value="abc123"/>"#;
        let result = normalize_digest_values(xml);
        assert_eq!(result, xml);
    }

    #[test]
    fn test_normalize_digest_values_already_normalized() {
        let xml = r#"<DigestValue type="ByteString" value="NORMALIZED_FOR_TEST"/>"#;
        let result = normalize_digest_values(xml);
        assert_eq!(result, xml);
    }
```

- [ ] **Step 2: Run to confirm compile failure**

```bash
cargo test -p tests_e2e test_normalize_digest 2>&1 | grep -E "error|FAILED"
```

Expected: compile error — `normalize_digest_values` not defined.

- [ ] **Step 3: Implement `normalize_digest_values`**

Add after `apply_var_substitution` in `tests_e2e/src/test/util.rs`:

```rust
fn normalize_digest_values(xml: &str) -> String {
    lazy_static! {
        static ref DIGEST_RE: Regex =
            Regex::new(r#"DigestValue\s+type="ByteString"\s+value="[^"]*""#).unwrap();
    }
    DIGEST_RE
        .replace_all(xml, r#"DigestValue type="ByteString" value="NORMALIZED_FOR_TEST""#)
        .into_owned()
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cargo test -p tests_e2e test_normalize_digest
```

Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests_e2e/src/test/util.rs
git commit -m "Add normalize_digest_values helper with unit tests"
```

---

### Task 5: Add `ConversationNormalizer` struct with unit tests (TDD)

**Files:**
- Modify: `tests_e2e/src/test/util.rs`

- [ ] **Step 1: Write failing unit tests**

Inside the existing `mod tests` block, add:

```rust
    #[test]
    fn test_normalizer_apply_to_request_substitutes_uid() {
        let mut normalizer = ConversationNormalizer::new();
        normalizer.var_map.insert(
            "$UNIQUE_IDENTIFIER_0".to_string(),
            "real-id-42".to_string(),
        );
        let req = r#"<UniqueIdentifier type="TextString" value="$UNIQUE_IDENTIFIER_0"/>"#;
        let result = normalizer.apply_to_request(req);
        assert!(result.contains(r#"value="real-id-42""#));
    }

    #[test]
    fn test_normalizer_apply_to_response_extracts_and_substitutes() {
        let mut normalizer = ConversationNormalizer::new();

        let actual = r#"<UniqueIdentifier type="TextString" value="real-id-99"/>"#;
        let expected = r#"<UniqueIdentifier type="TextString" value="$UNIQUE_IDENTIFIER_0"/>"#;

        let (norm_actual, norm_expected) = normalizer.apply_to_response(actual, expected);

        // actual is unchanged (no DigestValue to normalize)
        assert_eq!(norm_actual, actual);
        // expected had $UNIQUE_IDENTIFIER_0 replaced with the extracted value
        assert!(norm_expected.contains(r#"value="real-id-99""#));
    }

    #[test]
    fn test_normalizer_apply_to_response_normalizes_digest() {
        let mut normalizer = ConversationNormalizer::new();

        let actual = r#"<DigestValue type="ByteString" value="deadbeef"/>"#;
        let expected = r#"<DigestValue type="ByteString" value="cafebabe"/>"#;

        let (norm_actual, norm_expected) = normalizer.apply_to_response(actual, expected);

        assert_eq!(
            norm_actual,
            r#"<DigestValue type="ByteString" value="NORMALIZED_FOR_TEST"/>"#
        );
        assert_eq!(
            norm_expected,
            r#"<DigestValue type="ByteString" value="NORMALIZED_FOR_TEST"/>"#
        );
    }
```

- [ ] **Step 2: Run to confirm compile failure**

```bash
cargo test -p tests_e2e test_normalizer 2>&1 | grep -E "error|FAILED"
```

Expected: compile error — `ConversationNormalizer` not defined.

- [ ] **Step 3: Implement `ConversationNormalizer`**

Add before the `#[cfg(test)]` block in `tests_e2e/src/test/util.rs`:

```rust
pub struct ConversationNormalizer {
    var_map: HashMap<String, String>,
}

impl ConversationNormalizer {
    pub fn new() -> Self {
        ConversationNormalizer {
            var_map: HashMap::new(),
        }
    }

    pub fn apply_to_request(&mut self, xml: &str) -> String {
        apply_var_substitution(xml, &self.var_map)
    }

    pub fn apply_to_response(&mut self, actual: &str, expected: &str) -> (String, String) {
        extract_variables(actual, &mut self.var_map);
        let norm_expected = apply_var_substitution(expected, &self.var_map);
        let norm_actual = normalize_digest_values(actual);
        let norm_expected = normalize_digest_values(&norm_expected);
        (norm_actual, norm_expected)
    }
}
```

- [ ] **Step 4: Run all unit tests and confirm they pass**

```bash
cargo test -p tests_e2e test_normalizer
```

Expected: 3 tests pass.

- [ ] **Step 5: Run full unit test suite to confirm no regressions**

```bash
cargo test -p tests_e2e 2>&1 | grep -E "test .* \.\.\." | head -40
```

Expected: all unit tests pass (e2e tests may be skipped or need network).

- [ ] **Step 6: Commit**

```bash
git add tests_e2e/src/test/util.rs
git commit -m "Add ConversationNormalizer struct with unit tests"
```

---

### Task 6: Wire `ConversationNormalizer` into `run_e2e_xml_conversation`

**Files:**
- Modify: `tests_e2e/src/test/util.rs`

- [ ] **Step 1: Update `run_e2e_xml_conversation`**

Replace the existing function body (lines 211–231 of `tests_e2e/src/test/util.rs`) with:

```rust
pub fn run_e2e_xml_conversation(conv: &str) {
    let (reqs, resps) = parse_kmip_messages(conv);

    assert_eq!(reqs.len(), resps.len());

    let mut normalizer = ConversationNormalizer::new();

    run_e2e_client_test(reqs.len() as i32, |mut client| {
        for (i, req) in reqs.iter().enumerate() {
            let req = normalizer.apply_to_request(req);

            println!("XML Request: {:?}", req);

            let mut resp = client.make_xml_request(&req);
            eprintln!("{:?}", resp);

            resp = resp.replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>", "");
            resp = resp.replace(" />", "/>");

            let mut expected_resp = resps[i].to_owned();
            expected_resp = expected_resp.replace(" xmlns=\"ignore\"", "");

            let (norm_resp, norm_expected) = normalizer.apply_to_response(&resp, &expected_resp);

            assert_xml_eq(&norm_resp, &norm_expected);
        }
    });
}
```

- [ ] **Step 2: Run existing e2e tests to confirm no regressions**

```bash
cargo test -p tests_e2e e2e_test_xml 2>&1 | tail -20
```

Expected: all existing `e2e_test_xml_*` tests still pass (they use hardcoded values so the normalizer is a no-op for them).

- [ ] **Step 3: Commit**

```bash
git add tests_e2e/src/test/util.rs
git commit -m "Wire ConversationNormalizer into run_e2e_xml_conversation"
```

---

### Task 7: Add e2e test for SKFF-M-1-14.xml (Create + Destroy)

**Files:**
- Modify: `tests_e2e/src/test/basic.rs`

- [ ] **Step 1: Add the test function**

At the end of `tests_e2e/src/test/basic.rs`, add:

```rust
// https://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/SKFF-M-1-14.xml
#[test]
fn e2e_test_xml_skff_m_1_14() {
    let conv = std::str::from_utf8(
        include_bytes!("../../../../test_cases/1.4/SKFF-M-1-14.xml"),
    )
    .unwrap();
    run_e2e_xml_conversation(conv);
}
```

- [ ] **Step 2: Run the test**

```bash
cargo test -p tests_e2e e2e_test_xml_skff_m_1_14 -- --nocapture 2>&1 | tail -30
```

Expected: test passes. The normalizer substitutes `$NOW` from the Create response timestamp and `$UNIQUE_IDENTIFIER_0` from the returned key ID into both the Destroy request and both expected responses.

If the test fails, inspect the diff output — it will show exactly which fields don't match.

- [ ] **Step 3: Commit**

```bash
git add tests_e2e/src/test/basic.rs
git commit -m "Add e2e test for SKFF-M-1-14 (Create + Destroy)"
```

---

### Task 8: Add e2e test for SKLC-M-1-14.xml (Create + GetAttributes + Destroy)

**Files:**
- Modify: `tests_e2e/src/test/basic.rs`

- [ ] **Step 1: Add the test function**

At the end of `tests_e2e/src/test/basic.rs`, add:

```rust
// https://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/SKLC-M-1-14.xml
#[test]
fn e2e_test_xml_sklc_m_1_14_file() {
    let conv = std::str::from_utf8(
        include_bytes!("../../../../test_cases/1.4/SKLC-M-1-14.xml"),
    )
    .unwrap();
    run_e2e_xml_conversation(conv);
}
```

- [ ] **Step 2: Run the test**

```bash
cargo test -p tests_e2e e2e_test_xml_sklc_m_1_14_file -- --nocapture 2>&1 | tail -40
```

Expected: test passes. The normalizer handles `$NOW`, `$UNIQUE_IDENTIFIER_0`, and `DigestValue` normalization across the three-step Create / GetAttributes / Destroy conversation.

**Note:** The server currently does not implement the `Digest` attribute (`get_attribute("Digest")` returns `None`). If the test fails because the actual response is missing the `<Attribute><AttributeName value="Digest"/>...</Attribute>` block that the OASIS file expects, investigate whether to: (a) skip the Digest block in normalization, or (b) implement Digest in the server store. The diff will make the failure obvious.

- [ ] **Step 3: Run the full test suite to confirm no regressions**

```bash
cargo test -p tests_e2e 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests_e2e/src/test/basic.rs
git commit -m "Add e2e test for SKLC-M-1-14 (Create + GetAttributes + Destroy)"
```
