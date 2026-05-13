# ConversationNormalizer Design

**Date:** 2026-05-13

## Problem

OASIS KMIP XML test case files (e.g., `test_cases/1.4/SKFF-M-1-14.xml`) use placeholder variables (`$NOW`, `$UNIQUE_IDENTIFIER_0`, etc.) and non-deterministic fields (`DigestValue`) that must be resolved before comparing actual server responses against expected responses. The normalizations are expected to grow over time.

## Architecture

A `ConversationNormalizer` struct is added to `tests_e2e/src/test/util.rs`. It owns a variable map and provides two public methods consumed by `run_e2e_xml_conversation`.

```
ConversationNormalizer
  ├── var_map: HashMap<String, String>
  │     Keys:   "$NOW", "$UNIQUE_IDENTIFIER_0", "$UNIQUE_IDENTIFIER_1", ...
  │     Values: actual values extracted from server responses
  │
  ├── pub fn apply_to_request(&mut self, xml: &str) -> String
  │     Applies var_map substitutions to the request XML before sending.
  │     On first call var_map is empty, so no-op for most requests.
  │
  └── pub fn apply_to_response(&mut self, actual: &str, expected: &str) -> (String, String)
        1. extract_variables(actual) → update var_map
        2. apply_var_substitution(expected, &var_map) → normalized_expected
        3. normalize_digest_values(actual) → normalized_actual
        4. normalize_digest_values(normalized_expected) → normalized_expected
        Returns (normalized_actual, normalized_expected) ready for assert_xml_eq
```

Private helpers (pure functions, easily unit-testable):

- `extract_variables(xml: &str, var_map: &mut HashMap<String, String>)`
- `apply_var_substitution(xml: &str, var_map: &HashMap<String, String>) -> String`
- `normalize_digest_values(xml: &str) -> String`

## Variable Extraction Rules

Extraction uses regex on the actual response XML:

| Extracted from | Variable name | Example actual value |
|---|---|---|
| First `TimeStamp type="DateTime"` value seen across the conversation | `$NOW` | `"1970-01-01T00:02:03+00:00"` or `"10000"` |
| `UniqueIdentifier type="TextString"` values in first-appearance order | `$UNIQUE_IDENTIFIER_0`, `$UNIQUE_IDENTIFIER_1`, … | `"abc-123"` |

`$NOW` is stored once (first seen) and reused for all subsequent `$NOW` occurrences, since `TestClockSource` returns a fixed time. New variable types (e.g., `$ACTIVATION_DATE`) are added as new extraction rules in `extract_variables`.

## DigestValue Normalization

The `value` attribute of any `DigestValue type="ByteString"` element is replaced with `NORMALIZED_FOR_TEST` in **both** the actual and expected XML before comparison. This handles the case where the OASIS test file specifies a concrete digest that may differ from what the server produces.

Regex pattern: `DigestValue\s+type="ByteString"\s+value="[^"]*"` → `DigestValue type="ByteString" value="NORMALIZED_FOR_TEST"`

## Changes to `run_e2e_xml_conversation`

```rust
pub fn run_e2e_xml_conversation(conv: &str) {
    let (reqs, resps) = parse_kmip_messages(conv);
    assert_eq!(reqs.len(), resps.len());

    let mut normalizer = ConversationNormalizer::new();   // NEW

    run_e2e_client_test(reqs.len() as i32, |mut client| {
        for (i, req) in reqs.iter().enumerate() {
            let req = normalizer.apply_to_request(req);   // NEW

            let mut resp = client.make_xml_request(&req);
            resp = resp.replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>", "");
            resp = resp.replace(" />", "/>");

            let mut expected = resps[i].to_owned();
            expected = expected.replace(" xmlns=\"ignore\"", "");

            let (norm_resp, norm_expected) =              // NEW
                normalizer.apply_to_response(&resp, &expected);

            assert_xml_eq(&norm_resp, &norm_expected);
        }
    });
}
```

Existing tests that use hardcoded XML (no `$` variables, no `DigestValue`) are unaffected — `var_map` stays empty and `normalize_digest_values` is a no-op on XML without that element.

## New Tests

In `tests_e2e/src/test/basic.rs`, two new test functions are added:

```rust
#[test]
fn e2e_test_xml_skff_m_1_14() {
    let conv = std::str::from_utf8(
        include_bytes!("../../../../test_cases/1.4/SKFF-M-1-14.xml")
    ).unwrap();
    run_e2e_xml_conversation(conv);
}

#[test]
fn e2e_test_xml_sklc_m_1_14_file() {
    let conv = std::str::from_utf8(
        include_bytes!("../../../../test_cases/1.4/SKLC-M-1-14.xml")
    ).unwrap();
    run_e2e_xml_conversation(conv);
}
```

The `include_bytes!` path is relative to the source file (`tests_e2e/src/test/basic.rs`), so `../../../../test_cases/1.4/` resolves to the repo root's `test_cases/1.4/` directory at compile time.

## File Locations

| File | Change |
|---|---|
| `tests_e2e/src/test/util.rs` | Add `ConversationNormalizer` struct + private helpers; update `run_e2e_xml_conversation` |
| `tests_e2e/src/test/basic.rs` | Add two new `#[test]` functions |
| `test_cases/1.4/SKFF-M-1-14.xml` | Read-only (embedded via `include_bytes!`) |
| `test_cases/1.4/SKLC-M-1-14.xml` | Read-only (embedded via `include_bytes!`) |
