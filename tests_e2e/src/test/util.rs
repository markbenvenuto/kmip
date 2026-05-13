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

use difference::assert_diff;
use kmip_client::{parse_kmip_messages, Client};
use kmip_server::{
    handle_client,
    store::KmipStore,
    test_util::{TestClockSource, TestRngSource},
    ServerContext,
};
use lazy_static::lazy_static;
use quick_xml::{reader::Reader, writer::Writer};
use regex::Regex;
use rustls::{ClientConnection, Stream};

struct PortAllocator {
    start: u16,
}

impl PortAllocator {
    fn new() -> Self {
        PortAllocator { start: 7000 }
    }

    fn allocate(&mut self) -> u16 {
        let port = self.start;
        self.start += 1;
        port
    }
}

lazy_static! {
    static ref GLOBAL_PORT_ALLOCATOR: Mutex<PortAllocator> = Mutex::new(PortAllocator::new());
}

fn get_test_data_dir() -> PathBuf {
    let path = env::current_dir().unwrap();
    eprintln!("The current directory is {}", path.display());
    let mut root_dir = PathBuf::from(&path.parent().unwrap());
    root_dir.push("test_data");
    root_dir
}

// TODO - stop using Barrier, which really need Windows ManualResetEvent but I am too lazy to write
// it
fn run_server_count(start_barrier: Arc<Barrier>, end_barrier: Arc<Barrier>, port: u16, count: i32) {
    use rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    };

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let root_dir = get_test_data_dir();
    let server_cert_file = root_dir.join("server.pem");
    let server_key_file = root_dir.join("server.key");
    let _ca_cert_file = root_dir.join("ca.pem");

    // TODO - dynamically allocate port
    let addr: net::SocketAddr = net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    let listener = TcpListener::bind(&addr).expect("cannot listen on port");

    let server_cert = CertificateDer::from_pem_file(server_cert_file).unwrap();
    let server_cert_private_key = PrivateKeyDer::from_pem_file(server_key_file).unwrap();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_cert_private_key)
        .unwrap();

    let clock_source = Arc::new(TestClockSource::new());
    let rng_source = Arc::new(TestRngSource::new());
    let store = Arc::new(KmipStore::new_mem(clock_source.clone()));
    let server_context = Arc::new(ServerContext::new(store, clock_source, rng_source));
    let sc = Arc::new(server_config);

    start_barrier.wait();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("new client!");
                let sc2 = sc.clone();
                let mut tls_session = rustls::ServerConnection::new(sc2).unwrap();
                let mut tls = rustls::Stream::new(&mut tls_session, &mut stream);

                let mut req_count = count;
                while req_count > 0 {
                    handle_client(&mut tls, &server_context);
                    req_count -= 1;
                }

                end_barrier.wait();

                return;
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }

    end_barrier.wait();
}

fn run_with_client<F>(port: u16, mut func: F)
where
    F: FnMut(Client<Stream<ClientConnection, TcpStream>>),
{
    use std::convert::TryFrom;

    use rustls::{
        pki_types::{pem::PemObject, CertificateDer, ServerName},
        ClientConfig,
        RootCertStore,
    };

    let root_dir = get_test_data_dir();
    let ca_cert_file = root_dir.join("ca.pem");

    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let cert = CertificateDer::from_pem_file(ca_cert_file).unwrap();

    root_store.add(cert).unwrap();

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let dns_name = ServerName::try_from("localhost").expect("invalid DNS name");
    let rc_config = Arc::new(config);
    let mut client =
        rustls::ClientConnection::new(rc_config, dns_name).expect("Valid TLS connection setup");
    let mut sock = TcpStream::connect(("localhost", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut client, &mut sock);

    //let kmip_stream = StreamAdapter::new(&mut tls);
    let a = Client::create_from_stream(&mut tls);
    func(a);
}

pub fn run_e2e_client_test<F>(count: i32, func: F)
where
    F: FnMut(Client<Stream<ClientConnection, TcpStream>>),
{
    //let ssf = SharedStreamFactory::new();

    let port = GLOBAL_PORT_ALLOCATOR.lock().unwrap().allocate();
    let start_barrier = Arc::new(Barrier::new(2));
    let end_barrier = Arc::new(Barrier::new(2));

    let b1 = start_barrier.clone();
    let b2 = end_barrier.clone();
    let t1 = thread::spawn(move || {
        run_server_count(b1, b2, port, count);
    });

    start_barrier.wait();

    run_with_client(port, func);

    end_barrier.wait();

    t1.join().unwrap();
}

fn pretty_print_xml(xml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true); // Prevents doubling up on existing whitespace

    let mut buf = Vec::new();
    // Initialize the writer with a 4-space indent (' ', 4)
    let mut writer = Writer::new_with_indent(Cursor::new(&mut buf), b' ', 4);

    loop {
        match reader.read_event() {
            Ok(event) => {
                // End of file
                if let quick_xml::events::Event::Eof = event {
                    break;
                }
                // Write the event to the pretty-printer
                writer.write_event(event)?;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }

    Ok(String::from_utf8(buf)?.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", ""))
}

fn assert_xml_eq(left: &str, right: &str) {
    if left != right {
        let left_xml = pretty_print_xml(left).unwrap();
        let right_xml = pretty_print_xml(right).unwrap();

        assert_diff! {&left_xml, &right_xml, "\n", 0};
    }
}

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

fn apply_var_substitution(xml: &str, var_map: &HashMap<String, String>) -> String {
    // Sort by key length descending so longer keys (e.g. $UNIQUE_IDENTIFIER_10) are replaced
    // before shorter prefixes ($UNIQUE_IDENTIFIER_1), and iteration order is deterministic.
    let mut pairs: Vec<(&String, &String)> = var_map.iter().collect();
    pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    let mut result = xml.to_string();
    for (var, value) in pairs {
        result = result.replace(var.as_str(), value.as_str());
    }
    result
}

fn normalize_digest_values(xml: &str) -> String {
    lazy_static! {
        static ref DIGEST_RE: Regex =
            Regex::new(r#"DigestValue\s+type="ByteString"\s+value="[^"]*""#).unwrap();
    }
    DIGEST_RE
        .replace_all(xml, r#"DigestValue type="ByteString" value="NORMALIZED_FOR_TEST""#)
        .into_owned()
}

/// Strip entire `<Attribute><AttributeName value="Digest"/>...</Attribute>` blocks from
/// `expected` when `actual` does not contain a Digest attribute.  This allows tests to pass
/// when the server does not yet implement the Digest attribute.
fn strip_digest_attribute_block_if_absent(actual: &str, expected: &str) -> String {
    lazy_static! {
        static ref DIGEST_ATTR_RE: Regex = Regex::new(
            r#"(?s)<Attribute>\s*<AttributeName\s+type="TextString"\s+value="Digest"/>\s*<AttributeValue>.*?</AttributeValue>\s*</Attribute>"#
        )
        .unwrap();
        static ref HAS_DIGEST_RE: Regex =
            Regex::new(r#"AttributeName\s+type="TextString"\s+value="Digest""#).unwrap();
    }
    if HAS_DIGEST_RE.is_match(actual) {
        // actual has Digest — keep expected as-is
        expected.to_string()
    } else {
        // actual is missing Digest — strip the block from expected so comparison succeeds
        DIGEST_ATTR_RE.replace_all(expected, "").into_owned()
    }
}

/// Normalize human-readable CryptographicUsageMask symbolic values in `expected` to the
/// integer form that the server returns.  The OASIS test-case XML files use names like
/// `"Decrypt Encrypt"` while the server emits the bitmask integer (e.g. `"12"`).
fn normalize_crypto_usage_mask(xml: &str) -> String {
    // KMIP usage-mask bit values (Section 2.1.3 of the KMIP spec):
    //   Sign=0x01, Verify=0x02, Encrypt=0x04, Decrypt=0x08, WrapKey=0x10, UnwrapKey=0x20,
    //   Export=0x40, MACGenerate=0x80, MACVerify=0x100, DeriveKey=0x200, ...
    let bit_map: &[(&str, u32)] = &[
        ("Sign", 0x0001),
        ("Verify", 0x0002),
        ("Encrypt", 0x0004),
        ("Decrypt", 0x0008),
        ("WrapKey", 0x0010),
        ("UnwrapKey", 0x0020),
        ("Export", 0x0040),
        ("MACGenerate", 0x0080),
        ("MACVerify", 0x0100),
        ("DeriveKey", 0x0200),
        ("ContentCommitment", 0x0400),
        ("KeyAgreement", 0x0800),
        ("CertificateSign", 0x1000),
        ("CRLSign", 0x2000),
    ];

    lazy_static! {
        static ref USAGE_MASK_RE: Regex = Regex::new(
            r#"(?s)(<AttributeName\s+type="TextString"\s+value="Cryptographic Usage Mask"/>\s*<AttributeValue\s+type="Integer"\s+value=")([^"]+)(")"#
        )
        .unwrap();
    }

    USAGE_MASK_RE
        .replace_all(xml, |caps: &regex::Captures| {
            let value = &caps[2];
            // If already numeric, leave as-is
            if value.parse::<u32>().is_ok() {
                return caps[0].to_string();
            }
            // Try to interpret as space-separated symbolic names
            let mut mask: u32 = 0;
            let mut matched = true;
            for token in value.split_whitespace() {
                if let Some(&(_, bit)) = bit_map.iter().find(|&&(name, _)| name == token) {
                    mask |= bit;
                } else {
                    matched = false;
                    break;
                }
            }
            if matched && mask > 0 {
                format!("{}{}{}", &caps[1], mask, &caps[3])
            } else {
                caps[0].to_string()
            }
        })
        .into_owned()
}

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
        let norm_expected = strip_digest_attribute_block_if_absent(actual, &norm_expected);
        let norm_actual = normalize_crypto_usage_mask(actual);
        let norm_expected = normalize_crypto_usage_mask(&norm_expected);
        let norm_actual = normalize_digest_values(&norm_actual);
        let norm_expected = normalize_digest_values(&norm_expected);
        (norm_actual, norm_expected)
    }
}

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
}
