use std::fs::File;
use std::io::Cursor;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::{
    net,
    net::TcpListener,
    net::{IpAddr, Ipv4Addr, TcpStream},
    path::PathBuf,
    sync::Arc,
    sync::Barrier,
    sync::Mutex,
    thread,
};

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;

use difference::assert_diff;

use kmip_client::Client;

use kmip_server::{
    handle_client, store::KmipStore, test_util::TestClockSource, test_util::TestRngSource,
    ServerContext,
};

use minidom::Element;

use rustls::{ClientConnection, Stream};

use std::env;

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

// TODO - stop using Barrier, which really need Windows ManualResetEvent but I am too lazy to write it
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
    let ca_cert_file = root_dir.join("ca.pem");

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
        ClientConfig, RootCertStore,
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

fn get_buf_reader<P: AsRef<Path>>(filename: P) -> io::Result<impl BufRead> {
    let file = File::open(filename)?;
    Ok(BufReader::new(file))
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

/// Returns a tuple containing: (Vector of Requests, Vector of Responses)
fn parse_kmip_messages(xml: &str) -> (Vec<String>, Vec<String>) {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut requests = Vec::new();
    let mut responses = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(_) | Ok(Event::Eof) => break,
            Ok(Event::Start(ref e)) => {
                let tag_name = e.name();
                if tag_name.as_ref() == b"RequestMessage" || tag_name.as_ref() == b"ResponseMessage"
                {
                    // Capture the full content of this specific element
                    let span_start =
                        reader.buffer_position() as usize - (tag_name.as_ref().len() + 2);

                    // We need to find the corresponding end tag
                    if let Ok(_) = reader.read_to_end_into(tag_name, &mut Vec::new()) {
                        let span_end = reader.buffer_position() as usize;
                        let full_tag = &xml[span_start..span_end];

                        if tag_name.as_ref() == b"RequestMessage" {
                            requests.push(full_tag.to_string());
                        } else if tag_name.as_ref() == b"ResponseMessage" {
                            responses.push(full_tag.to_string());
                        } else {
                            panic!("Unexpected XML input: {tag_name:?} ");
                        }
                    }
                }
            }
            _ => (),
        }
        buf.clear();
    }

    (requests, responses)
}

pub fn run_e2e_xml_conversation(conv: &str) {
    let (reqs, resps) = parse_kmip_messages(conv);

    assert_eq!(reqs.len(), resps.len());

    run_e2e_client_test(reqs.len() as i32, |mut client| {
        for (i, req) in reqs.iter().enumerate() {
            println!("XML Request1111: {:?}", req);

            let mut resp = client.make_xml_request(&req);
            eprintln!("{:?}", resp);

            resp = resp.replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>", "");
            resp = resp.replace(" />", "/>");
            let mut expected_resp = resps[i].to_owned();
            expected_resp = expected_resp.replace(" xmlns=\"ignore\"", "");
            assert_xml_eq(&resp, &expected_resp);
            // assert_eq! {resp, expected_resp };
        }
    });
}
