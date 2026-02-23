#[cfg(test)]
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

#[cfg(test)]
use difference::assert_diff;

#[cfg(test)]
use kmip_client::Client;

#[cfg(test)]
use kmip_server::{
    handle_client, store::KmipStore, test_util::TestClockSource, test_util::TestRngSource,
    ServerContext,
};

#[cfg(test)]
use minidom::Element;

#[cfg(test)]
use rustls::{ClientConnection, Stream};

#[cfg(test)]
use std::env;

extern crate kmip_client;
extern crate kmip_server;

#[cfg(test)]
struct PortAllocator {
    start: u16,
}

#[cfg(test)]
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

#[cfg(test)]
lazy_static! {
    static ref GLOBAL_PORT_ALLOCATOR: Mutex<PortAllocator> = Mutex::new(PortAllocator::new());
}

#[cfg(test)]
fn get_test_data_dir() -> PathBuf {
    let path = env::current_dir().unwrap();
    eprintln!("The current directory is {}", path.display());
    let mut root_dir = PathBuf::from(&path.parent().unwrap());
    root_dir.push("test_data");
    root_dir
}

// TODO - stop using Barrier, which really need Windows ManualResetEvent but I am too lazy to write it
#[cfg(test)]
fn run_server_count(start_barrier: Arc<Barrier>, end_barrier: Arc<Barrier>, port: u16, count: i32) {
    use rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    };

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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn pretty_print_xml(s: &str) -> String {
    let mut file = minidom::quick_xml::Reader::from_str(s);
    file.trim_text(true);
    let root: Element = Element::from_reader(&mut file).unwrap();
    let buf: Vec<u8> = Vec::new();

    let mut writer = minidom::quick_xml::Writer::new_with_indent(buf, ' ' as u8, 4);
    root.to_writer(&mut writer).unwrap();

    std::str::from_utf8(&writer.into_inner())
        .unwrap()
        .to_string()
}

#[cfg(test)]
fn assert_xml_eq(left: &str, right: &str) {
    if left != right {
        let left_xml = pretty_print_xml(left);
        let right_xml = pretty_print_xml(right);

        assert_diff! {&left_xml, &right_xml, "\n", 0};
    }
}

#[cfg(test)]
pub fn run_e2e_xml_conversation(conv: &str) {
    let mut file = minidom::quick_xml::Reader::from_str(conv);
    file.trim_text(true);
    let root: Element = Element::from_reader(&mut file).unwrap();

    let mut reqs: Vec<String> = Vec::new();
    let mut resps: Vec<String> = Vec::new();
    for child in root.children() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = minidom::quick_xml::Writer::new(buf);
        child.to_writer(&mut writer).unwrap();

        let xml_str = std::str::from_utf8(&writer.into_inner())
            .unwrap()
            .to_string();
        // println!("{:?}", child);
        println!("xml_str{:?}", xml_str);
        if child.name() == "RequestMessage" {
            reqs.push(xml_str);
        } else if child.name() == "ResponseMessage" {
            resps.push(xml_str);
        } else {
            panic!("Unknown XML child {:?}", child.name());
        }
    }

    assert_eq!(reqs.len(), resps.len());

    run_e2e_client_test(reqs.len() as i32, |mut client| {
        for (i, req) in reqs.iter().enumerate() {
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
