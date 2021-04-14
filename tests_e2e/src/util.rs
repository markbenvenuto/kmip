
use std::{
    fs,
    io::BufReader,
    net,
    net::TcpListener,
    net::{IpAddr, Ipv4Addr, TcpStream},
    path::PathBuf,
    sync::Arc,
    sync::Barrier,
    sync::Mutex,
    thread,
};

use difference::assert_diff;
use kmip_client::Client;
use kmip_server::{
    handle_client, process_kmip_request, store::KmipStore, RequestContext, ServerContext,
    TestClockSource,
};
use minidom::Element;
use rustls::{ClientSession, NoClientAuth, Stream};
use std::env;

extern crate kmip_client;
extern crate kmip_server;

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

fn load_certs(filename: &PathBuf) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &PathBuf) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
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
    let root_dir = get_test_data_dir();
    let server_cert_file = root_dir.join("server.pem");
    let server_key_file = root_dir.join("server.key");
    let ca_cert_file = root_dir.join("ca.pem");

    // TODO - dynamically allocate port
    let addr: net::SocketAddr = net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    let listener = TcpListener::bind(&addr).expect("cannot listen on port");
    let mut server_config = rustls::ServerConfig::new(NoClientAuth::new());

    let mut server_certs = load_certs(&server_cert_file);
    let privkey = load_private_key(&server_key_file);

    let mut ca_certs = load_certs(&ca_cert_file);

    server_certs.append(&mut ca_certs);

    server_config
        .set_single_cert(server_certs, privkey)
        .unwrap();

    let clock_source = Arc::new(TestClockSource::new());
    let store = Arc::new(KmipStore::new_mem(clock_source.clone()));
    let server_context = Arc::new(ServerContext::new(store, clock_source));
    let sc = Arc::new(server_config);

    start_barrier.wait();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("new client!");
                let sc2 = sc.clone();
                let mut tls_session = rustls::ServerSession::new(&sc2);
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
    F: FnMut(Client<Stream<ClientSession, TcpStream>>),
{
    let mut config = rustls::ClientConfig::new();

    let root_dir = get_test_data_dir();
    let ca_cert_file = root_dir.join("ca.pem");
    let certfile = fs::File::open(ca_cert_file).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    config.root_store.add_pem_file(&mut reader).unwrap();

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect(("localhost", port)).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    //let kmip_stream = StreamAdapter::new(&mut tls);
    let a = Client::create_from_stream(&mut tls);
    func(a);
}

pub fn run_e2e_client_test<F>(count: i32, func: F)
where
    F: FnMut(Client<Stream<ClientSession, TcpStream>>),
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

fn assert_xml_eq(left: &str, right: &str) {
    if left != right {
        let left_xml = pretty_print_xml(left);
        let right_xml = pretty_print_xml(right);

        assert_diff! {&left_xml, &right_xml, "\n", 0};
    }
}

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
