//mod shared_stream;

#[macro_use]
extern crate lazy_static;

  
#[cfg(test)]
mod tests {

    use std::{fs, io::BufReader, net, net::TcpListener, net::{IpAddr, Ipv4Addr, TcpStream}, path::PathBuf, sync::Arc, sync::Barrier, sync::Mutex, thread};

        use std::env;
use kmip_client::Client;
    use kmip_server::{
        handle_client, process_kmip_request, store::KmipMemoryStore, RequestContext, ServerContext,
        TestClockSource,
    };
    use minidom::Element;
    use rustls::{ClientSession, NoClientAuth, Stream};

    extern crate kmip_client;
    extern crate kmip_server;


    struct PortAllocator {
      start: u16,
    }
    
    impl PortAllocator {
    
      fn new() -> Self {
        PortAllocator{
          start: 6000,
        }
      }
    
      fn allocate(&mut self) -> u16 {
        let port = self.start;
        self.start+=1;
        port
      }
    }
          
      lazy_static! {
        static ref GLOBAL_PORT_ALLOCATOR: Mutex<PortAllocator> = Mutex::new(PortAllocator::new());
      }
    

    #[test]
    fn test_10_create() {

        let clock_source = Arc::new(TestClockSource::new());

        let store = Arc::new(KmipMemoryStore::new());

        let server_context = ServerContext::new(store, clock_source);

        let mut rc = RequestContext::new(&server_context);

        // From 1.0 test case, 3.1.1
        let bytes = hex::decode("42007801000001204200770100000038420069010000002042006A0200000004000000010000000042006B0200000004000000000000000042000D0200000004000000010000000042000F01000000D842005C0500000004000000010000000042007901000000C04200570500000004000000020000000042009101000000A8420008010000003042000A070000001743727970746F6772617068696320416C676F726974686D0042000B05000000040000000300000000420008010000003042000A070000001443727970746F67726170686963204C656E6774680000000042000B02000000040000008000000000420008010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B02000000040000000C00000000").unwrap();

        let resp = process_kmip_request(&mut rc, bytes.as_slice());

        protocol::to_print(resp.as_slice());

        println!("Hello");
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
    fn run_server_count(start_barrier: Arc<Barrier>, end_barrier: Arc<Barrier>, port  : u16, count: i32) {

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

        let store = Arc::new(KmipMemoryStore::new());
        let clock_source = Arc::new(TestClockSource::new());
        let server_context = Arc::new(ServerContext::new(store, clock_source));
        let sc = Arc::new(server_config);

        start_barrier.wait();

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    println!("new client!");
                    let sc2 = sc.clone();
                    let server_context2 = server_context.clone();
                    // thread::spawn(move || {
                    let mut tls_session = rustls::ServerSession::new(&sc2);
                    let mut tls = rustls::Stream::new(&mut tls_session, &mut stream);

                    let mut req_count = count;
                    while req_count > 0 {
                        handle_client(&mut tls, &server_context2);
                        req_count -= 1;
                    }

                    end_barrier.wait();

                    return;
                    // });
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }

        end_barrier.wait();
    }

    fn run_with_client<F>(port : u16, mut func: F)
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

    fn run_e2e_client_test<F>(count: i32, func: F)
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

    #[test]
    fn e2e_test_10_create() {
        run_e2e_client_test(1, |mut client| {
            let mut bytes = hex::decode("42007801000001204200770100000038420069010000002042006A0200000004000000010000000042006B0200000004000000000000000042000D0200000004000000010000000042000F01000000D842005C0500000004000000010000000042007901000000C04200570500000004000000020000000042009101000000A8420008010000003042000A070000001743727970746F6772617068696320416C676F726974686D0042000B05000000040000000300000000420008010000003042000A070000001443727970746F67726170686963204C656E6774680000000042000B02000000040000008000000000420008010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B02000000040000000C00000000").unwrap();

            let resp = client.make_request(&mut bytes);
            eprintln!("{:?}", resp);
        });
    }

    // https://docs.oasis-open.org/kmip/testcases/v1.2/kmip-testcases-v1.2.html
    // has test cases for 1.0, 1.1 and 1.2

    #[test]
    fn e2e_test_xml_10_create() {
        run_e2e_client_test(1, |mut client| {
            let conv = r#"
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Create"/>
    <RequestPayload>
      <ObjectType type="Enumeration" value="SymmetricKey"/>
      <TemplateAttribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Algorithm"/>
          <AttributeValue type="Enumeration" value="AES"/>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Length"/>
          <AttributeValue type="Integer" value="128"/>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
          <AttributeValue type="Integer" value="Decrypt Encrypt"/>
        </Attribute>
      </TemplateAttribute>
    </RequestPayload>
  </BatchItem>
</RequestMessage>"#;

            let resp = client.make_xml_request(conv);
            eprintln!("{:?}", resp);
        });
    }

    fn run_e2e_xml_conversation(conv: &str) {
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
                panic!(format!("Unknown XML child {:?}", child.name()));
            }
        }

        assert_eq!(reqs.len(), resps.len());

        run_e2e_client_test(reqs.len() as i32, |mut client| {
            for (i, req) in reqs.iter().enumerate() {
                let mut resp = client.make_xml_request(&req);
                eprintln!("{:?}", resp);

                resp = resp.replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>", "");
                resp = resp.replace(" />", "/>");
                assert_eq! {resp, resps[i]};
            }
        });
    }

    #[test]
    fn e2e_test_xml_tc_311_10() {
        let conv = r#"
<KMIP>
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Create"/>
    <RequestPayload>
      <ObjectType type="Enumeration" value="SymmetricKey"/>
      <TemplateAttribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Algorithm"/>
          <AttributeValue type="Enumeration" value="AES"/>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Length"/>
          <AttributeValue type="Integer" value="128"/>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
          <AttributeValue type="Integer" value="Decrypt Encrypt"/>
        </Attribute>
      </TemplateAttribute>
    </RequestPayload>
  </BatchItem>
</RequestMessage>
<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Create"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <ObjectType type="Enumeration" value="SymmetricKey"/>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Destroy"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </RequestPayload>
  </BatchItem>
</RequestMessage>
<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Destroy"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>
</KMIP>
"#;

        run_e2e_xml_conversation(conv);
    }

    #[test]
    fn e2e_test_xml_tc_315_10() {
        let conv = r#"
<KMIP>
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion> <BatchCount type="Integer" value="1"/>
  </RequestHeader> <BatchItem>
    <Operation type="Enumeration"                                   value="Register"/>
     <RequestPayload>
      <ObjectType type="Enumeration" value="SecretData"/>
      <TemplateAttribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>       
          <AttributeValue type="Integer" value="Verify"/>
        </Attribute>
      </TemplateAttribute>
      <SecretData>
        <SecretDataType type="Enumeration"                          value="Password"/>
         <KeyBlock>
           <KeyFormatType type="Enumeration"                         value="Opaque"/>
            <KeyValue>
              <KeyMaterial type="ByteString"                          value="53656372657450617373776f7264"/>
            </KeyValue>
        </KeyBlock>
      </SecretData>
    </RequestPayload>
  </BatchItem>
</RequestMessage>
<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="2010-02-15T10:41:21+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Register"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString"                           value="$UNIQUE_IDENTIFIER_0"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Destroy"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString"                           value="$UNIQUE_IDENTIFIER_0"/>
    </RequestPayload>
  </BatchItem>
</RequestMessage>
<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="0"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="2010-02-15T10:41:21+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Destroy"/>
   <ResultStatus type="Enumeration" value="Success"/>

   <ResponsePayload>
      <UniqueIdentifier type="TextString"                           value="$UNIQUE_IDENTIFIER_0"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>"#;

run_e2e_xml_conversation(conv);
}

  } // mod tests
