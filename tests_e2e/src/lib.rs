
#[macro_use]
extern crate lazy_static;

mod client;
mod util;

#[cfg(test)]
mod tests {

    use std::{
        sync::Arc,
    };

    use kmip_server::{
        process_kmip_request, store::KmipStore, RequestContext, ServerContext,
        TestClockSource,
    };

    use crate::util::{run_e2e_client_test, run_e2e_xml_conversation};

    extern crate kmip_client;
    extern crate kmip_server;

    #[test]
    fn test_10_create() {
        let clock_source = Arc::new(TestClockSource::new());
        let store = Arc::new(KmipStore::new_mem(clock_source.clone()));

        let server_context = ServerContext::new(store, clock_source);

        let mut rc = RequestContext::new(&server_context);

        // From 1.0 test case, 3.1.1
        let bytes = hex::decode("42007801000001204200770100000038420069010000002042006A0200000004000000010000000042006B0200000004000000000000000042000D0200000004000000010000000042000F01000000D842005C0500000004000000010000000042007901000000C04200570500000004000000020000000042009101000000A8420008010000003042000A070000001743727970746F6772617068696320416C676F726974686D0042000B05000000040000000300000000420008010000003042000A070000001443727970746F67726170686963204C656E6774680000000042000B02000000040000008000000000420008010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B02000000040000000C00000000").unwrap();

        let resp = process_kmip_request(&mut rc, bytes.as_slice());

        protocol::to_print(resp.as_slice());

        println!("Hello");
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
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Register"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString"                           value="1"/>
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
      <UniqueIdentifier type="TextString"                           value="1"/>
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
      <UniqueIdentifier type="TextString"                           value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>"#;

        run_e2e_xml_conversation(conv);
    }

    // TODO - create key generates a random key and therefore this test never passes
    #[test]
    fn e2e_test_xml_cs_bc_m_1_14() {
        let conv = r#"
<KMIP>

<!--
     Key Management Interoperability Protocol Profiles Version 1.4
     OASIS Standard
     22 November 2017
     Copyright (c) OASIS Open 2017. All Rights Reserved.
     Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
     Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
     TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
-->
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
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
        <Attribute>
          <AttributeName type="TextString" value="Name"/>
          <AttributeValue>
            <NameValue type="TextString" value="CS-BC-M-1-14"/>
            <NameType type="Enumeration" value="UninterpretedTextString"/>
          </AttributeValue>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Parameters"/>
          <AttributeValue>
            <BlockCipherMode type="Enumeration" value="ECB"/>
          </AttributeValue>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Activation Date"/>
          <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        </Attribute>
      </TemplateAttribute>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
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
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Encrypt"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <Data type="ByteString" value="01020304050607080910111213141516"/>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Encrypt"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <Data type="ByteString" value="fd912d102dbb482f6f6e91bd57119095"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Revoke"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <RevocationReason>
        <RevocationReasonCode type="Enumeration" value="Unspecified"/>
      </RevocationReason>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Revoke"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
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
      <ProtocolVersionMinor type="Integer" value="4"/>
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

        // TODO - fix me run_e2e_xml_conversation(conv);
    }

    // Tests Register + Encryption
    #[test]
    fn e2e_test_xml_cs_bc_m_4_14() {
        let conv = r#"
    <KMIP>

<!--
     Key Management Interoperability Protocol Profiles Version 1.4
     OASIS Standard
     22 November 2017
     Copyright (c) OASIS Open 2017. All Rights Reserved.
     Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
     Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
     TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
-->
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Register"/>
    <RequestPayload>
      <ObjectType type="Enumeration" value="SymmetricKey"/>
      <TemplateAttribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
          <AttributeValue type="Integer" value="Encrypt Decrypt"/>
        </Attribute>
        <!-- <Attribute>
          <AttributeName type="TextString" value="x-ID"/>
          <AttributeValue type="TextString" value="CS-BC-M-4-14"/>
        </Attribute> -->
        <Attribute>
          <AttributeName type="TextString" value="Activation Date"/>
          <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        </Attribute>
      </TemplateAttribute>
      <SymmetricKey>
        <KeyBlock>
          <KeyFormatType type="Enumeration" value="Raw"/>
          <KeyValue>
            <KeyMaterial type="ByteString" value="0123456789abcdef0123456789abcdef"/>
          </KeyValue>
          <CryptographicAlgorithm type="Enumeration" value="AES"/>
          <CryptographicLength type="Integer" value="128"/>
        </KeyBlock>
      </SymmetricKey>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Register"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Encrypt"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <CryptographicParameters>
        <BlockCipherMode type="Enumeration" value="ECB"/>
      </CryptographicParameters>
      <Data type="ByteString" value="01020304050607080910111213141516"/>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Encrypt"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <Data type="ByteString" value="d9bcce11b0b437b90239552df3a360c9"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Revoke"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <RevocationReason>
        <RevocationReasonCode type="Enumeration" value="Unspecified"/>
      </RevocationReason>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Revoke"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
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
      <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Tests Register + Decryption
    #[test]
    fn e2e_test_xml_cs_bc_m_5_14() {
        let conv = r#"
    <KMIP>

    <!--
         Key Management Interoperability Protocol Profiles Version 1.4
         OASIS Standard
         22 November 2017
         Copyright (c) OASIS Open 2017. All Rights Reserved.
         Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
         Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
         TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
    -->
    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
        <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <RequestPayload>
          <ObjectType type="Enumeration" value="SymmetricKey"/>
          <TemplateAttribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
              <AttributeValue type="Integer" value="Encrypt Decrypt"/>
            </Attribute>
            <!-- <Attribute>
              <AttributeName type="TextString" value="x-ID"/>
              <AttributeValue type="TextString" value="CS-BC-M-5-14"/>
            </Attribute> -->
            <Attribute>
              <AttributeName type="TextString" value="Activation Date"/>
              <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
            </Attribute>
          </TemplateAttribute>
          <SymmetricKey>
            <KeyBlock>
              <KeyFormatType type="Enumeration" value="Raw"/>
              <KeyValue>
                <KeyMaterial type="ByteString" value="0123456789abcdef0123456789abcdef"/>
              </KeyValue>
              <CryptographicAlgorithm type="Enumeration" value="AES"/>
              <CryptographicLength type="Integer" value="128"/>
            </KeyBlock>
          </SymmetricKey>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Decrypt"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <CryptographicParameters>
            <BlockCipherMode type="Enumeration" value="ECB"/>
          </CryptographicParameters>
          <Data type="ByteString" value="d9bcce11b0b437b90239552df3a360c9"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Decrypt"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Data type="ByteString" value="01020304050607080910111213141516"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <RevocationReason>
            <RevocationReasonCode type="Enumeration" value="Unspecified"/>
          </RevocationReason>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Register + MAC
    #[test]
    fn e2e_test_xml_cs_ac_m_4_14() {
        let conv = r#"
    <KMIP>

    <!--
         Key Management Interoperability Protocol Profiles Version 1.4
         OASIS Standard
         22 November 2017
         Copyright (c) OASIS Open 2017. All Rights Reserved.
         Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
         Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
         TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
    -->
    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <RequestPayload>
          <ObjectType type="Enumeration" value="SymmetricKey"/>
          <TemplateAttribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
              <AttributeValue type="Integer" value="Encrypt Decrypt MACGenerate MACVerify"/>
            </Attribute>
            <!--<Attribute>
              <AttributeName type="TextString" value="x-ID"/>
              <AttributeValue type="TextString" value="CS-AC-M-4-14"/>
            </Attribute>-->
            <Attribute>
              <AttributeName type="TextString" value="Activation Date"/>
              <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
            </Attribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Parameters"/>
              <AttributeValue>
                <CryptographicAlgorithm type="Enumeration" value="HMAC_SHA256"/>
              </AttributeValue>
            </Attribute>
          </TemplateAttribute>
          <SymmetricKey>
            <KeyBlock>
              <KeyFormatType type="Enumeration" value="Raw"/>
              <KeyValue>
                <KeyMaterial type="ByteString" value="0123456789abcdef0123456789abcdef"/>
              </KeyValue>
              <CryptographicAlgorithm type="Enumeration" value="AES"/>
              <CryptographicLength type="Integer" value="128"/>
            </KeyBlock>
          </SymmetricKey>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="MAC"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Data type="ByteString" value="01020304050607080910111213141516"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="MAC"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <MACData type="ByteString" value="c911e78196d64c30f631bb079ea37b97a95936d4da764d6a171df030c895ecf9"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <RevocationReason>
            <RevocationReasonCode type="Enumeration" value="Unspecified"/>
          </RevocationReason>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Register + MAC Verfiy
    #[test]
    fn e2e_test_xml_cs_ac_m_5_14() {
        let conv = r#"
        <KMIP>

<!--
     Key Management Interoperability Protocol Profiles Version 1.4
     OASIS Standard
     22 November 2017
     Copyright (c) OASIS Open 2017. All Rights Reserved.
     Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
     Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
     TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
-->
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Register"/>
    <RequestPayload>
      <ObjectType type="Enumeration" value="SymmetricKey"/>
      <TemplateAttribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
          <AttributeValue type="Integer" value="Encrypt Decrypt MACGenerate MACVerify"/>
        </Attribute>
        <!--<Attribute>
          <AttributeName type="TextString" value="x-ID"/>
          <AttributeValue type="TextString" value="CS-AC-M-5-14"/>
        </Attribute>-->
        <Attribute>
          <AttributeName type="TextString" value="Activation Date"/>
          <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        </Attribute>
        <Attribute>
          <AttributeName type="TextString" value="Cryptographic Parameters"/>
          <AttributeValue>
            <CryptographicAlgorithm type="Enumeration" value="HMAC_SHA256"/>
          </AttributeValue>
        </Attribute>
      </TemplateAttribute>
      <SymmetricKey>
        <KeyBlock>
          <KeyFormatType type="Enumeration" value="Raw"/>
          <KeyValue>
            <KeyMaterial type="ByteString" value="0123456789abcdef0123456789abcdef"/>
          </KeyValue>
          <CryptographicAlgorithm type="Enumeration" value="AES"/>
          <CryptographicLength type="Integer" value="128"/>
        </KeyBlock>
      </SymmetricKey>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Register"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="MACVerify"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <Data type="ByteString" value="01020304050607080910111213141516"/>
      <MACData type="ByteString" value="c911e78196d64c30f631bb079ea37b97a95936d4da764d6a171df030c895ecf9"/>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="MACVerify"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <ValidityIndicator type="Enumeration" value="Valid"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Revoke"/>
    <RequestPayload>
      <UniqueIdentifier type="TextString" value="1"/>
      <RevocationReason>
        <RevocationReasonCode type="Enumeration" value="Unspecified"/>
      </RevocationReason>
    </RequestPayload>
  </BatchItem>
</RequestMessage>

<ResponseMessage>
  <ResponseHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
    </ProtocolVersion>
    <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
    <BatchCount type="Integer" value="1"/>
  </ResponseHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Revoke"/>
    <ResultStatus type="Enumeration" value="Success"/>
    <ResponsePayload>
      <UniqueIdentifier type="TextString" value="1"/>
    </ResponsePayload>
  </BatchItem>
</ResponseMessage>

<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="1"/>
      <ProtocolVersionMinor type="Integer" value="4"/>
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
      <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Create + GetAttributes
    //  https://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/SKLC-M-1-14.xml
    #[test]
    fn e2e_test_xml_sklc_m_1_14() {
        /*
        *           <!-- TODO - add digest support <Attribute>
             <AttributeName type="TextString" value="Digest"/>
             <AttributeValue>
               <HashingAlgorithm type="Enumeration" value="SHA_256"/>
               <DigestValue type="ByteString" value="bc12861408b8ac72cdb3b2748ad342b7dc519bd109046a1b931fdaed73591f29"/>
               <KeyFormatType type="Enumeration" value="Raw"/>
             </AttributeValue>
           </Attribute> -->
        */
        let conv = r#"
    #"
    <KMIP>

    <!--
         Key Management Interoperability Protocol Profiles Version 1.4
         OASIS Standard
         22 November 2017
         Copyright (c) OASIS Open 2017. All Rights Reserved.
         Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
         Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
         TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
    -->
    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
              <AttributeValue type="Integer" value="256"/>
            </Attribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
              <AttributeValue type="Integer" value="Encrypt Decrypt"/>
            </Attribute>
            <Attribute>
              <AttributeName type="TextString" value="Name"/>
              <AttributeValue>
                <NameValue type="TextString" value="SKLC-M-1-14"/>
                <NameType type="Enumeration" value="UninterpretedTextString"/>
              </AttributeValue>
            </Attribute>
          </TemplateAttribute>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <AttributeName type="TextString" value="State"/>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
          <AttributeName type="TextString" value="Unique Identifier"/>
          <AttributeName type="TextString" value="Object Type"/>
          <AttributeName type="TextString" value="Cryptographic Algorithm"/>
          <AttributeName type="TextString" value="Cryptographic Length"/>
          <AttributeName type="TextString" value="Digest"/>
          <AttributeName type="TextString" value="Initial Date"/>
          <AttributeName type="TextString" value="Last Change Date"/>
          <AttributeName type="TextString" value="Activation Date"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Attribute>
            <AttributeName type="TextString" value="State"/>
            <AttributeValue type="Enumeration" value="PreActive"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
            <AttributeValue type="Integer" value="12"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Unique Identifier"/>
            <AttributeValue type="TextString" value="1"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Object Type"/>
            <AttributeValue type="Enumeration" value="SymmetricKey"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Cryptographic Algorithm"/>
            <AttributeValue type="Enumeration" value="AES"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Cryptographic Length"/>
            <AttributeValue type="Integer" value="256"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Initial Date"/>
            <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Last Change Date"/>
            <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
          </Attribute>

        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Create + Destroy + Revoke
    //  https://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/SKLC-M-2-14.xml
    #[test]
    fn e2e_test_xml_sklc_m_2_14() {
        /*
           <Attribute>
             <AttributeName type="TextString" value="Digest"/>
             <AttributeValue>
               <HashingAlgorithm type="Enumeration" value="SHA_256"/>
               <DigestValue type="ByteString" value="bc12861408b8ac72cdb3b2748ad342b7dc519bd109046a1b931fdaed73591f29"/>
               <KeyFormatType type="Enumeration" value="Raw"/>
             </AttributeValue>
           </Attribute>
        */
        let conv = r#"
    #"
    <KMIP>

    <!--
         Key Management Interoperability Protocol Profiles Version 1.4
         OASIS Standard
         22 November 2017
         Copyright (c) OASIS Open 2017. All Rights Reserved.
         Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
         Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
         TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
    -->
    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
              <AttributeValue type="Integer" value="256"/>
            </Attribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
              <AttributeValue type="Integer" value="Encrypt Decrypt"/>
            </Attribute>
            <Attribute>
              <AttributeName type="TextString" value="Name"/>
              <AttributeValue>
                <NameValue type="TextString" value="SKLC-M-2-14"/>
                <NameType type="Enumeration" value="UninterpretedTextString"/>
              </AttributeValue>
            </Attribute>
          </TemplateAttribute>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <AttributeName type="TextString" value="State"/>
          <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
          <AttributeName type="TextString" value="Unique Identifier"/>
          <AttributeName type="TextString" value="Object Type"/>
          <AttributeName type="TextString" value="Cryptographic Algorithm"/>
          <AttributeName type="TextString" value="Cryptographic Length"/>
          <AttributeName type="TextString" value="Digest"/>
          <AttributeName type="TextString" value="Initial Date"/>
          <AttributeName type="TextString" value="Last Change Date"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Attribute>
            <AttributeName type="TextString" value="State"/>
            <AttributeValue type="Enumeration" value="PreActive"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
            <AttributeValue type="Integer" value="12"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Unique Identifier"/>
            <AttributeValue type="TextString" value="1"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Object Type"/>
            <AttributeValue type="Enumeration" value="SymmetricKey"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Cryptographic Algorithm"/>
            <AttributeValue type="Enumeration" value="AES"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Cryptographic Length"/>
            <AttributeValue type="Integer" value="256"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Initial Date"/>
            <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Last Change Date"/>
            <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
          </Attribute>

        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Activate"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Activate"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <AttributeName type="TextString" value="State"/>
          <AttributeName type="TextString" value="Activation Date"/>
          <AttributeName type="TextString" value="Deactivation Date"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Attribute>
            <AttributeName type="TextString" value="State"/>
            <AttributeValue type="Enumeration" value="Active"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Activation Date"/>
            <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
          </Attribute>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Destroy"/>
        <ResultStatus type="Enumeration" value="OperationFailed"/>
        <ResultReason type="Enumeration" value="PermissionDenied"/>
        <ResultMessage type="TextString" value="DENIED"/>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <RevocationReason>
            <RevocationReasonCode type="Enumeration" value="KeyCompromise"/>
          </RevocationReason>
          <CompromiseOccurrenceDate type="DateTime" value="1970-01-01T00:00:06+00:00"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <AttributeName type="TextString" value="State"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="GetAttributes"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Attribute>
            <AttributeName type="TextString" value="State"/>
            <AttributeValue type="Enumeration" value="Compromised"/>
          </Attribute>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Register + Ecb + PKCS5
    //  https://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/CS-BC-M-8-14.xml
    #[test]
    fn e2e_test_xml_cs_bc_m_8_14() {
        let conv = r#"
    #"
    <KMIP>

    <!--
         Key Management Interoperability Protocol Profiles Version 1.4
         OASIS Standard
         22 November 2017
         Copyright (c) OASIS Open 2017. All Rights Reserved.
         Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
         Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
         TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
    -->
    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <RequestPayload>
          <ObjectType type="Enumeration" value="SymmetricKey"/>
          <TemplateAttribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
              <AttributeValue type="Integer" value="Encrypt Decrypt"/>
            </Attribute>
            <!--<Attribute>
              <AttributeName type="TextString" value="x-ID"/>
              <AttributeValue type="TextString" value="CS-BC-M-8-14"/>
            </Attribute>-->
            <Attribute>
              <AttributeName type="TextString" value="Activation Date"/>
              <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
            </Attribute>
          </TemplateAttribute>
          <SymmetricKey>
            <KeyBlock>
              <KeyFormatType type="Enumeration" value="Raw"/>
              <KeyValue>
                <KeyMaterial type="ByteString" value="0123456789abcdef0123456789abcdef"/>
              </KeyValue>
              <CryptographicAlgorithm type="Enumeration" value="AES"/>
              <CryptographicLength type="Integer" value="128"/>
            </KeyBlock>
          </SymmetricKey>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Encrypt"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <CryptographicParameters>
      <BlockCipherMode type="Enumeration" value="ECB"/>
      <PaddingMethod type="Enumeration" value="PKCS5"/>
          </CryptographicParameters>
          <Data type="ByteString" value="01020304050607080910111213141516"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Encrypt"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Data type="ByteString" value="d9bcce11b0b437b90239552df3a360c90efb6bfed93b4d1ea2123ba4db075ff6"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Decrypt"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <CryptographicParameters>
      <BlockCipherMode type="Enumeration" value="ECB"/>
      <PaddingMethod type="Enumeration" value="PKCS5"/>
          </CryptographicParameters>
          <Data type="ByteString" value="d9bcce11b0b437b90239552df3a360c90efb6bfed93b4d1ea2123ba4db075ff6"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Decrypt"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Data type="ByteString" value="01020304050607080910111213141516"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <RevocationReason>
            <RevocationReasonCode type="Enumeration" value="Unspecified"/>
          </RevocationReason>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
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

    // Register + Cbc + PKCS5
    //  https://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/CS-BC-M-10-14.xml
    #[test]
    fn e2e_test_xml_cs_bc_m_10_14() {
        let conv = r#"
    #"
    <KMIP>

    <!--
         Key Management Interoperability Protocol Profiles Version 1.4
         OASIS Standard
         22 November 2017
         Copyright (c) OASIS Open 2017. All Rights Reserved.
         Source: http://docs.oasis-open.org/kmip/profiles/v1.4/os/test-cases/kmip-v1.4/mandatory/
         Latest version of the specification: http://docs.oasis-open.org/kmip/profiles/v1.4/kmip-profiles-v1.4.html
         TC IPR Statement: https://www.oasis-open.org/committees/kmip/ipr.php
    -->
    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <RequestPayload>
          <ObjectType type="Enumeration" value="SymmetricKey"/>
          <TemplateAttribute>
            <Attribute>
              <AttributeName type="TextString" value="Cryptographic Usage Mask"/>
              <AttributeValue type="Integer" value="Encrypt Decrypt"/>
            </Attribute>
            <!--<Attribute>
              <AttributeName type="TextString" value="x-ID"/>
              <AttributeValue type="TextString" value="CS-BC-M-10-14"/>
            </Attribute>-->
            <Attribute>
              <AttributeName type="TextString" value="Activation Date"/>
              <AttributeValue type="DateTime" value="1970-01-01T00:02:03+00:00"/>
            </Attribute>
          </TemplateAttribute>
          <SymmetricKey>
            <KeyBlock>
              <KeyFormatType type="Enumeration" value="Raw"/>
              <KeyValue>
                <KeyMaterial type="ByteString" value="0123456789abcdef0123456789abcdef"/>
              </KeyValue>
              <CryptographicAlgorithm type="Enumeration" value="AES"/>
              <CryptographicLength type="Integer" value="128"/>
            </KeyBlock>
          </SymmetricKey>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Register"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Encrypt"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <CryptographicParameters>
      <BlockCipherMode type="Enumeration" value="CBC"/>
      <PaddingMethod type="Enumeration" value="PKCS5"/>
          </CryptographicParameters>
          <Data type="ByteString" value="010203040506070809101112131415160102030405060708091011121314151601"/>
          <IVCounterNonce type="ByteString" value="01020304050607080910111213141516"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Encrypt"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Data type="ByteString" value="79abc5c23868ad84d388ce61110a62742bda19d694bbcb757dd06617c0d80fb1df2e71864ad9633d7d797e30860df00d"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Decrypt"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <CryptographicParameters>
      <BlockCipherMode type="Enumeration" value="CBC"/>
      <PaddingMethod type="Enumeration" value="PKCS5"/>
          </CryptographicParameters>
          <Data type="ByteString" value="79abc5c23868ad84d388ce61110a62742bda19d694bbcb757dd06617c0d80fb1df2e71864ad9633d7d797e30860df00d"/>
          <IVCounterNonce type="ByteString" value="01020304050607080910111213141516"/>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Decrypt"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <Data type="ByteString" value="010203040506070809101112131415160102030405060708091011121314151601"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
      </RequestHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="1"/>
          <RevocationReason>
            <RevocationReasonCode type="Enumeration" value="Unspecified"/>
          </RevocationReason>
        </RequestPayload>
      </BatchItem>
    </RequestMessage>

    <ResponseMessage>
      <ResponseHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
        </ProtocolVersion>
        <TimeStamp type="DateTime" value="1970-01-01T00:02:03+00:00"/>
        <BatchCount type="Integer" value="1"/>
      </ResponseHeader>
      <BatchItem>
        <Operation type="Enumeration" value="Revoke"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="1"/>
        </ResponsePayload>
      </BatchItem>
    </ResponseMessage>

    <RequestMessage>
      <RequestHeader>
        <ProtocolVersion>
          <ProtocolVersionMajor type="Integer" value="1"/>
          <ProtocolVersionMinor type="Integer" value="4"/>
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
          <ProtocolVersionMinor type="Integer" value="4"/>
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
} // mod tests
