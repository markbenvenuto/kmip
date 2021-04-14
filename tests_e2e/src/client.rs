#[cfg(test)]
mod tests {

    use protocol::*;

    use crate::util::run_e2e_client_test;

    extern crate kmip_client;
    extern crate kmip_server;

    #[test]
    fn test_create_revoke_client() {
        run_e2e_client_test(4, |mut client| {
            let resp = client
                .create_symmetric_key(CryptographicAlgorithm::AES, 128)
                .unwrap();

            eprintln!("{:?}", resp);

            let get = client.get(&resp.unique_identifier).unwrap();

            assert_eq! {get.object_type, ObjectTypeEnum::SymmetricKey};

            let _revoke = client
                .revoke(
                    &resp.unique_identifier,
                    RevocationReason {
                        revocation_reason_code: RevocationReasonCode::CessationofOperation,
                        revocation_message: None,
                    },
                )
                .unwrap();

            let _destroy = client.destroy(&resp.unique_identifier).unwrap();
        });
    }

    #[test]
    fn test_preactive_destory() {
        run_e2e_client_test(3, |mut client| {
            let resp = client
                .create_symmetric_key(CryptographicAlgorithm::AES, 128)
                .unwrap();

            let get = client.get(&resp.unique_identifier).unwrap();

            assert_eq! {get.object_type, ObjectTypeEnum::SymmetricKey};

            let _destroy = client.destroy(&resp.unique_identifier).unwrap();
        });
    }

    #[test]
    fn test_negative_active_destory() {
        run_e2e_client_test(4, |mut client| {
            let resp = client
                .create_symmetric_key(CryptographicAlgorithm::AES, 128)
                .unwrap();

            let get = client.get(&resp.unique_identifier).unwrap();

            assert_eq! {get.object_type, ObjectTypeEnum::SymmetricKey};

            let _activate = client.activate(&resp.unique_identifier).unwrap();

            let destroy = client.destroy(&resp.unique_identifier);
            assert!(destroy.is_err());
        });
    }
}
