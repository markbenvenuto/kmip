use protocol::{BlockCipherMode, CryptographicAlgorithm, PaddingMethod};
use serde_bytes::ByteBuf;

use crate::KmipResponseError;

use aes::Aes128;
use aes::NewBlockCipher;
use block_modes::block_padding::{NoPadding, Pkcs7};
use block_modes::{BlockMode, Cbc, Ecb};

// fn encrypt_with_padding<T>(
//     padding_method: PaddingMethod,
//     key: &[u8],
//     data: &[u8],
//     nonce: &Option<ByteBuf>) {
// match padding_method

//     }

// fn do_encrypt<T>(
//     key: &[u8],
//     data: &[u8],
//     nonce: &Option<ByteBuf>,
// ) -> Result<(Vec<u8>, Option<Vec<u8>>), KmipResponseError>
// where T : BlockMode<_> {
//     // ECB has no nonce
//     let cipher =
//         T::new_var(key, Default::default()).expect("Wrong key size");
//     Ok((cipher.encrypt_vec(data), None))
// // }


// macro_rules! define_aes_impl {
//     (
//         $name:ident,
//         $key_size:ty,
//         $fixslice_keys:ty,
//         $fixslice_key_schedule:path,
//         $fixslice_decrypt:path,
//         $fixslice_encrypt:path,
//         $doc:expr
//     ) => {
//         #[doc=$doc]
//         #[derive(Clone)]
//         pub struct $name {
//             keys: $fixslice_keys,
//         }
//         impl NewBlockCipher for $name {
//             type KeySize = $key_size;

//             #[inline]
//             fn new(key: &GenericArray<u8, $key_size>) -> Self {
//                 Self { keys: $fixslice_key_schedule(key) }
//             }
//         }

pub fn encrypt_block_cipher(
    algo: CryptographicAlgorithm,
    block_cipher_mode: BlockCipherMode,
    padding_method: PaddingMethod,
    key: &[u8],
    data: &[u8],
    nonce: &Option<ByteBuf>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmipResponseError> {
    match algo {
        CryptographicAlgorithm::AES => {
            if key.len() == 16 {
                // AES 128
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        match padding_method {
                            PaddingMethod::None => {
                                type Aes128Ecb = Ecb<Aes128, NoPadding >;
                                // ECB has no nonce
                                let cipher = Aes128Ecb::new_var(key, Default::default()).expect("Wrong key size");
                                Ok((cipher.encrypt_vec(data), None))
                            },
                            _ => Err(KmipResponseError::new("Ecb and padding is not supported")),
                        }
                    },
                                       
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                }
                
            } else if key.len() == 24 { // AES 192
            } else if key.len() == 32 { // AES 256
            }
            // let x = NewBlockCipher::<Aes128>::KeySize;
            // if key.len() ==  x{

            // }
            // type Aes128Cbc = Cbc<Aes128, Pkcs7>;

            //     let mut buffer = [0u8; 32];
            // // copy message to the buffer
            // let pos = plaintext.len();

            //     buffer[..pos].copy_from_slice(plaintext);
            //     let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
            Ok((Vec::new(), None))
        }

        _ => Err(KmipResponseError::new("Algorithm is not supported")),
    }
}


pub fn decrypt_block_cipher(
    algo: CryptographicAlgorithm,
    block_cipher_mode: BlockCipherMode,
    padding_method: PaddingMethod,
    key: &[u8],
    data: &[u8],
    nonce: &Option<ByteBuf>,
) -> Result<Vec<u8>, KmipResponseError> {
    match algo {
        CryptographicAlgorithm::AES => {
            if key.len() == 16 {
                // AES 128
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        match padding_method {
                            PaddingMethod::None => {
                                type Aes128Ecb = Ecb<Aes128, NoPadding >;
                                // ECB has no nonce
                                let cipher = Aes128Ecb::new_var(key, Default::default()).expect("Wrong key size");
                                Ok(cipher.decrypt_vec(data).expect("TODO - add eerror"))
                            },
                            _ => Err(KmipResponseError::new("Ecb and padding is not supported")),
                        }
                    },
                                       
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                }
                
            } else if key.len() == 24 { // AES 192
            } else if key.len() == 32 { // AES 256
            }
            // let x = NewBlockCipher::<Aes128>::KeySize;
            // if key.len() ==  x{

            // }
            // type Aes128Cbc = Cbc<Aes128, Pkcs7>;

            //     let mut buffer = [0u8; 32];
            // // copy message to the buffer
            // let pos = plaintext.len();

            //     buffer[..pos].copy_from_slice(plaintext);
            //     let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
            Ok(Vec::new())
        }

        _ => Err(KmipResponseError::new("Algorithm is not supported")),
    }
}

use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

pub fn hmac(    algo: CryptographicAlgorithm,
    key: &[u8],
    data: &[u8]) -> Result<Vec<u8>, KmipResponseError>  {

    match algo {
        CryptographicAlgorithm::HMACSHA256 => {
            // Create alias for HMAC-SHA256
            type HmacSha256 = Hmac<Sha256>;
            
            // Create HMAC-SHA256 instance which implements `Mac` trait
            let mut mac = HmacSha256::new_varkey(key)
                .expect("HMAC can take key of any size");
            mac.update(data);
            
            // `result` has type `Output` which is a thin wrapper around array of
            // bytes for providing constant time equality check
            let result = mac.finalize();
            // To get underlying array use `into_bytes` method, but be careful, since
            // incorrect use of the code value may permit timing attacks which defeat
            // the security provided by the `Output`
            Ok(result.into_bytes().as_slice().to_vec())
            // Ok(Vec::new())
        }

        _ => Err(KmipResponseError::new(&format!("Algorithm {:?} is not supported", algo))),
    }

}