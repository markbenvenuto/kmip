use protocol::{BlockCipherMode, CryptographicAlgorithm, PaddingMethod, ValidityIndicator};
use serde_bytes::ByteBuf;

use crate::{KmipResponseError, RngSource};

use aes::{Aes128, Aes192, Aes256};
use block_modes::block_padding::{NoPadding, Pkcs7};
use block_modes::{BlockMode, Cbc, Ecb};

use crypto_mac::generic_array::ArrayLength;
use digest::{BlockInput, FixedOutput, Reset, Update};

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;

pub mod rng;

macro_rules! encrypt_cipher_mode {
    ($cipher: ty, $mode:ident, $padd: ident, $iv : expr, $data: ident, $key : ident) => {
        match $padd {
            PaddingMethod::None => {
                // TODO - check room for padding
                type CipherAndMode = $mode<$cipher, NoPadding>;
                let cipher = CipherAndMode::new_var($key, $iv).expect("Wrong key size");
                Ok((cipher.encrypt_vec($data), None))
            }
            PaddingMethod::PKCS5 => {
                // TODO - allocate room for padding, unsure what KMIP requres
                // Pkcs7 is a more general version of Pkcs5
                type CipherAndMode = $mode<$cipher, Pkcs7>;
                let cipher = CipherAndMode::new_var($key, $iv).expect("Wrong key size");
                Ok((cipher.encrypt_vec($data), None))
            }
            _ => Err(KmipResponseError::new(
                "Cipher and padding is not supported",
            )),
        }
    };
}

fn get_iv(
    required_iv_size: usize,
    nonce: &Option<ByteBuf>,
    random_iv: bool,
    rng_source: &dyn RngSource,
) -> Result<Vec<u8>, KmipResponseError> {
    match nonce {
        Some(bytes) => {
            if bytes.len() != required_iv_size {
                return Err(KmipResponseError::new(&format!(
                    "Wrong IV size {}, expected {}",
                    bytes.len(),
                    required_iv_size
                )));
            }

            Ok(bytes.to_vec())
        }
        None => {
            match random_iv {
                true => {
                    // Generate IV
                    Ok(rng_source.gen(required_iv_size))
                }
                false => Err(KmipResponseError::new("Missing IV")),
            }
        }
    }
}

pub fn encrypt_block_cipher(
    algo: CryptographicAlgorithm,
    block_cipher_mode: BlockCipherMode,
    padding_method: PaddingMethod,
    key: &[u8],
    data: &[u8],
    nonce: &Option<ByteBuf>,
    random_iv: bool,
    rng_source: &dyn RngSource,
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmipResponseError> {
    match algo {
        CryptographicAlgorithm::AES => {
            if key.len() == 16 {
                // AES 128
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        encrypt_cipher_mode!(
                            Aes128,
                            Ecb,
                            padding_method,
                            Default::default(),
                            data,
                            key
                        )
                    }
                    BlockCipherMode::CBC => {
                        let iv = get_iv(128 / 8, nonce, random_iv, rng_source)?;

                        encrypt_cipher_mode!(Aes128, Cbc, padding_method, &iv, data, key)
                    }
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                };
            } else if key.len() == 24 {
                // AES 192
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        encrypt_cipher_mode!(
                            Aes192,
                            Ecb,
                            padding_method,
                            Default::default(),
                            data,
                            key
                        )
                    }
                    BlockCipherMode::CBC => {
                        let iv = get_iv(128 / 8, nonce, random_iv, rng_source)?;

                        encrypt_cipher_mode!(Aes192, Cbc, padding_method, &iv, data, key)
                    }
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                };
            } else if key.len() == 32 {
                // AES 256
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        encrypt_cipher_mode!(
                            Aes256,
                            Ecb,
                            padding_method,
                            Default::default(),
                            data,
                            key
                        )
                    }
                    BlockCipherMode::CBC => {
                        let iv = get_iv(128 / 8, nonce, random_iv, rng_source)?;

                        encrypt_cipher_mode!(Aes256, Cbc, padding_method, &iv, data, key)
                    }
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                };
            }

            Ok((Vec::new(), None))
        }

        _ => Err(KmipResponseError::new("Algorithm is not supported")),
    }
}

// macro_rules! decrypt_cipher_mode_padding {
//     ($cipher: ty, $mode:ty, $padd: ty, $data: ident, $key : ident) => {
//         type CipherAndMode = $mode<$cipher, $padd>;
//         // ECB has no nonce
//         let cipher = CipherAndMode::new_var($key, Default::default())
//             .expect("Wrong key size");
//         Ok(cipher.decrypt_vec($data).expect("TODO - add eerror"))

//     };
// }

macro_rules! decrypt_cipher_mode {
    ($cipher: ty, $mode:ident, $padd: ident, $iv : expr, $data: ident, $key : ident) => {
        match $padd {
            PaddingMethod::None => {
                // decrypt_cipher_mode_padding!($cipher, $mode, NoPadding, $data, $key)
                type CipherAndMode = $mode<$cipher, NoPadding>;
                let cipher = CipherAndMode::new_var($key, $iv).expect("Wrong key size");
                Ok(cipher.decrypt_vec($data).expect("TODO - add eerror"))
            }
            PaddingMethod::PKCS5 => {
                // decrypt_cipher_mode_padding!($cipher, $mode, NoPadding, $data, $key)
                // Pkcs7 is a more general version of Pkcs5
                type CipherAndMode = $mode<$cipher, Pkcs7>;
                let cipher = CipherAndMode::new_var($key, $iv).expect("Wrong key size");
                Ok(cipher.decrypt_vec($data).expect("TODO - add eerror"))
            }
            _ => Err(KmipResponseError::new(
                "Cipher and padding is not supported",
            )),
        }
    };
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
                        decrypt_cipher_mode!(
                            Aes128,
                            Ecb,
                            padding_method,
                            Default::default(),
                            data,
                            key
                        )
                    }
                    BlockCipherMode::CBC => {
                        decrypt_cipher_mode!(
                            Aes128,
                            Cbc,
                            padding_method,
                            nonce
                                .as_ref()
                                .ok_or_else(|| KmipResponseError::new("Missing IV"))?
                                .as_ref(),
                            data,
                            key
                        )
                    }
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                };
            } else if key.len() == 24 {
                // AES 192
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        decrypt_cipher_mode!(
                            Aes192,
                            Ecb,
                            padding_method,
                            Default::default(),
                            data,
                            key
                        )
                    }
                    BlockCipherMode::CBC => {
                        decrypt_cipher_mode!(
                            Aes192,
                            Cbc,
                            padding_method,
                            nonce
                                .as_ref()
                                .ok_or_else(|| KmipResponseError::new("Missing IV"))?
                                .as_ref(),
                            data,
                            key
                        )
                    }
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                };
            } else if key.len() == 32 {
                // AES 256
                return match block_cipher_mode {
                    BlockCipherMode::ECB => {
                        decrypt_cipher_mode!(
                            Aes256,
                            Ecb,
                            padding_method,
                            Default::default(),
                            data,
                            key
                        )
                    }
                    BlockCipherMode::CBC => {
                        decrypt_cipher_mode!(
                            Aes256,
                            Cbc,
                            padding_method,
                            nonce
                                .as_ref()
                                .ok_or_else(|| KmipResponseError::new("Missing IV"))?
                                .as_ref(),
                            data,
                            key
                        )
                    }
                    _ => Err(KmipResponseError::new("Cipher Mode is not supported")),
                };
            }

            Ok(Vec::new())
        }

        _ => Err(KmipResponseError::new("Algorithm is not supported")),
    }
}

fn do_hmac<D>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, KmipResponseError>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
{
    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = Hmac::<D>::new_varkey(key).expect("HMAC can take key of any size");
    mac.update(data);

    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes` method, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `Output`
    Ok(result.into_bytes().as_slice().to_vec())
}

pub fn hmac(
    algo: CryptographicAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, KmipResponseError> {
    match algo {
        CryptographicAlgorithm::HMACSHA224 => do_hmac::<Sha224>(key, data),
        CryptographicAlgorithm::HMACSHA256 => do_hmac::<Sha256>(key, data),
        CryptographicAlgorithm::HMACSHA384 => do_hmac::<Sha384>(key, data),
        CryptographicAlgorithm::HMACSHA512 => do_hmac::<Sha512>(key, data),

        _ => Err(KmipResponseError::new(&format!(
            "Algorithm {:?} is not supported",
            algo
        ))),
    }
}

fn do_hmac_verify<D>(
    key: &[u8],
    data: &[u8],
    mac_data: &[u8],
) -> Result<ValidityIndicator, KmipResponseError>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
{
    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = Hmac::<D>::new_varkey(key).expect("HMAC can take key of any size");
    mac.update(data);

    Ok(mac
        .verify(mac_data)
        .map_or(ValidityIndicator::Invalid, |_| ValidityIndicator::Valid))
}

pub fn hmac_verify(
    algo: CryptographicAlgorithm,
    key: &[u8],
    data: &[u8],
    mac_data: &[u8],
) -> Result<ValidityIndicator, KmipResponseError> {
    match algo {
        CryptographicAlgorithm::HMACSHA224 => do_hmac_verify::<Sha224>(key, data, mac_data),
        CryptographicAlgorithm::HMACSHA256 => do_hmac_verify::<Sha256>(key, data, mac_data),
        CryptographicAlgorithm::HMACSHA384 => do_hmac_verify::<Sha384>(key, data, mac_data),
        CryptographicAlgorithm::HMACSHA512 => do_hmac_verify::<Sha512>(key, data, mac_data),

        _ => Err(KmipResponseError::new(&format!(
            "Algorithm {:?} is not supported",
            algo
        ))),
    }
}
