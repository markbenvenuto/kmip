use aes::{Aes128, Aes192, Aes256};
use block_padding::{NoPadding, Pkcs7};
use crypto_common::KeyIvInit;
use digest::{FixedOutput, Update};
use hmac::{EagerHash, Hmac, KeyInit};
use kmip_protocol::{BlockCipherMode, CryptographicAlgorithm, PaddingMethod, ValidityIndicator};
use sha2::{Sha224, Sha256, Sha384, Sha512};

use crate::{KmipResponseError, RngSource};

pub mod rng;

fn get_iv(
    required_iv_size: usize,
    nonce: &Option<Vec<u8>>,
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
        None => match random_iv {
            true => Ok(rng_source.generate(required_iv_size)),
            false => Err(KmipResponseError::new("Missing IV")),
        },
    }
}

fn do_encrypt<E>(
    encryptor: E,
    padding: PaddingMethod,
    data: &[u8],
) -> Result<Vec<u8>, KmipResponseError>
where
    E: cbc::cipher::BlockModeEncrypt,
{
    match padding {
        PaddingMethod::PKCS5 => Ok(encryptor.encrypt_padded_vec::<Pkcs7>(data)),
        PaddingMethod::None => {
            if data.len() % 16 != 0 {
                return Err(KmipResponseError::new(
                    "Data length must be a multiple of 16 bytes when using NoPadding",
                ));
            }
            Ok(encryptor.encrypt_padded_vec::<NoPadding>(data))
        }
        _ => Err(KmipResponseError::new("Padding method not supported")),
    }
}

fn do_decrypt<D>(
    decryptor: D,
    padding: PaddingMethod,
    data: &[u8],
) -> Result<Vec<u8>, KmipResponseError>
where
    D: cbc::cipher::BlockModeDecrypt,
{
    match padding {
        PaddingMethod::PKCS5 => decryptor
            .decrypt_padded_vec::<Pkcs7>(data)
            .map_err(|_| KmipResponseError::new("PKCS7 unpadding failed: invalid padding")),
        PaddingMethod::None => decryptor
            .decrypt_padded_vec::<NoPadding>(data)
            .map_err(|_| KmipResponseError::new("Decryption failed")),
        _ => Err(KmipResponseError::new("Padding method not supported")),
    }
}

pub fn encrypt_aes(
    algo: CryptographicAlgorithm,
    mode: BlockCipherMode,
    padding: PaddingMethod,
    key: &[u8],
    data: &[u8],
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, KmipResponseError> {
    match algo {
        CryptographicAlgorithm::AES => match mode {
            BlockCipherMode::CBC => {
                let iv = iv.ok_or_else(|| KmipResponseError::new("CBC mode requires an IV"))?;
                match key.len() {
                    16 => do_encrypt(
                        cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
                            .map_err(|_| KmipResponseError::new("Invalid key or IV size"))?,
                        padding,
                        data,
                    ),
                    24 => do_encrypt(
                        cbc::Encryptor::<Aes192>::new_from_slices(key, iv)
                            .map_err(|_| KmipResponseError::new("Invalid key or IV size"))?,
                        padding,
                        data,
                    ),
                    32 => do_encrypt(
                        cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
                            .map_err(|_| KmipResponseError::new("Invalid key or IV size"))?,
                        padding,
                        data,
                    ),
                    _ => Err(KmipResponseError::new("Invalid AES key size")),
                }
            }
            BlockCipherMode::ECB => match key.len() {
                16 => do_encrypt(
                    ecb::Encryptor::<Aes128>::new_from_slice(key)
                        .map_err(|_| KmipResponseError::new("Invalid AES key size"))?,
                    padding,
                    data,
                ),
                24 => do_encrypt(
                    ecb::Encryptor::<Aes192>::new_from_slice(key)
                        .map_err(|_| KmipResponseError::new("Invalid AES key size"))?,
                    padding,
                    data,
                ),
                32 => do_encrypt(
                    ecb::Encryptor::<Aes256>::new_from_slice(key)
                        .map_err(|_| KmipResponseError::new("Invalid AES key size"))?,
                    padding,
                    data,
                ),
                _ => Err(KmipResponseError::new("Invalid AES key size")),
            },
            _ => Err(KmipResponseError::new("Block cipher mode not supported")),
        },
        _ => Err(KmipResponseError::new("Algorithm not supported")),
    }
}

pub fn decrypt_aes(
    algo: CryptographicAlgorithm,
    mode: BlockCipherMode,
    padding: PaddingMethod,
    key: &[u8],
    data: &[u8],
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, KmipResponseError> {
    match algo {
        CryptographicAlgorithm::AES => match mode {
            BlockCipherMode::CBC => {
                let iv = iv.ok_or_else(|| KmipResponseError::new("CBC mode requires an IV"))?;
                match key.len() {
                    16 => do_decrypt(
                        cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                            .map_err(|_| KmipResponseError::new("Invalid key or IV size"))?,
                        padding,
                        data,
                    ),
                    24 => do_decrypt(
                        cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
                            .map_err(|_| KmipResponseError::new("Invalid key or IV size"))?,
                        padding,
                        data,
                    ),
                    32 => do_decrypt(
                        cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                            .map_err(|_| KmipResponseError::new("Invalid key or IV size"))?,
                        padding,
                        data,
                    ),
                    _ => Err(KmipResponseError::new("Invalid AES key size")),
                }
            }
            BlockCipherMode::ECB => match key.len() {
                16 => do_decrypt(
                    ecb::Decryptor::<Aes128>::new_from_slice(key)
                        .map_err(|_| KmipResponseError::new("Invalid AES key size"))?,
                    padding,
                    data,
                ),
                24 => do_decrypt(
                    ecb::Decryptor::<Aes192>::new_from_slice(key)
                        .map_err(|_| KmipResponseError::new("Invalid AES key size"))?,
                    padding,
                    data,
                ),
                32 => do_decrypt(
                    ecb::Decryptor::<Aes256>::new_from_slice(key)
                        .map_err(|_| KmipResponseError::new("Invalid AES key size"))?,
                    padding,
                    data,
                ),
                _ => Err(KmipResponseError::new("Invalid AES key size")),
            },
            _ => Err(KmipResponseError::new("Block cipher mode not supported")),
        },
        _ => Err(KmipResponseError::new("Algorithm not supported")),
    }
}

pub fn encrypt_block_cipher(
    algo: CryptographicAlgorithm,
    block_cipher_mode: BlockCipherMode,
    padding_method: PaddingMethod,
    key: &[u8],
    data: &[u8],
    nonce: &Option<Vec<u8>>,
    random_iv: bool,
    rng_source: &dyn RngSource,
) -> Result<(Vec<u8>, Option<Vec<u8>>), KmipResponseError> {
    let (iv, returned_iv) = match block_cipher_mode {
        BlockCipherMode::CBC => {
            let iv = get_iv(16, nonce, random_iv, rng_source)?;
            let returned = if random_iv { Some(iv.clone()) } else { None };
            (Some(iv), returned)
        }
        _ => (None, None),
    };

    let ciphertext = encrypt_aes(algo, block_cipher_mode, padding_method, key, data, iv.as_deref())?;
    Ok((ciphertext, returned_iv))
}

pub fn decrypt_block_cipher(
    algo: CryptographicAlgorithm,
    block_cipher_mode: BlockCipherMode,
    padding_method: PaddingMethod,
    key: &[u8],
    data: &[u8],
    nonce: &Option<Vec<u8>>,
) -> Result<Vec<u8>, KmipResponseError> {
    let iv = match block_cipher_mode {
        BlockCipherMode::CBC => Some(
            nonce
                .as_deref()
                .ok_or_else(|| KmipResponseError::new("CBC mode requires an IV"))?,
        ),
        _ => None,
    };

    decrypt_aes(algo, block_cipher_mode, padding_method, key, data, iv)
}

fn do_hmac<D>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, KmipResponseError>
where
    D: EagerHash,
{
    let mut mac = Hmac::<D>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);

    let result = mac.finalize_fixed();
    Ok(result.to_vec())
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
    D: EagerHash,
{
    let mut mac = Hmac::<D>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);

    Ok(hmac::Mac::verify_slice(mac, mac_data)
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
