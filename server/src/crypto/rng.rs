extern crate ring;
use ring::rand::*;

use crate::RngSource;

lazy_static! {
    static ref GLOBAL_RAND: SystemRandom = SystemRandom::new();
}

pub struct SecureRngSource;

impl SecureRngSource {
    pub fn new() -> SecureRngSource {
        SecureRngSource {}
    }
}

impl RngSource for SecureRngSource {
    fn gen(&self, len: usize) -> Vec<u8> {
        let mut a: Vec<u8> = Vec::new();
        a.resize(len, 0);
        GLOBAL_RAND
            .fill(a.as_mut())
            .expect("Random number generator failed");

        a
    }
}