
use chrono::NaiveDateTime;
use chrono::Utc;

use crate::{ClockSource, RngSource};

pub struct TestClockSource {}

impl TestClockSource {
    pub fn new() -> TestClockSource {
        TestClockSource {}
    }
}

impl ClockSource for TestClockSource {
    fn now(&self) -> chrono::DateTime<Utc> {
        chrono::DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(123, 0), Utc)
    }
}

pub struct TestRngSource {}

impl TestRngSource {
    pub fn new() -> TestRngSource {
        TestRngSource {}
    }
}

impl RngSource for TestRngSource {
        fn gen(&self, len: usize) -> Vec<u8> {
            let mut v  = Vec::new();
            v.resize(len, 0);
            v
    }
}
