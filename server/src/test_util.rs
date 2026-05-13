use chrono::{DateTime, Utc};

use crate::{ClockSource, RngSource};

pub struct TestClockSource {}

impl TestClockSource {
    pub fn new() -> TestClockSource {
        TestClockSource {}
    }
}

impl Default for TestClockSource {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockSource for TestClockSource {
    fn now(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(123, 0).unwrap()
    }
}

pub struct TestRngSource {}

impl TestRngSource {
    pub fn new() -> TestRngSource {
        TestRngSource {}
    }
}

impl Default for TestRngSource {
    fn default() -> Self {
        Self::new()
    }
}

impl RngSource for TestRngSource {
    fn generate(&self, len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.resize(len, 0);
        v
    }
}
