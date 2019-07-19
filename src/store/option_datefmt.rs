use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Deserializer};

// From https://github.com/serde-rs/serde/issues/1444
// TODO - make it go to millis
const FORMAT: &str = "%Y-%m-%d %H:%M:%S";

fn datefmt<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Utc.datetime_from_str(&s, FORMAT)
        .map_err(serde::de::Error::custom)
}

pub fn option_datefmt<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "datefmt")] DateTime<Utc>);

    let v = Option::deserialize(deserializer)?;
    Ok(v.map(|Wrapper(a)| a))
}

// EXAMPLE:
// #[derive(Deserialize, Debug)]
// struct MyStruct {
//     #[serde(default, deserialize_with = "option_datefmt")]
//     expiration_date: Option<DateTime<Utc>>,
// }
