use chrono::{NaiveDateTime, Utc};
use serde::{self, Deserialize, Deserializer, Serializer};

// The signature of a serialize_with function must follow the pattern:
//
//    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error>
//    where
//        S: Serializer
//
// although it may also be generic over the input types T.
pub fn serialize<S>(
    date: &Option<chrono::DateTime<chrono::Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let v = date.unwrap().timestamp();
    serializer.serialize_newtype_struct("my_date", &v)
    //serializer.serialize_str(&s)
}

// The signature of a deserialize_with function must follow the pattern:
//
//    fn deserialize<'de, D>(D) -> Result<T, D::Error>
//    where
//        D: Deserializer<'de>
//
// although it may also be generic over the output types T.
pub fn deserialize<'de, D>(
    deserializer: D,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = i64::deserialize(deserializer)?;

    Ok(Some(chrono::DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp(v, 0),
        Utc,
    )))
}
