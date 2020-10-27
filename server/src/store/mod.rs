mod mem;
mod mongodb;
mod option_datefmt;

use chrono::serde::ts_milliseconds;
use chrono::DateTime;
use chrono::Utc;

pub use crate::store::mongodb::KmipMongoDBStore;
pub use mem::KmipMemoryStore;

use option_datefmt::option_datefmt;

use protocol::AttributesEnum;
use protocol::CryptographicAlgorithm;
use protocol::ObjectStateEnum;
use protocol::SymmetricKey;

#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedAttributes {
    //    pub cryptographic_algorithm : Option<CryptographicAlgorithm>,
    // NOTE: do not serialize as an enum because of the Serialize_enum macro breaks
    // the bson serializer.
    pub cryptographic_algorithm: Option<i32>,

    pub cryptographic_length: Option<i32>,

    pub cryptographic_usage_mask: Option<i32>,

    pub state: ObjectStateEnum,

    #[serde(with = "ts_milliseconds")]
    pub initial_date: chrono::DateTime<Utc>,

    // #[serde(with = "ts_milliseconds")]
    // pub process_start_date : Option<chrono::DateTime<Utc>>,

    // #[serde(with = "ts_milliseconds")]
    // pub process_stop_date : Option<chrono::DateTime<Utc>>,

    //#[serde(with = "ts_milliseconds")]
    #[serde(default, deserialize_with = "option_datefmt")]
    pub activation_date: Option<chrono::DateTime<Utc>>,
    // #[serde(with = "ts_milliseconds")]
    // pub deactivation_date : Option<chrono::DateTime<Utc>>,
    #[serde(default, deserialize_with = "option_datefmt")]
    pub destroy_date: Option<chrono::DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedObject {
    #[serde(rename = "_id")]
    pub id: String,

    pub payload: ManagedObjectEnum,

    pub attributes: ManagedAttributes,
}

////////////////////////////////////

// TODO - add helper methods for ManagedOject
pub trait KmipStore {
    fn add(&self, id: &str, doc: bson::Document);

    fn gen_id(&self) -> String;

    fn get(&self, id: &String) -> Option<bson::Document>;

    fn update(&self, id: &String, doc: bson::Document);
}
