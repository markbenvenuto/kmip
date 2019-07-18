mod mem;
mod mongodb;

use chrono::DateTime;
use chrono::Utc;
use chrono::serde::ts_milliseconds;

pub use crate::store::mongodb::KmipMongoDBStore;
pub use mem::KmipMemoryStore;

use crate::messages::AttributesEnum;
use crate::messages::SymmetricKey;
use crate::messages::ObjectStateEnum;
use crate::messages::CryptographicAlgorithm;

#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedAttributes {
    pub cryptographic_algorithm : Option<CryptographicAlgorithm>,

    pub cryptographic_length : Option<i32>,

    pub cryptographic_usage_mask : Option<i32>,

    pub state : ObjectStateEnum,

    #[serde(with = "ts_milliseconds")]
    pub initial_date : chrono::DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedObject {
    #[serde(rename = "_id")]
    pub id: String,

    pub payload: ManagedObjectEnum,

    pub attributes: ManagedAttributes,
}

////////////////////////////////////

pub trait KmipStore {
    fn add(&self, id: &str, doc: bson::Document);

    fn gen_id(&self) -> String;

    fn get(&self, id: &String) -> Option<bson::Document>;
}


