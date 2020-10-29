mod mem;
mod mongodb;
mod option_datefmt;

use chrono::serde::ts_milliseconds;
use chrono::Utc;

use crate::KmipResponseError;
pub use crate::store::mongodb::KmipMongoDBStore;
pub use mem::KmipMemoryStore;

use option_datefmt::option_datefmt;

use protocol::{CryptographicAlgorithm, CryptographicParameters, NameStruct, ObjectStateEnum, SecretData};
use protocol::SymmetricKey;

#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKey),
    SecretData(SecretData),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedAttributes {
    //    pub cryptographic_algorithm : Option<CryptographicAlgorithm>,
    // NOTE: do not serialize as an enum because of the Serialize_enum macro breaks
    // the bson serializer.
    
    // TODO - we should probably refactor these as not top-level attributes because they are symmetricy key specific
    pub cryptographic_algorithm: Option<i32>,

    pub cryptographic_length: Option<i32>,

    pub cryptographic_usage_mask: Option<i32>,

    pub cryptographic_parameters: Option<CryptographicParameters>,

    pub state: ObjectStateEnum,

    pub names: Vec<NameStruct>,

    #[serde(with = "ts_milliseconds")]
    pub initial_date: chrono::DateTime<Utc>,

    // #[serde(with = "ts_milliseconds")]
    // pub process_start_date : Option<chrono::DateTime<Utc>>,

    // #[serde(with = "ts_milliseconds")]
    // pub process_stop_date : Option<chrono::DateTime<Utc>>,

    // //#[serde(with = "ts_milliseconds")]
    // #[serde(default, deserialize_with = "option_datefmt")]
    // pub activation_date: Option<chrono::DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_date: Option<chrono::DateTime<Utc>>,

    // // #[serde(with = "ts_milliseconds")]
    // // pub deactivation_date : Option<chrono::DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destroy_date: Option<chrono::DateTime<Utc>>,
}

impl ManagedAttributes {
    pub fn get_cryptographic_algorithm(&self) -> std::result::Result<CryptographicAlgorithm, KmipResponseError> {
        match self.cryptographic_algorithm {
            Some(i) => {
                Ok(num::FromPrimitive::from_i32(i).ok_or(KmipResponseError::new("Corupption in cryptographic_algorithm"))?)
            }
            _ => Err(KmipResponseError::new("Wrong object type"))
        }
    }

    
}




#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedObject {
    #[serde(rename = "_id")]
    pub id: String,

    pub payload: ManagedObjectEnum,

    pub attributes: ManagedAttributes,
}

impl ManagedObject {
    pub fn get_symmetric_key<'a>(&'a self) -> std::result::Result<&'a SymmetricKey, KmipResponseError> {
        match &self.payload {
            ManagedObjectEnum::SymmetricKey(s) => Ok(s),
            _ => Err(KmipResponseError::new("Wrong object type"))
        }
    }
}

////////////////////////////////////

// TODO - add helper methods for ManagedOject
pub trait KmipStore {
    fn add(&self, id: &str, doc: bson::Document);

    fn gen_id(&self) -> String;

    fn get(&self, id: &str) -> Option<bson::Document>;

    fn update(&self, id: &str, doc: bson::Document);
}
