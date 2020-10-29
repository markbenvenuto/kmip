mod mem;
mod mongodb;
mod option_datefmt;

use chrono::serde::ts_milliseconds;
use chrono::Utc;

use crate::{ClockSource, KmipResponseError, RequestContext};
pub use crate::store::mongodb::KmipMongoDBStore;
pub use mem::KmipMemoryStore;

use option_datefmt::option_datefmt;

use protocol::{CryptographicAlgorithm, CryptographicParameters, NameStruct, ObjectStateEnum, SecretData};
use protocol::SymmetricKey;


// TODO - the storage format for SymmetricKey should be different from the wire format
#[derive(Serialize, Deserialize, Debug)]
pub struct SymmetricKeyStore {
    pub symmetric_key : SymmetricKey,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}


#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKeyStore),
    SecretData(SecretData),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedAttributes {
    //    pub cryptographic_algorithm : Option<CryptographicAlgorithm>,
    // NOTE: do not serialize as an enum because of the Serialize_enum macro breaks
    // the bson serializer.
    pub cryptographic_usage_mask: Option<i32>,

    // pub cryptographic_parameters: Option<CryptographicParameters>,

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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compromise_date: Option<chrono::DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivation_date: Option<chrono::DateTime<Utc>>,

    // // #[serde(with = "ts_milliseconds")]
    // // pub deactivation_date : Option<chrono::DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destroy_date: Option<chrono::DateTime<Utc>>,
}

// impl ManagedAttributes {
//     pub fn get_cryptographic_algorithm(&self) -> std::result::Result<CryptographicAlgorithm, KmipResponseError> {
//         match self.cryptographic_algorithm {
//             Some(i) => {
//                 Ok(num::FromPrimitive::from_i32(i).ok_or(KmipResponseError::new("Corruption in cryptographic_algorithm"))?)
//             }
//             _ => Err(KmipResponseError::new("No cryptographic_algorithm present"))
//         }
//     }

    
// }

impl ManagedAttributes {

    pub fn new(clock: &dyn ClockSource) -> ManagedAttributes {
        ManagedAttributes {
            state: ObjectStateEnum::PreActive,
            initial_date:clock.now(),
    
        names : Vec::new(),
            activation_date: None,
            compromise_date : None,
            deactivation_date : None,
            destroy_date: None,
            cryptographic_usage_mask: None,
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
    pub fn get_symmetric_key<'a>(&'a self) -> std::result::Result<&'a SymmetricKeyStore, KmipResponseError> {
        match &self.payload {
            ManagedObjectEnum::SymmetricKey(s) => Ok(s),
            _ => Err(KmipResponseError::new("Wrong stored object type"))
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


impl<'b> dyn KmipStore {

    pub fn get_managed_object<'a : 'b>(&self,  id: &Option<String>, rc: &'a RequestContext) -> std::result::Result<(String, ManagedObject), KmipResponseError> {
        let id = rc.get_id_placeholder(id)?;
        let doc_maybe = rc
            .get_server_context()
            .get_store()
            .get(id);
        if doc_maybe.is_none() {
            return Err(KmipResponseError::new("Thing not found"));
        }
        let doc = doc_maybe.unwrap();
    
        println!("BSON: {:?}", doc);
        let mo: ManagedObject = bson::from_bson(bson::Bson::Document(doc)).unwrap();
        println!("MO: {:?}", mo);

        Ok((id.to_string(), mo))
    }

}