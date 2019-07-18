mod mem;
mod mongodb;

pub use mem::KmipMemoryStore;
pub use crate::store::mongodb::KmipMongoDBStore;

use crate::messages::SymmetricKey;
use crate::messages::AttributesEnum;


#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedObject {

    #[serde(rename="_id")]
    pub id: String,
    pub payload: ManagedObjectEnum,

    pub attributes: Vec<AttributesEnum>,
}

////////////////////////////////////


pub trait KmipStore {
    fn add(&self, id: &str, doc: bson::Document);

    fn gen_id(&self) -> String;

    fn get(&self, id: &String) -> Option<bson::Document>;
}


