mod mem;
mod mongodb;

pub use mem::KmipMemoryStore;

use crate::messages::SymmetricKey;


#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedObject {
    pub id: String,
    pub payload: ManagedObjectEnum,
}

////////////////////////////////////


pub trait KmipStore {
    fn add(&self, id: &str, doc: bson::Document);

    fn gen_id(&self) -> String;

    fn get(&self, id: &String) -> Option<bson::Document>;
}


