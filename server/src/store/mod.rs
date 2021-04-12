mod mem;
mod mongodb;
mod option_datefmt;

use std::sync::Arc;

use chrono::serde::ts_milliseconds;
use chrono::Utc;

pub use crate::store::mongodb::KmipMongoDBStore;
use crate::{ClockSource, KmipResponseError};
pub use mem::KmipMemoryStore;

use protocol::{AttributesEnum, ObjectTypeEnum, SymmetricKey};
use protocol::{
    CryptographicAlgorithm, CryptographicParameters, NameStruct, ObjectStateEnum, SecretData,
};

// TODO - the storage format for SymmetricKey should be different from the wire format
#[derive(Serialize, Deserialize, Debug)]
pub struct SymmetricKeyStore {
    pub symmetric_key: SymmetricKey,

    // TODO - this is multi instance per KMIP spec
    pub cryptographic_parameters: Option<CryptographicParameters>,

    pub cryptographic_algorithm: CryptographicAlgorithm,

    pub cryptographic_length: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ManagedObjectEnum {
    SymmetricKey(SymmetricKeyStore),
    SecretData(SecretData),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedAttributes {
    // NOTE: do not serialize as an enum because of the Serialize_enum macro breaks
    // the bson serializer.
    pub cryptographic_usage_mask: Option<i32>,

    pub state: ObjectStateEnum,

    pub names: Vec<NameStruct>,

    #[serde(with = "ts_milliseconds")]
    pub initial_date: chrono::DateTime<Utc>,

    #[serde(with = "ts_milliseconds")]
    pub last_change_date: chrono::DateTime<Utc>,

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
            initial_date: clock.now(),
            last_change_date: clock.now(),

            names: Vec::new(),
            activation_date: None,
            compromise_date: None,
            deactivation_date: None,
            destroy_date: None,
            cryptographic_usage_mask: None,
        }
    }

    // TODO - find a way to generate this function from an attribute?
    pub fn get_attribute_list(&self) -> Vec<String> {
        let mut attribute_names: Vec<String> = Vec::new();

        attribute_names.push("State".to_owned());
        attribute_names.push("Initial Date".to_owned());
        attribute_names.push("Last Change Date".to_owned());

        if self.cryptographic_usage_mask.is_some() {
            attribute_names.push("Cryptographic Usage Mask".to_owned());
        }

        if self.activation_date.is_some() {
            attribute_names.push("Activation Date".to_owned());
        }

        if self.deactivation_date.is_some() {
            attribute_names.push("Deactivation Date".to_owned());
        }

        if self.compromise_date.is_some() {
            attribute_names.push("Compromise Date".to_owned());
        }

        if self.destroy_date.is_some() {
            attribute_names.push("Destroy Date".to_owned());
        }

        attribute_names
    }

    pub fn get_all_attributes(&self) -> Vec<AttributesEnum> {
        let mut attributes: Vec<AttributesEnum> = Vec::new();

        attributes.push(AttributesEnum::State(self.state));

        if let Some(mask) = self.cryptographic_usage_mask {
            attributes.push(AttributesEnum::CryptographicUsageMask(mask));
        }

        if let Some(date) = self.activation_date {
            attributes.push(AttributesEnum::ActivationDate(date));
        }

        if let Some(date) = self.deactivation_date {
            attributes.push(AttributesEnum::DeactivationDate(date));
        }

        attributes.push(AttributesEnum::InitialDate(self.initial_date));
        attributes.push(AttributesEnum::LastChangeDate(self.last_change_date));

        attributes
    }

    pub fn get_attribute(&self, name: &str) -> Option<AttributesEnum> {
        if name == "State" {
            return Some(AttributesEnum::State(self.state));
        } else if name == "Activation Date" {
            if let Some(date) = self.activation_date {
                return Some(AttributesEnum::ActivationDate(date));
            }
        } else if name == "Deactivation Date" {
            if let Some(date) = self.deactivation_date {
                return Some(AttributesEnum::DeactivationDate(date));
            }
        } else if name == "Initial Date" {
            return Some(AttributesEnum::InitialDate(self.initial_date));
        } else if name == "Last Change Date" {
            return Some(AttributesEnum::LastChangeDate(self.last_change_date));
        } else if name == "Cryptographic Usage Mask" {
            if let Some(m) = self.cryptographic_usage_mask {
            return Some(AttributesEnum::CryptographicUsageMask(m));
            }
        }

        None
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
    pub fn get_symmetric_key<'a>(
        &'a self,
    ) -> std::result::Result<&'a SymmetricKeyStore, KmipResponseError> {
        match &self.payload {
            ManagedObjectEnum::SymmetricKey(s) => Ok(s),
            _ => Err(KmipResponseError::new("Wrong stored object type")),
        }
    }

    // TODO - find a way to generate this function from an attribute?
    pub fn get_attribute_list(&self) -> Vec<String> {
        let mut attribute_names = self.attributes.get_attribute_list();

        attribute_names.push("Unique Identifier".to_owned());
        attribute_names.push("Object Type".to_owned());

        match &self.payload {
            ManagedObjectEnum::SymmetricKey(_s) => {
                attribute_names.push("Cryptographic Parameters".to_owned());
                attribute_names.push("Cryptographic Algorithm".to_owned());
                attribute_names.push("Cryptographic Length".to_owned());
            }
            ManagedObjectEnum::SecretData(_s) => {}
        }

        attribute_names
    }

    pub fn get_all_attributes(&self) -> Vec<AttributesEnum> {
        let mut attributes = self.attributes.get_all_attributes();

        attributes.push(AttributesEnum::UniqueIdentifier(self.id.clone()));

        match &self.payload {
            ManagedObjectEnum::SymmetricKey(s) => {
                // if let Some(params) = s.cryptographic_parameters {
                //     // attributes.push(AttributesEnum::CryptographicUsageMask(params));
                // }

                attributes.push(AttributesEnum::CryptographicAlgorithm(s.cryptographic_algorithm));

                attributes.push(AttributesEnum::CryptographicLength(s.cryptographic_length));

                attributes.push(AttributesEnum::ObjectType(ObjectTypeEnum::SymmetricKey));
            }
            ManagedObjectEnum::SecretData(_s) => {
                attributes.push(AttributesEnum::ObjectType(ObjectTypeEnum::SecretData));

            }
        }

        attributes
    }

    pub fn get_attribute(&self, name: &str) -> Option<AttributesEnum> {
        let attr = self.attributes.get_attribute(name);
        if attr.is_some() {
            return attr;
        }

        if name == "Unique Identifier" {
            return Some(AttributesEnum::UniqueIdentifier(self.id.clone()));
        }

        match &self.payload {
            ManagedObjectEnum::SymmetricKey(s) => {
                if name == "Cryptographic Length" {
                    return Some(AttributesEnum::CryptographicLength(s.cryptographic_length));
                } else if name == "Cryptographic Algorithm" {
                    return Some(AttributesEnum::CryptographicAlgorithm(s.cryptographic_algorithm));
                } else if name == "Object Type" {
                    return Some(AttributesEnum::ObjectType(ObjectTypeEnum::SymmetricKey));
                }
            }
            ManagedObjectEnum::SecretData(_s) => {
           if name == "Object Type" {
                return Some(AttributesEnum::ObjectType(ObjectTypeEnum::SymmetricKey));
            }

            }
        }

        None
    }
}

////////////////////////////////////

pub trait KmipStoreProvider {
    fn add(&self, id: &str, doc: bson::Document);

    fn gen_id(&self) -> String;

    fn get(&self, id: &str) -> Option<bson::Document>;

    fn update_bson(&self, id: &str, doc: bson::Document);
}

pub struct KmipStore {
    store: Arc<dyn KmipStoreProvider + Send + Sync>,
    clock: Arc<dyn ClockSource + Send + Sync>,
}

impl KmipStore {
    pub fn new_mem(clock: Arc<dyn ClockSource + Send + Sync>) -> KmipStore {
        KmipStore {
            store: Arc::new(KmipMemoryStore::new()),
            clock: clock,
        }
    }

    pub fn new_mongodb(clock: Arc<dyn ClockSource + Send + Sync>, uri: &str) -> KmipStore {
        KmipStore {
            store: Arc::new(KmipMongoDBStore::new(uri)),
            clock: clock,
        }
    }

    pub fn add(&self, id: &str, doc: bson::Document) {
        self.store.add(id, doc);
    }

    pub fn gen_id(&self) -> String {
        self.store.gen_id()
    }

    pub fn get(&self, id: &str) -> std::result::Result<ManagedObject, KmipResponseError> {
        let doc_maybe = self.store.get(id);
        if doc_maybe.is_none() {
            return Err(KmipResponseError::new(&format!(
                "Could not find object in kmip store: {}",
                id
            )));
        }
        let doc = doc_maybe.unwrap();

        let mo: ManagedObject = bson::from_bson(bson::Bson::Document(doc))?;

        Ok(mo)
    }

    pub fn update(
        &self,
        id: &str,
        mo: &mut ManagedObject,
    ) -> std::result::Result<(), KmipResponseError> {
        mo.attributes.last_change_date = self.clock.now();

        let d = bson::to_bson(&mo).unwrap();

        if let bson::Bson::Document(d1) = d {
            self.store.update_bson(id, d1);
        } else {
            return Err(KmipResponseError::new("Barff"));
        }

        Ok(())
    }
}
