use std::sync::Mutex;

use mongodb::*;
use bson::Document;

use crate::store::KmipStore;

struct KmipMongoDBStoreInner {
    counter: i32,
    uri : String,
}

pub struct KmipMongoDBStore {
    inner: Mutex<KmipMongoDBStoreInner>,
}

impl KmipMongoDBStore  {
    pub fn new(uri: &str) -> KmipMongoDBStore {
        KmipMongoDBStore {
            inner: Mutex::new(KmipMongoDBStoreInner {
            uri : uri.to_string(),
            counter: 0,
            })
        }
    }

    fn make_connection(&self) -> Collection {
        let uri = self.inner.lock().unwrap().uri.clone();
        let client = Client::with_uri_str(&uri).unwrap();

        let db = client.database("kmip");

        let collection = db.collection("managed_objects");

        return collection;
    }
}

impl KmipStore for KmipMongoDBStore  {
    fn add(&self, id: &str, doc: bson::Document) {
        let collection = self.make_connection();

        collection.insert_one(doc, None);
    }

    // TODO - improve
    fn gen_id(&self) -> String {
                let c : i32;
        {
            let mut lock = self.inner.lock().unwrap();
            lock.counter += 1;
            c = lock.counter;
        }
        return c.to_string();
    }

    fn get(&self, id: &String) -> Option<bson::Document> {
        let collection = self.make_connection();

        let doc = doc!{
            "_id" : id
        };

        let cursor = collection.find(Some(doc), None);

        let mut results : Vec<mongodb::error::Result<Document>> = cursor.unwrap().collect();
        if results.len() == 0 {
            return None;
        }

        assert_eq!(results.len(), 1);

        return Some(results.remove(0).unwrap());
    }
}