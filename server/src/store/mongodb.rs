use std::sync::Mutex;

use crate::store::KmipStoreProvider;
use mongodb::{Client, Collection};

struct KmipMongoDBStoreInner {
    counter: i32,
    uri: String,
}

pub struct KmipMongoDBStore {
    inner: Mutex<KmipMongoDBStoreInner>,
}

impl KmipMongoDBStore {
    pub fn new(uri: &str) -> KmipMongoDBStore {
        KmipMongoDBStore {
            inner: Mutex::new(KmipMongoDBStoreInner {
                uri: uri.to_string(),
                counter: 0,
            }),
        }
    }

    fn make_connection(&self) -> Collection<bson::Document> {
        let uri = self.inner.lock().unwrap().uri.clone();
        // TODO - make async
        let client = futures::executor::block_on(Client::with_uri_str(&uri)).unwrap();

        let db = client.database("kmip");

        let collection = db.collection("managed_objects");

        collection
    }
}

impl KmipStoreProvider for KmipMongoDBStore {
    fn add(&self, _id: &str, doc: bson::Document) {
        let collection = self.make_connection();

        collection.insert_one(doc).run().unwrap();
    }

    // TODO - improve
    fn gen_id(&self) -> String {
        let c: i32;
        {
            let mut lock = self.inner.lock().unwrap();
            lock.counter += 1;
            c = lock.counter;
        }
        c.to_string()
    }

    fn get(&self, id: &str) -> Option<bson::Document> {
        let collection = self.make_connection();

        let filter = mongodb::bson::doc! {
            "_id" : id
        };

        // TODO - make async
        // let cursor = collection.find(filter);

        // let cur = futures::executor::block_on(cursor).unwrap();
        // let mut results: Vec<mongodb::error::Result<bson::Document>> =
        //     futures::executor::block_on(cur.collect());
        // if results.is_empty() {
        //     return None;
        // }
        // let mut results: Vec<mongodb::error::Result<bson::Document>> =
        //     cursor.run().unwrap().collect();

        // assert_eq!(results.len(), 1);

        // Some(results.remove(0).unwrap())
        let doc = collection.find_one(filter).run().unwrap();
        doc
    }

    fn update_bson(&self, id: &str, doc: bson::Document) {
        let collection = self.make_connection();

        let filter = mongodb::bson::doc! {
            "_id" : id
        };

        collection.find_one_and_replace(filter, doc).run().unwrap();
    }
}
