use std::sync::Mutex;
use std::collections::HashMap;

use crate::store::KmipStore;

struct KmipMemoryStoreInner {
    documents: HashMap<String, bson::Document>,
    counter: i32,
}

pub struct KmipMemoryStore {
    inner: Mutex<KmipMemoryStoreInner>,
}

impl KmipMemoryStore  {
    pub fn new() -> KmipMemoryStore {
        KmipMemoryStore {
            inner: Mutex::new(KmipMemoryStoreInner {
            documents: HashMap::new(),
            counter: 0,
            })
        }
    }
}

impl KmipStore for KmipMemoryStore  {
    fn add(&self, id: &str, doc: bson::Document) {
        let r = self.inner.lock().unwrap().documents.insert(id.to_string(), doc);
        assert!(r.is_none());
    }

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
        {
            let lock = self.inner.lock().unwrap();
            let doc = lock.documents.get(id);
            if let Some(d) = doc {
                return Some(d.clone());
            }
        }
        return None;
    }
}