use std::collections::HashMap;
use std::sync::Mutex;

use crate::store::KmipStoreProvider;

struct KmipMemoryStoreInner {
    documents: HashMap<String, bson::Document>,
    counter: i32,
}

pub struct KmipMemoryStore {
    inner: Mutex<KmipMemoryStoreInner>,
}

impl KmipMemoryStore {
    pub fn new() -> KmipMemoryStore {
        KmipMemoryStore {
            inner: Mutex::new(KmipMemoryStoreInner {
                documents: HashMap::new(),
                counter: 0,
            }),
        }
    }
}

impl KmipStoreProvider for KmipMemoryStore {
    fn add(&self, id: &str, doc: bson::Document) {
        let r = self
            .inner
            .lock()
            .unwrap()
            .documents
            .insert(id.to_string(), doc);
        assert!(r.is_none());
    }

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
        {
            let lock = self.inner.lock().unwrap();
            if let Some(d) = lock.documents.get(id) {
                return Some(d.clone());
            }
        }
        None
    }

    fn update_bson(&self, id: &str, doc: bson::Document) {
        {
            let mut lock = self.inner.lock().unwrap();
            if let Some(d) = lock.documents.get_mut(id) {
                *d = doc;
            }
        }
    }
}
