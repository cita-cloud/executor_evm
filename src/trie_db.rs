// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::sync::Arc;

use crate::types::H256;

use cita_database::error::DatabaseError;
use cita_database::{DataCategory, Database};
use hashable::HASH_NULL_RLP;
use parking_lot::RwLock;

#[derive(Debug, Clone, Copy)]
pub enum NodeType {
    Archive,
    Full,
}

impl From<&str> for NodeType {
    fn from(journaldb_type: &str) -> Self {
        match journaldb_type {
            "archive" => NodeType::Archive,
            "full" => NodeType::Full,
            str => panic!("input archive or full, your input: {str}"),
        }
    }
}

static NULL_RLP_STATIC: [u8; 1] = [0x80; 1];

#[derive(Debug)]
pub struct TrieDb<DB>
where
    DB: Database,
{
    db: Arc<DB>,
    cache: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    node_type: NodeType,
}

impl<DB> TrieDb<DB>
where
    DB: Database,
{
    pub fn new(db: Arc<DB>, node_type: NodeType) -> Self {
        TrieDb {
            db,
            cache: Arc::new(RwLock::new(HashMap::new())),
            node_type,
        }
    }

    pub fn database(&self) -> Arc<DB> {
        self.db.clone()
    }
}

/// "TrieDB" provides state read/write capabilities for executor.
impl<DB> cita_trie::DB for TrieDb<DB>
where
    DB: Database,
{
    type Error = DatabaseError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        if H256::from_slice(key) == HASH_NULL_RLP {
            return Ok(Some(NULL_RLP_STATIC.to_vec()));
        }
        match self.cache.read().get(key) {
            Some(v) => Ok(Some(v.to_vec())),
            None => self.db.get(Some(DataCategory::State), key),
        }
    }

    fn insert(&self, mut key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error> {
        if key.len() != 32 {
            key.resize(32, 0)
        }
        if H256::from_slice(key.as_slice()) == HASH_NULL_RLP {
            return Ok(());
        }
        self.cache.write().insert(key, value);
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        if H256::from_slice(key) == HASH_NULL_RLP {
            return Ok(true);
        }
        if self.cache.read().contains_key(key) {
            Ok(true)
        } else {
            self.db.contains(Some(DataCategory::State), key)
        }
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        match self.node_type {
            NodeType::Archive => Ok(()),
            NodeType::Full => {
                if H256::from_slice(key) == HASH_NULL_RLP {
                    return Ok(());
                }
                self.cache.write().remove(key);
                self.db.remove(Some(DataCategory::State), key)
            }
        }
    }

    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        let mut cache = self.cache.write();
        for i in 0..keys.len() {
            let key = keys[i].clone();
            if H256::from_slice(key.as_slice()) == HASH_NULL_RLP {
                continue;
            }
            let value = values[i].clone();
            cache.insert(key, value);
        }
        Ok(())
    }

    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<(), Self::Error> {
        match self.node_type {
            NodeType::Archive => Ok(()),
            NodeType::Full => {
                {
                    let mut cache = self.cache.write();
                    for key in keys {
                        if H256::from_slice(&key[..]) == HASH_NULL_RLP {
                            continue;
                        }
                        cache.remove(key);
                    }
                }
                self.db.remove_batch(Some(DataCategory::State), keys)
            }
        }
    }

    fn flush(&self) -> Result<(), Self::Error> {
        let len = self.cache.read().len();
        let mut keys = Vec::with_capacity(len);
        let mut values = Vec::with_capacity(len);

        for (key, value) in self.cache.write().drain() {
            keys.push(key);
            values.push(value);
        }

        self.db
            .insert_batch(Some(DataCategory::State), keys.to_vec(), values.to_vec())
    }
}

impl<DB> Clone for TrieDb<DB>
where
    DB: Database,
{
    fn clone(&self) -> Self {
        TrieDb {
            db: Arc::clone(&self.db),
            cache: Arc::clone(&self.cache),
            node_type: self.node_type,
        }
    }
}
