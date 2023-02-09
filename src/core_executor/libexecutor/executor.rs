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

use crate::config::ExecutorConfig;
use crate::core_chain::Chain;
pub use crate::core_executor::libexecutor::block::*;
use crate::trie_db::TrieDb;
use crate::types::block_number::{BlockTag, Tag};
use crate::types::db_indexes;
use crate::types::db_indexes::DbIndex;
use crate::types::header::*;
use crate::types::H256;
pub use byteorder::{BigEndian, ByteOrder};
use cita_database::{Config, DataCategory, Database, RocksDB, NUM_COLUMNS};
use libproto::{ConsensusConfig, ExecutedResult};
use rlp::{decode, encode};
use std::convert::Into;
use std::sync::Arc;
use util::RwLock;

pub type CitaTrieDb = TrieDb<RocksDB>;
pub type CitaDb = RocksDB;

pub type LastHashes = Vec<H256>;

pub struct Executor {
    pub current_header: RwLock<Header>,
    pub state_db: Arc<CitaTrieDb>,
    pub db: Arc<dyn Database>,
    pub eth_compatibility: bool,
    pub core_chain: Chain,
}

impl Executor {
    pub fn init(config: &ExecutorConfig) -> Executor {
        // TODO: Can remove NUM_COLUMNS(useless)
        let rocks_config = Config::with_category_num(NUM_COLUMNS);
        let statedb_path = config.db_path.clone() + "/statedb";
        let state_db = RocksDB::open(&statedb_path, &rocks_config).unwrap();
        let db = Arc::new(state_db);
        let state_db = Arc::new(TrieDb::new(db.clone(), config.sync_mode.as_str().into()));

        let current_header = match get_current_header(db.clone()) {
            Some(header) => header,
            None => {
                warn!("Not found exist block within database.");
                Header::default()
            }
        };
        let nosql_path = config.db_path.clone() + "/nosql";
        let nosql_db =
            RocksDB::open(&nosql_path, &rocks_config).expect("Open DB failed unexpected.");
        let chain_db = Arc::new(nosql_db);
        let core_chain = Chain::init_chain(chain_db);
        let executor = Executor {
            current_header: RwLock::new(current_header),
            state_db,
            db,
            eth_compatibility: config.eth_compatibility,
            core_chain,
        };

        info!(
            "executor init, current_height: {}, current_hash: {:?}",
            executor.get_current_height(),
            executor.get_current_hash(),
        );
        executor
    }

    pub fn close(&mut self) {
        // FIXME: Need a close interface for db.
        // IMPORTANT: close and release database handler so that it will not
        //            compact data/logs in background, which may effect snapshot
        //            changing database when restore snapshot.
        // self.db.close();

        info!(
            "executor closed, current_height: {}",
            self.get_current_height()
        );
    }

    pub fn rollback_current_height(&mut self, rollback_id: BlockTag) {
        let rollback_height: BlockNumber = match rollback_id {
            BlockTag::Height(height) => height,
            BlockTag::Tag(Tag::Earliest) => 0,
            _ => unimplemented!(),
        };
        if self.get_current_height() != rollback_height {
            warn!(
                "executor roll back from {} to {}",
                self.get_current_height(),
                rollback_height
            );
            let rollback_hash = self
                .block_hash(rollback_height)
                .expect("the target block to roll back should exist");

            let current_hash_key = db_indexes::CurrentHash.get_index();
            let hash_value = encode(&rollback_hash).to_vec();
            self.db
                .insert(
                    Some(DataCategory::Extra),
                    current_hash_key.to_vec(),
                    hash_value,
                )
                .expect("Insert rollback hash error.");
        }

        let rollback_header = self.block_header_by_height(rollback_height).unwrap();
        self.current_header = RwLock::new(rollback_header);
    }

    /// Write data to db
    /// 1. Header
    /// 2. CurrentHash
    /// 3. State
    pub fn write_batch(&self, block: &ClosedBlock) {
        let height = block.number();
        let hash = block.hash().unwrap();
        let version = block.version();
        trace!(
            "commit block in db hash {:?}, height {:?}, version {}",
            hash,
            height,
            version
        );

        // Insert [hash : block_header].
        let hash_key = db_indexes::Hash2Header(hash).get_index();
        self.db
            .insert(
                Some(DataCategory::Headers),
                hash_key.to_vec(),
                block.header().rlp(),
            )
            .expect("Insert block header error.");

        // Insert [CurrentHash : hash].
        let current_hash_key = db_indexes::CurrentHash.get_index();
        let hash_value = encode(&hash).to_vec();
        self.db
            .insert(
                Some(DataCategory::Extra),
                current_hash_key.to_vec(),
                hash_value.clone(),
            )
            .expect("Insert block hash error.");

        // Insert [height : hash]
        let height_key = db_indexes::BlockNumber2Hash(height).get_index();
        self.db
            .insert(Some(DataCategory::Extra), height_key.to_vec(), hash_value)
            .expect("Insert block hash error.");
    }

    /// Get block hash by number
    fn block_hash(&self, number: BlockNumber) -> Option<H256> {
        let height_key = db_indexes::BlockNumber2Hash(number).get_index();
        self.db
            .get(Some(DataCategory::Extra), &height_key.to_vec())
            .map(|h| h.map(|hash| decode(hash.as_slice()).unwrap()))
            .expect("Get block header error.")
    }

    fn current_state_root(&self) -> H256 {
        *self.current_header.read().state_root()
    }

    pub fn genesis_header(&self) -> Header {
        self.block_header(BlockTag::Tag(Tag::Earliest))
            .expect("failed to fetch genesis header")
    }

    /// Get block header by BlockTag
    pub fn block_header(&self, tag: BlockTag) -> Option<Header> {
        match tag {
            BlockTag::Tag(Tag::Latest) => self.block_header_by_height(self.get_latest_height()),
            BlockTag::Hash(hash) => self.block_header_by_hash(hash),
            BlockTag::Height(number) => self.block_header_by_height(number),
            BlockTag::Tag(Tag::Earliest) => self.block_header_by_height(0),
            BlockTag::Tag(Tag::Pending) => self.block_header_by_height(self.get_pending_height()),
        }
    }

    /// Get block header by height
    pub fn block_header_by_height(&self, number: BlockNumber) -> Option<Header> {
        {
            let header = self.current_header.read();
            if header.number() == number {
                return Some(header.clone());
            }
        }
        self.block_hash(number)
            .and_then(|h| self.block_header_by_hash(h))
    }

    /// Get block header by hash
    pub fn block_header_by_hash(&self, hash: H256) -> Option<Header> {
        {
            let header = self.current_header.read();
            if header.hash().unwrap() == hash {
                return Some(header.clone());
            }
        }

        let hash_key = db_indexes::Hash2Header(hash).get_index();
        self.db
            .get(Some(DataCategory::Headers), &hash_key.to_vec())
            .map(|header| header.map(|bytes| decode(bytes.as_slice()).unwrap()))
            .expect("Get block header error.")
    }

    #[inline]
    fn get_latest_height(&self) -> u64 {
        self.current_header.read().number().saturating_sub(1)
    }

    #[inline]
    fn get_pending_height(&self) -> u64 {
        self.current_header.read().number()
    }

    #[inline]
    pub fn get_current_height(&self) -> u64 {
        self.current_header.read().number()
    }

    #[inline]
    pub fn get_current_hash(&self) -> H256 {
        self.current_header.read().hash().unwrap()
    }

    pub fn get_current_header(&self) -> Header {
        (*self.current_header.read()).clone()
    }

    /// Build last 256 block hashes.
    pub fn build_last_hashes(&self, prevhash: Option<H256>, parent_height: u64) -> LastHashes {
        let parent_hash = prevhash.unwrap_or_else(|| {
            self.block_hash(parent_height).unwrap_or_else(|| {
                if parent_height == 0 {
                    H256::zero()
                } else {
                    panic!("invalid block height: {parent_height}")
                }
            })
        });

        let mut last_hashes = LastHashes::new();
        last_hashes.resize(256, H256::default());
        last_hashes[0] = parent_hash;
        for (i, last_hash) in last_hashes.iter_mut().enumerate().take(255_usize).skip(1) {
            if i >= parent_height as usize {
                break;
            }
            let height = parent_height - i as u64;
            *last_hash = self
                .block_hash(height)
                .expect("blocks lower then parent must exist");
        }
        last_hashes
    }

    // `executed_result_by_height` returns ExecutedResult which only contains system configs,
    // but not block data (like receipts).
    //
    // Q: So what is its called-scenario?
    // A: `executed_result_by_height` would only be called via `command::load_executed_result`;
    //    `command::load_executed_result` would only be called by Postman when it is at
    //    `bootstrap_broadcast` initializing phase;
    //    Postman do it to acquire recent 2 blocks' ExecutedResult and save them into backlogs,
    //    which be used to validate arrived Proof (ExecutedResult has "validators" config)
    pub fn executed_result_by_height(&self, height: u64) -> ExecutedResult {
        let block_tag = BlockTag::Height(height);
        let consensus_config = ConsensusConfig::default();
        let executed_header = self
            .block_header(block_tag)
            .map(Header::generate_executed_header)
            .unwrap_or_default();
        let mut executed_result = ExecutedResult::new();
        executed_result.set_config(consensus_config);
        executed_result
            .mut_executed_info()
            .set_header(executed_header);
        executed_result
    }

    pub fn to_executed_block(&self, open_block: OpenBlock) -> ExecutedBlock {
        let current_state_root = self.current_state_root();
        let last_hashes = {
            if open_block.number() == 0 {
                Vec::new()
            } else {
                self.build_last_hashes(None, open_block.number() - 1)
            }
        };

        ExecutedBlock::create(
            open_block,
            self.state_db.clone(),
            current_state_root,
            last_hashes.into(),
            self.eth_compatibility,
        )
        .unwrap()
    }
}

pub fn get_current_header(db: Arc<CitaDb>) -> Option<Header> {
    let current_hash_key = db_indexes::CurrentHash.get_index();
    if let Ok(hash) = db.get(Some(DataCategory::Extra), &current_hash_key.to_vec()) {
        let hash: H256 = if let Some(h) = hash {
            decode(h.as_slice()).unwrap()
        } else {
            return None;
        };
        let hash_key = db_indexes::Hash2Header(hash).get_index();
        if let Ok(header) = db.get(Some(DataCategory::Headers), &hash_key.to_vec()) {
            Some(decode(header.unwrap().as_slice()).unwrap())
        } else {
            None
        }
    } else {
        None
    }
}
