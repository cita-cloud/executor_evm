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

use crate::core_chain::Chain;
pub use crate::core_executor::libexecutor::block::*;
use crate::core_executor::trie_db::TrieDb;
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
    #[allow(unknown_lints, clippy::too_many_arguments)] // TODO clippy
    pub fn init(data_path: String, eth_compatibility: bool) -> Executor {
        // TODO: Can remove NUM_COLUMNS(useless)
        let config = Config::with_category_num(NUM_COLUMNS);
        let statedb_path = data_path.clone() + "/statedb";
        let rocks_db = RocksDB::open(&statedb_path, &config).unwrap();
        let db = Arc::new(rocks_db);
        let state_db = Arc::new(TrieDb::new(db.clone()));

        let current_header = match get_current_header(db.clone()) {
            Some(header) => header,
            None => {
                warn!("Not found exist block within database.");
                Header::default()
            }
        };
        let nosql_path = data_path + "/nosql";
        let rocks_db = RocksDB::open(&nosql_path, &config).expect("Open DB failed unexpected.");
        let chain_db = Arc::new(rocks_db);
        let core_chain = Chain::init_chain(chain_db);
        let executor = Executor {
            current_header: RwLock::new(current_header),
            state_db,
            db,
            eth_compatibility,
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

    /// Build last 256 block hashes.
    pub fn build_last_hashes(&self, prevhash: Option<H256>, parent_height: u64) -> LastHashes {
        let parent_hash = prevhash.unwrap_or_else(|| {
            self.block_hash(parent_height).unwrap_or_else(|| {
                if parent_height == 0 {
                    H256::zero()
                } else {
                    panic!("invalid block height: {}", parent_height)
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

#[cfg(test)]
mod tests {
    extern crate cita_logger as logger;
    extern crate tempdir;
    use crate::core_executor::libexecutor::command::Commander;
    use crate::core_executor::libexecutor::command::{Command, CommandResp};
    use crate::core_executor::libexecutor::fsm::Fsm;
    use crate::tests::helpers;
    use crate::types::block_number::{BlockTag, Tag};
    use crate::types::Address;
    use cita_crypto::{CreateKey, KeyPair};
    use std::thread;
    use std::time::Duration;

    // #[test]
    // #[cfg(feature = "sha3hash")]
    // fn test_chain_name_valid_block_number() {
    //     use crate::core_executor::contracts::solc::sys_config::SysConfig;
    //     use crate::types::reserved_addresses;
    //     use crate::types::H256;
    //     use rustc_hex::FromHex;
    //     use std::str::FromStr;

    //     let privkey =
    //         H256::from("0x5f0258a4778057a8a7d97809bd209055b2fbafa654ce7d31ec7191066b9225e6");

    //     let mut executor = helpers::init_executor();
    //     let to = Address::from_str(reserved_addresses::SYS_CONFIG).unwrap();
    //     let data = "c0c41f220000000000000000000000000000000000000000000\
    //                 000000000000000000020000000000000000000000000000000\
    //                 000000000000000000000000000000000531323334350000000\
    //                 00000000000000000000000000000000000000000000000";
    //     let code = data.from_hex().unwrap();
    //     let block = helpers::create_block(&executor, to, &code, (0, 1), &privkey);

    //     let closed_block = executor.into_fsm(block);
    //     let _executed_result = executor.grow(closed_block);

    //     let chain_name_latest = SysConfig::new(&executor)
    //         .chain_name(BlockTag::Tag(Tag::Latest))
    //         .unwrap();

    //     let chain_name_pending = SysConfig::new(&executor)
    //         .chain_name(BlockTag::Tag(Tag::Pending))
    //         .unwrap();

    //     assert_eq!(chain_name_pending, "12345");
    //     assert_eq!(chain_name_latest, "test-chain");
    // }

    #[test]
    fn test_rollback_current_height() {
        let keypair = KeyPair::gen_keypair();
        let privkey = keypair.privkey();
        let mut executor = helpers::init_executor();

        let data = helpers::generate_contract();
        for _i in 0..5 {
            let block = helpers::create_block(
                &executor,
                Address::from_low_u64_le(0),
                &data,
                (0, 1),
                &privkey,
            );
            let mut closed_block = executor.into_fsm(block.clone());
            executor.grow(&closed_block);
            closed_block.clear_cache();
        }

        let current_height = executor.get_current_height();
        assert_eq!(current_height, 5);

        // rollback_height = current_height
        executor.rollback_current_height(BlockTag::Height(current_height));
        assert_eq!(executor.get_current_height(), current_height);

        // rollback height = current_height - 3
        let rollback_to_2 = current_height - 3;
        executor.rollback_current_height(BlockTag::Height(rollback_to_2));
        assert_eq!(executor.get_current_height(), 2);

        // rollback_height = 0
        executor.rollback_current_height(BlockTag::Tag(Tag::Earliest));
        assert_eq!(executor.get_current_height(), 0);
    }

    #[test]
    fn test_closed_block_grow() {
        let keypair = KeyPair::gen_keypair();
        let privkey = keypair.privkey();
        let mut executor = helpers::init_executor();

        let data = helpers::generate_contract();
        let block = helpers::create_block(
            &executor,
            Address::from_low_u64_le(0),
            &data,
            (0, 1),
            &privkey,
        );
        let mut closed_block = executor.into_fsm(block.clone());
        let closed_block_height = closed_block.number();
        let closed_block_hash = closed_block.hash();
        executor.grow(&closed_block);
        closed_block.clear_cache();

        let current_height = executor.get_current_height();
        let current_hash = executor.block_hash(current_height);
        assert_eq!(closed_block_height, current_height);
        assert_eq!(closed_block_hash, current_hash);
    }
}
