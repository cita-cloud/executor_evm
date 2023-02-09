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

use crate::core_executor::cita_executive::create_address_from_address_and_nonce;
use crate::types::block::{Block, BlockBody, OpenBlock};
use crate::types::db_indexes::DbIndex;
use crate::types::db_indexes::{
    BlockNumber2Body, BlockNumber2Header, CurrentHash, CurrentHeight, Hash2BlockNumber,
    Hash2BlockReceipts, Hash2TransactionIndex, LogGroupPosition,
};
use crate::types::header::{BlockNumber, Header};
use crate::types::log_blooms::LogBloomGroup;
use crate::types::receipt::{Receipt, RichReceipt};
use crate::types::{
    block_number::BlockTag, block_number::Tag, block_number::TransactionHash,
    block_receipts::BlockReceipts, log::LocalizedLog, log::Log, transaction::Action,
    transaction::SignedTransaction, transaction_index::TransactionIndex,
};
use crate::types::{Bloom as LogBloom, H256};
use bloomchain::group::{
    BloomGroup, BloomGroupChain, BloomGroupDatabase, GroupPosition as BloomGroupPosition,
};
use bloomchain::{Bloom, Config as BloomChainConfig, Number as BloomChainNumber};
use cita_database as cita_db;
use cita_database::{Database, RocksDB};
use hashable::Hashable;
use libproto::{executor::ExecutedResult, FullTransaction};
use prost::Message;
use rlp::{self, decode, Encodable};
use std::collections::HashMap;
use std::convert::Into;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use util::RwLock;

pub const VERSION: u32 = 0;
const LOG_BLOOMS_LEVELS: usize = 3;
const LOG_BLOOMS_ELEMENTS_PER_INDEX: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
pub struct Config {
    pub prooftype: u8,
}

impl Config {
    pub fn new(path: &str) -> Self {
        let c: Config = parse_config!(Config, path);
        c
    }
}

impl Default for Config {
    fn default() -> Self {
        Self { prooftype: 2 }
    }
}

impl BloomGroupDatabase for Chain {
    fn blooms_at(&self, position: &BloomGroupPosition) -> Option<BloomGroup> {
        let p = LogGroupPosition::from(position.clone());
        self.db
            .get(Some(cita_db::DataCategory::Extra), &p.get_index())
            .unwrap_or(None)
            .map(|blooms| {
                let g: LogBloomGroup = rlp::decode(&blooms).unwrap();
                g.into()
            })
    }
}

pub struct Chain {
    pub blooms_config: BloomChainConfig,
    pub current_header: RwLock<Header>,
    // Chain current height
    pub current_height: AtomicUsize,
    pub db: Arc<RocksDB>,

    // snapshot flag
    pub version: RwLock<Option<u32>>,
}

/// Get latest status
pub fn get_chain(db: &RocksDB) -> Option<Header> {
    let res = db
        .get(
            Some(cita_db::DataCategory::Extra),
            &CurrentHash.get_index().to_vec(),
        )
        .unwrap_or(None)
        .map(|h| decode::<H256>(&h).unwrap());

    if let Some(hash) = res {
        trace!("Get block height from hash : {:?}", hash);
        let hash_key = Hash2BlockNumber(hash).get_index();
        let header = db
            .get(Some(cita_db::DataCategory::Extra), &hash_key)
            .unwrap_or(None)
            .map(|n| {
                let height = decode::<BlockNumber>(&n).unwrap();
                trace!("Get chain from height : {:?}", height);
                let height_key = BlockNumber2Header(height).get_index();
                db.get(Some(cita_db::DataCategory::Headers), &height_key)
                    .unwrap_or(None)
                    .map(|res| {
                        let header: Header = rlp::decode(&res).unwrap();
                        header
                    })
            })
            .and_then(|x| x);
        return header;
    }
    None
}

pub fn get_chain_body_height(db: &RocksDB) -> Option<BlockNumber> {
    db.get(
        Some(cita_db::DataCategory::Extra),
        &CurrentHeight.get_index(),
    )
    .unwrap_or(None)
    .map(|res| {
        let block_number: BlockNumber = rlp::decode(&res).unwrap();
        block_number
    })
}

impl Chain {
    pub fn init_chain(db: Arc<RocksDB>) -> Chain {
        let blooms_config = BloomChainConfig {
            levels: LOG_BLOOMS_LEVELS,
            elements_per_index: LOG_BLOOMS_ELEMENTS_PER_INDEX,
        };

        let header = get_chain(&db).unwrap_or_default();
        debug!("get chain head is : {:?}", header);
        let current_height = AtomicUsize::new(header.number() as usize);
        info!("current_height: {:?}", current_height);

        Chain {
            blooms_config,
            current_header: RwLock::new(header),
            current_height,
            db,
            version: RwLock::new(None),
        }
    }

    pub fn block_height_by_hash(&self, hash: H256) -> Option<BlockNumber> {
        let hash_key = Hash2BlockNumber(hash).get_index();
        self.db
            .get(Some(cita_db::DataCategory::Extra), &hash_key)
            .unwrap_or(None)
            .map(|res| decode::<BlockNumber>(&res).unwrap())
    }

    pub fn set_db_result(&self, ret: &ExecutedResult, block: &OpenBlock) {
        let info = ret.get_executed_info();
        let number = info.get_header().get_height();
        let log_bloom = LogBloom::from_slice(info.get_header().get_log_bloom());
        let header = Header::from_executed_info(ret.get_executed_info(), &block.header);
        let header_hash = header.hash().unwrap();

        let block_transaction_indexes = block.body().transaction_indexes(header_hash);
        let blocks_blooms: HashMap<LogGroupPosition, LogBloomGroup> = if log_bloom.is_zero() {
            HashMap::new()
        } else {
            let group = BloomGroupChain::new(self.blooms_config, self);
            group
                .insert(
                    number as BloomChainNumber,
                    Bloom::from(Into::<[u8; 256]>::into(log_bloom)),
                )
                .into_iter()
                .map(|p| (From::from(p.0), From::from(p.1)))
                .collect()
        };

        // Save hash -> receipts
        if !info.get_receipts().is_empty() {
            let receipts: Vec<Receipt> = info
                .get_receipts()
                .iter()
                .map(|r| {
                    Receipt::from_with_state_root(
                        r.get_receipt().clone(),
                        Some(H256::from_slice(info.get_header().get_state_root())),
                    )
                })
                .collect();
            let block_receipts = BlockReceipts::new(receipts);
            let hash_key = Hash2BlockReceipts(header_hash).get_index();
            let _ = self.db.insert(
                Some(cita_db::DataCategory::Extra),
                hash_key,
                rlp::encode(&block_receipts).to_vec(),
            );
        }

        // Save block transaction indexes
        if !block_transaction_indexes.is_empty() {
            for (k, v) in block_transaction_indexes.iter() {
                let hash_key = Hash2TransactionIndex(*k).get_index();
                let _ = self.db.insert(
                    Some(cita_db::DataCategory::Extra),
                    hash_key,
                    rlp::encode(v).to_vec(),
                );
            }
        }

        // Save number -> header
        trace!("Save ExecutedResult's header: {:?}", header);
        let number_key = BlockNumber2Header(number).get_index();
        let _ = self.db.insert(
            Some(cita_db::DataCategory::Headers),
            number_key,
            rlp::encode(&header).to_vec(),
        );

        // Save Body
        let number_key = BlockNumber2Body(number).get_index();
        let _ = self.db.insert(
            Some(cita_db::DataCategory::Bodies),
            number_key,
            rlp::encode(block.body()).to_vec(),
        );

        // Save hash -> blockNumber
        let hash_key = Hash2BlockNumber(header_hash).get_index();
        let _ = self.db.insert(
            Some(cita_db::DataCategory::Extra),
            hash_key,
            rlp::encode(&number).to_vec(),
        );

        // Save blocks blooms
        for (k, v) in blocks_blooms.iter() {
            let _ = self.db.insert(
                Some(cita_db::DataCategory::Extra),
                k.get_index(),
                rlp::encode(v).to_vec(),
            );
        }

        // Save current hash
        let _ = self.db.insert(
            Some(cita_db::DataCategory::Extra),
            CurrentHash.get_index(),
            rlp::encode(&header_hash).to_vec(),
        );

        *self.current_header.write() = header;
        self.current_height.store(number as usize, Ordering::SeqCst);
    }

    /// Get block by hash
    pub fn block_by_hash(&self, hash: H256) -> Option<Block> {
        self.block_height_by_hash(hash)
            .and_then(|h| self.block_by_height(h))
    }

    /// Get block by height
    pub fn block_by_height(&self, number: BlockNumber) -> Option<Block> {
        match (
            self.block_header_by_height(number),
            self.block_body_by_height(number),
        ) {
            (Some(h), Some(b)) => Some(Block { header: h, body: b }),
            _ => None,
        }
    }

    /// Get block header by BlockTag
    pub fn block_header(&self, tag: BlockTag) -> Option<Header> {
        match tag {
            BlockTag::Hash(hash) => self.block_header_by_hash(hash),
            BlockTag::Height(number) => self.block_header_by_height(number),
            BlockTag::Tag(Tag::Earliest) => self.block_header_by_height(0),
            BlockTag::Tag(Tag::Latest) => self.block_header_by_height(self.get_latest_height()),
            BlockTag::Tag(Tag::Pending) => self.block_header_by_height(self.get_pending_height()),
        }
    }

    /// Get block header by hash
    pub fn block_header_by_hash(&self, hash: H256) -> Option<Header> {
        {
            let header = self.current_header.read();
            if header.hash().unwrap() == hash {
                return Some(header.clone());
            }
        }
        self.block_height_by_hash(hash)
            .and_then(|h| self.block_header_by_height(h))
    }

    fn block_header_by_height(&self, number: BlockNumber) -> Option<Header> {
        let number_key = BlockNumber2Header(number).get_index();
        self.db
            .get(Some(cita_db::DataCategory::Headers), &number_key)
            .unwrap_or(None)
            .map(|res| {
                let header: Header = rlp::decode(&res).unwrap();
                header
            })
    }

    /// Get block body by BlockTag
    pub fn block_body(&self, tag: BlockTag) -> Option<BlockBody> {
        match tag {
            BlockTag::Hash(hash) => self.block_body_by_hash(hash),
            BlockTag::Height(number) => self.block_body_by_height(number),
            BlockTag::Tag(Tag::Earliest) => self.block_body_by_height(0),
            BlockTag::Tag(Tag::Latest) => self.block_body_by_height(self.get_latest_height()),
            BlockTag::Tag(Tag::Pending) => self.block_body_by_height(self.get_pending_height()),
        }
    }

    pub fn block_hash_by_height(&self, height: BlockNumber) -> Option<H256> {
        self.block_header_by_height(height)
            .map(|hdr| hdr.hash().unwrap())
    }

    /// Get block body by hash
    fn block_body_by_hash(&self, hash: H256) -> Option<BlockBody> {
        self.block_height_by_hash(hash)
            .and_then(|h| self.block_body_by_height(h))
    }

    /// Get block body by height
    fn block_body_by_height(&self, number: BlockNumber) -> Option<BlockBody> {
        let number_key = BlockNumber2Body(number).get_index();
        self.db
            .get(Some(cita_db::DataCategory::Bodies), &number_key)
            .unwrap_or(None)
            .map(|res| {
                let body: BlockBody = rlp::decode(&res).unwrap();
                body
            })
    }

    /// Get block tx hashes
    pub fn block_tx_hashes(&self, number: BlockNumber) -> Option<Vec<H256>> {
        self.block_body_by_height(number)
            .map(|body| body.transaction_hashes())
    }

    /// Get transaction by hash
    pub fn transaction(&self, hash: TransactionHash) -> Option<SignedTransaction> {
        self.transaction_index(hash).and_then(|addr| {
            let index = addr.index;
            let hash = addr.block_hash;
            self.transaction_by_address(hash, index)
        })
    }

    /// Get address of transaction by hash.
    fn transaction_index(&self, hash: TransactionHash) -> Option<TransactionIndex> {
        let hash_key = Hash2TransactionIndex(hash).get_index();
        self.db
            .get(Some(cita_db::DataCategory::Extra), &hash_key)
            .unwrap_or(None)
            .map(|res| {
                let tx_index: TransactionIndex = rlp::decode(&res).unwrap();
                tx_index
            })
    }

    /// Get transaction by address
    fn transaction_by_address(&self, hash: H256, index: usize) -> Option<SignedTransaction> {
        self.block_body_by_hash(hash)
            .map(|body| body.transactions()[index].clone())
    }

    /// Get transaction hashes by block hash
    pub fn transaction_hashes(&self, tag: BlockTag) -> Option<Vec<H256>> {
        self.block_body(tag).map(|body| body.transaction_hashes())
    }

    /// Get full transaction by hash
    pub fn full_transaction(&self, hash: TransactionHash) -> Option<FullTransaction> {
        self.transaction_index(hash).and_then(|addr| {
            let index = addr.index;
            let hash = addr.block_hash;
            self.block_by_hash(hash).map(|block| {
                let transactions = block.body().transactions();
                let tx = transactions[index].protobuf();
                let mut full_ts = FullTransaction::new();
                full_ts.set_transaction(tx);
                full_ts.set_block_number(block.number());
                full_ts.set_block_hash(hash.0.to_vec());
                full_ts.set_index(index as u32);
                full_ts
            })
        })
    }

    pub fn get_block_header_bytes(&self, tag: BlockTag) -> Option<Vec<u8>> {
        self.block_header(tag).map(|x| x.rlp_bytes().to_vec())
    }

    pub fn get_rich_receipt(&self, tx_hash: TransactionHash) -> Option<RichReceipt> {
        trace!("Get receipt by hash: {:?}", tx_hash);
        if let Some(transaction_index) = self.transaction_index(tx_hash) {
            let block_hash = transaction_index.block_hash;
            let tx_index = transaction_index.index;

            if let Some(res) = self.block_receipts(block_hash) {
                let mut receipts = res.receipts;
                receipts.truncate(tx_index + 1);

                let last_receipt = receipts.pop().expect("Current receipt is provided");
                let prior_quota_used = receipts.last().map_or(0.into(), |r| r.quota_used);
                let log_position_block = receipts.iter().fold(0, |acc, r| acc + r.logs.len());

                if last_receipt.transaction_hash == tx_hash {
                    let stx = self
                        .transaction_by_address(block_hash, tx_index)
                        .unwrap_or_default();
                    let block_number = self.block_height_by_hash(block_hash).unwrap_or(0);
                    let contract_address = match *stx.action() {
                        Action::Create if last_receipt.error.is_none() => {
                            Some(create_address_from_address_and_nonce(
                                stx.sender(),
                                &last_receipt.account_nonce,
                            ))
                        }
                        _ => None,
                    };

                    // avoid crashes caused by inconsistent receipts' quota_used and block header's
                    // quota_used
                    let (mut quota_used, overflow) =
                        last_receipt.quota_used.overflowing_sub(prior_quota_used);
                    if overflow {
                        warn!(
                            "Occur arithmetic overflow when compute {} quota use.",
                            tx_hash.to_string()
                        );
                        quota_used = stx.gas;
                    }

                    let block_header = self
                        .block_header(BlockTag::Height(block_number))
                        .expect("Can't get block header");
                    let cloud_header = block_header
                        .open_header()
                        .to_cloud_protobuf()
                        .header
                        .unwrap();
                    let mut block_header_bytes = Vec::with_capacity(cloud_header.encoded_len());
                    cloud_header
                        .encode(&mut block_header_bytes)
                        .expect("get_block_hash: encode block header failed");

                    let receipt = RichReceipt {
                        transaction_hash: tx_hash,
                        transaction_index: tx_index,
                        block_hash: block_header_bytes.crypt_hash(),
                        block_number,
                        cumulative_quota_used: last_receipt.quota_used,
                        quota_used,
                        contract_address,
                        logs: last_receipt
                            .logs
                            .into_iter()
                            .enumerate()
                            .map(|(i, log)| LocalizedLog {
                                log,
                                block_hash,
                                block_number,
                                transaction_hash: tx_hash,
                                transaction_index: tx_index,
                                transaction_log_index: i,
                                log_index: log_position_block + i,
                            })
                            .collect(),
                        log_bloom: last_receipt.log_bloom,
                        state_root: last_receipt.state_root,
                        error: last_receipt.error,
                    };
                    return Some(receipt);
                }
            }
        }
        info!("Get receipt by hash failed {:?}", tx_hash);
        None
    }

    #[inline]
    pub fn get_current_height(&self) -> u64 {
        self.current_height.load(Ordering::SeqCst) as u64
    }

    #[inline]
    pub fn get_pending_height(&self) -> u64 {
        self.current_header.read().number()
    }

    #[inline]
    pub fn get_latest_height(&self) -> u64 {
        self.current_header.read().number().saturating_sub(1)
    }

    #[inline]
    pub fn get_version(&self) -> Option<u32> {
        *self.version.read()
    }

    #[inline]
    pub fn current_state_root(&self) -> H256 {
        *self.current_header.read().state_root()
    }

    pub fn logs<F>(
        &self,
        mut blocks: Vec<BlockNumber>,
        matches: F,
        limit: Option<usize>,
    ) -> Vec<LocalizedLog>
    where
        F: Fn(&Log) -> bool,
        Self: Sized,
    {
        // sort in reverse order
        blocks.sort_by(|a, b| b.cmp(a));

        let mut log_index = 0;
        let mut logs = blocks
            .into_iter()
            .filter_map(|number| self.block_hash_by_height(number).map(|hash| (number, hash)))
            .filter_map(|(number, hash)| {
                self.block_receipts(hash)
                    .map(|r| (number, hash, r.receipts))
            })
            .filter_map(|(number, hash, receipts)| {
                self.block_body_by_hash(hash)
                    .map(|ref b| (number, hash, receipts, b.transaction_hashes()))
            })
            .flat_map(|(number, hash, mut receipts, mut hashes)| {
                if receipts.len() != hashes.len() {
                    warn!(
                        "Block {} ({}) has different number of receipts ({}) to transactions ({}). Database corrupt?",
                        number,
                        hash,
                        receipts.len(),
                        hashes.len()
                    );
                    unreachable!();
                }
                log_index = receipts
                    .iter()
                    .fold(0, |sum, receipt| sum + receipt.logs.len());

                let receipts_len = receipts.len();
                hashes.reverse();
                receipts.reverse();
                receipts
                    .into_iter()
                    .map(|receipt| receipt.logs)
                    .zip(hashes)
                    .enumerate()
                    .flat_map(move |(index, (mut logs, tx_hash))| {
                        let current_log_index = log_index;
                        let no_of_logs = logs.len();
                        log_index -= no_of_logs;

                        logs.reverse();
                        logs.into_iter().enumerate().map(move |(i, log)| {
                            LocalizedLog {
                                log,
                                block_hash: hash,
                                block_number: number,
                                transaction_hash: tx_hash,
                                // iterating in reverse order
                                transaction_index: receipts_len - index - 1,
                                transaction_log_index: no_of_logs - i - 1,
                                log_index: current_log_index - i - 1,
                            }
                        })
                    })
            })
            .filter(|log| matches(&log.log))
            .take(limit.unwrap_or(::std::usize::MAX))
            .collect::<Vec<LocalizedLog>>();
        logs.reverse();
        logs
    }

    /// Returns numbers of blocks containing given bloom.
    pub fn blocks_with_bloom(
        &self,
        bloom: &LogBloom,
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> Vec<BlockNumber> {
        let range = from_block as BloomChainNumber..to_block as BloomChainNumber;
        BloomGroupChain::new(self.blooms_config, self)
            .with_bloom(&range, &Bloom::from(Into::<[u8; 256]>::into(*bloom)))
            .into_iter()
            .map(|b| b as BlockNumber)
            .collect()
    }

    /// Get receipts of block with given hash.
    pub fn block_receipts(&self, hash: H256) -> Option<BlockReceipts> {
        let hash_key = Hash2BlockReceipts(hash).get_index();
        self.db
            .get(Some(cita_db::DataCategory::Extra), &hash_key)
            .unwrap_or(None)
            .map(|res| {
                let block_receipts: BlockReceipts = decode(&res).unwrap();
                block_receipts
            })
    }
}
