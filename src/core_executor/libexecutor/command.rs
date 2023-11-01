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

use super::executor::CitaTrieDb;
use super::executor::Executor;
use crate::core_chain::Chain;
use crate::core_executor::cita_executive::{CitaExecutive, ExecutedResult as CitaExecuted};
use crate::core_executor::exception::ExecutedException;
pub use crate::core_executor::libexecutor::block::*;
use crate::core_executor::libexecutor::call_request::CallRequest;
use crate::trie_db::TrieDb;
use crate::types::block_number::BlockTag;
use crate::types::context::Context;
use crate::types::errors::CallError;
use crate::types::errors::ExecutionError;
use crate::types::receipt::RichReceipt;
use crate::types::transaction::{Action, SignedTransaction, Transaction};
use crate::types::Bytes;
use crate::types::{Address, H256, U256};
pub use byteorder::{BigEndian, ByteOrder};
use cita_cloud_proto::evm::{ReceiptProof, RootsInfo};
use cita_database::RocksDB;
use cita_vm::state::{State as CitaState, StateObjectInfo};
use hashable::Hashable;
use libproto::{ConsensusConfig, ExecutedResult};
use rlp::Encodable;
use std::cell::RefCell;
use std::convert::{From, Into};
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use util::RwLock;

#[cfg_attr(feature = "cargo-clippy", allow(clippy::large_enum_variant))]
pub enum Command {
    StateAt(BlockTag),
    GenState(H256, H256),
    CodeAt(Address, BlockTag),
    AbiAt(Address, BlockTag),
    BalanceAt(Address, BlockTag),
    NonceAt(Address, BlockTag),
    EthCall(CallRequest, BlockTag),
    EstimateQuota(CallRequest, BlockTag),
    SignCall(CallRequest),
    Call(SignedTransaction, BlockTag),
    LoadExecutedResult(u64),
    Grow(ClosedBlock),
    Exit(BlockTag),
    CloneExecutorReader,
    ReceiptAt(H256),
    ReceiptProof(H256),
    RootsInfo(BlockTag),
    StorageAt(Address, H256, BlockTag),
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::large_enum_variant))]
pub enum CommandResp {
    StateAt(Option<CitaState<CitaTrieDb>>),
    GenState(Option<CitaState<CitaTrieDb>>),
    CodeAt(Option<Bytes>),
    AbiAt(Option<Bytes>),
    BalanceAt(Option<Bytes>),
    NonceAt(Option<U256>),
    EthCall(Result<Bytes, String>),
    EstimateQuota(Result<Bytes, String>),
    SignCall(SignedTransaction),
    Call(Result<CitaExecuted, CallError>),
    LoadExecutedResult(ExecutedResult),
    Grow(ExecutedResult),
    Exit,
    CloneExecutorReader(Executor),
    ReceiptAt(Option<RichReceipt>),
    ReceiptProof(Option<ReceiptProof>),
    RootsInfo(Option<RootsInfo>),
    StorageAt(Option<H256>),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Command::StateAt(_) => write!(f, "Command::StateAt"),
            Command::GenState(_, _) => write!(f, "Command::GenState"),
            Command::CodeAt(_, _) => write!(f, "Command::CodeAt"),
            Command::AbiAt(_, _) => write!(f, "Command::ABIAt"),
            Command::BalanceAt(_, _) => write!(f, "Command::BalanceAt"),
            Command::NonceAt(_, _) => write!(f, "Command::NonceAt"),
            Command::EthCall(_, _) => write!(f, "Command::ETHCall"),
            Command::EstimateQuota(_, _) => write!(f, "Command::EstimateQuota"),
            Command::SignCall(_) => write!(f, "Command::SignCall"),
            Command::Call(_, _) => write!(f, "Command::Call"),
            Command::LoadExecutedResult(_) => write!(f, "Command::LoadExecutedResult"),
            Command::Grow(_) => write!(f, "Command::Grow"),
            Command::Exit(_) => write!(f, "Command::Exit"),
            Command::CloneExecutorReader => write!(f, "Command::CloneExecutorReader"),
            Command::ReceiptAt(_) => write!(f, "Command::ReceiptAt"),
            Command::ReceiptProof(_) => write!(f, "Command::ReceiptProof"),
            Command::RootsInfo(_) => write!(f, "Command::RootsInfo"),
            Command::StorageAt(_, _, _) => write!(f, "Command::StorageAt"),
        }
    }
}

impl fmt::Display for CommandResp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CommandResp::StateAt(_) => write!(f, "CommandResp::StateAt"),
            CommandResp::GenState(_) => write!(f, "CommandResp::GenState"),
            CommandResp::CodeAt(_) => write!(f, "CommandResp::CodeAt"),
            CommandResp::AbiAt(_) => write!(f, "CommandResp::ABIAt"),
            CommandResp::BalanceAt(_) => write!(f, "CommandResp::BalanceAt"),
            CommandResp::NonceAt(_) => write!(f, "CommandResp::NonceAt"),
            CommandResp::EthCall(_) => write!(f, "CommandResp::ETHCall"),
            CommandResp::EstimateQuota(_) => write!(f, "CommandResp::EstimateQuota"),
            CommandResp::SignCall(_) => write!(f, "CommandResp::SignCall"),
            CommandResp::Call(_) => write!(f, "CommandResp::Call"),
            CommandResp::LoadExecutedResult(_) => write!(f, "CommandResp::LoadExecutedResult"),
            CommandResp::Grow(_) => write!(f, "CommandResp::Grow"),
            CommandResp::Exit => write!(f, "CommandResp::Exit"),
            CommandResp::CloneExecutorReader(_) => write!(f, "CommandResp::CloneExecurorReader"),
            CommandResp::ReceiptAt(_) => write!(f, "CommandResp::ReceiptAt"),
            CommandResp::ReceiptProof(_) => write!(f, "CommandResp::ReceiptProof"),
            CommandResp::RootsInfo(_) => write!(f, "CommandResp::RootsInfo"),
            CommandResp::StorageAt(_) => write!(f, "CommandResp::StorageAt"),
        }
    }
}

pub trait Commander {
    fn operate(&mut self, command: Command) -> CommandResp;
    fn state_at(&self, block_tag: BlockTag) -> Option<CitaState<CitaTrieDb>>;
    fn gen_state(&self, root: H256, parent_hash: H256) -> Option<CitaState<CitaTrieDb>>;
    fn code_at(&self, address: &Address, block_tag: BlockTag) -> Option<Bytes>;
    fn abi_at(&self, address: &Address, block_tag: BlockTag) -> Option<Bytes>;
    fn balance_at(&self, address: &Address, block_tag: BlockTag) -> Option<Bytes>;
    fn nonce_at(&self, address: &Address, block_tag: BlockTag) -> Option<U256>;
    fn eth_call(&self, request: CallRequest, block_tag: BlockTag) -> Result<Bytes, String>;
    fn estimate_quota(&self, request: CallRequest, block_tag: BlockTag) -> Result<Bytes, String>;
    fn sign_call(&self, request: CallRequest) -> SignedTransaction;
    fn call(&self, t: &SignedTransaction, block_tag: BlockTag) -> Result<CitaExecuted, CallError>;
    fn load_executed_result(&self, height: u64) -> ExecutedResult;
    fn grow(&mut self, closed_block: &ClosedBlock) -> ExecutedResult;
    fn exit(&mut self, rollback_id: BlockTag);
    fn clone_executor_reader(&mut self) -> Self;
    fn receipt_at(&self, tx_hash: H256) -> Option<RichReceipt>;
    fn receipt_proof(&self, tx_hash: H256) -> Option<ReceiptProof>;
    fn roots_info(&self, height: BlockTag) -> Option<RootsInfo>;
    fn storage_at(&self, address: Address, key: H256, block_tag: BlockTag) -> Option<H256>;
}

// revert string like this, abi encode string
// 0x08c379a0
// 0x0000000000000000000000000000000000000000000000000000000000000020
// 0x000000000000000000000000000000000000000000000000000000000000000e
// 0x4e6f7420657175616c207a65726f000000000000000000000000000000000000
// 4 bytes version + 32 bytes whole len + 32 bytes string's len
fn parse_reason_string(output: &[u8]) -> Option<String> {
    if output.len() <= 68 {
        return None;
    }
    if output[..4].to_vec() != vec![0x08, 0xc3, 0x79, 0xa0] {
        return None;
    }
    let bstr = output[68..].split(|x| *x == 0).next()?;
    String::from_utf8(bstr.to_vec()).ok()
}

impl Commander for Executor {
    fn operate(&mut self, command: Command) -> CommandResp {
        match command {
            Command::StateAt(block_tag) => CommandResp::StateAt(self.state_at(block_tag)),
            Command::GenState(root, parent_hash) => {
                CommandResp::GenState(self.gen_state(root, parent_hash))
            }
            Command::CodeAt(address, block_tag) => {
                CommandResp::CodeAt(self.code_at(&address, block_tag))
            }
            Command::AbiAt(address, block_tag) => {
                CommandResp::AbiAt(self.abi_at(&address, block_tag))
            }
            Command::BalanceAt(address, block_tag) => {
                CommandResp::BalanceAt(self.balance_at(&address, block_tag))
            }
            Command::NonceAt(address, block_tag) => {
                CommandResp::NonceAt(self.nonce_at(&address, block_tag))
            }
            Command::EthCall(call_request, block_tag) => {
                CommandResp::EthCall(self.eth_call(call_request, block_tag))
            }
            Command::EstimateQuota(call_request, block_tag) => {
                CommandResp::EstimateQuota(self.estimate_quota(call_request, block_tag))
            }
            Command::SignCall(call_request) => CommandResp::SignCall(self.sign_call(call_request)),
            Command::Call(signed_transaction, block_tag) => {
                CommandResp::Call(self.call(&signed_transaction, block_tag))
            }
            Command::LoadExecutedResult(height) => {
                CommandResp::LoadExecutedResult(self.load_executed_result(height))
            }
            Command::Grow(mut closed_block) => {
                let r = self.grow(&closed_block);
                closed_block.clear_cache();
                CommandResp::Grow(r)
            }
            Command::Exit(rollback_id) => {
                self.exit(rollback_id);
                CommandResp::Exit
            }
            Command::CloneExecutorReader => {
                CommandResp::CloneExecutorReader(self.clone_executor_reader())
            }
            Command::ReceiptAt(tx_hash) => CommandResp::ReceiptAt(self.receipt_at(tx_hash)),
            Command::ReceiptProof(tx_hash) => {
                CommandResp::ReceiptProof(self.receipt_proof(tx_hash))
            }
            Command::RootsInfo(block_tag) => CommandResp::RootsInfo(self.roots_info(block_tag)),
            Command::StorageAt(address, key, block_tag) => {
                CommandResp::StorageAt(self.storage_at(address, key, block_tag))
            }
        }
    }

    /// Attempt to get a copy of a specific block's final state.
    fn state_at(&self, id: BlockTag) -> Option<CitaState<CitaTrieDb>> {
        self.block_header(id)
            .and_then(|h| self.gen_state(*h.state_root(), *h.parent_hash()))
    }

    /// Generate block's final state.
    fn gen_state(&self, root: H256, _parent_hash: H256) -> Option<CitaState<CitaTrieDb>> {
        // FIXME: There is a RWLock for clone a db, is it ok for using Arc::clone?
        CitaState::from_existing(Arc::<CitaTrieDb>::clone(&self.state_db), root).ok()
    }

    /// Get code by address
    fn code_at(&self, address: &Address, id: BlockTag) -> Option<Bytes> {
        self.state_at(id).and_then(|mut s| s.code(address).ok())
    }

    /// Get abi by address
    fn abi_at(&self, address: &Address, id: BlockTag) -> Option<Bytes> {
        self.state_at(id).and_then(|mut s| s.abi(address).ok())
    }

    /// Get balance by address
    fn balance_at(&self, address: &Address, id: BlockTag) -> Option<Bytes> {
        self.state_at(id)
            .and_then(|mut s| s.balance(address).ok())
            .map(|c| {
                let balance = &mut [0u8; 32];
                c.to_big_endian(balance);
                balance.to_vec()
            })
    }

    fn nonce_at(&self, address: &Address, id: BlockTag) -> Option<U256> {
        self.state_at(id).and_then(|mut s| s.nonce(address).ok())
    }

    fn eth_call(&self, request: CallRequest, id: BlockTag) -> Result<Bytes, String> {
        let signed = self.sign_call(request);
        match self.call(&signed, id) {
            Ok(b) => {
                if let Some(ExecutedException::Reverted) = b.exception {
                    if let Some(estr) = parse_reason_string(&b.output) {
                        return Err("Reverted: ".to_owned() + &estr);
                    }
                }
                Ok(b.output)
            }
            Err(e) => Err(format!("Call Error {e}")),
        }
    }

    fn estimate_quota(&self, request: CallRequest, id: BlockTag) -> Result<Bytes, String> {
        // The estimated transaction cost cannot exceed BQL
        let max_quota = U256::from(u64::MAX);
        let precision = U256::from(1024);

        let signed = self.sign_call(request);
        let header = self
            .block_header(id)
            .ok_or_else(|| "Estimate Error CallError::StatePruned".to_owned())?;
        let last_hashes = self.build_last_hashes(Some(header.hash().unwrap()), header.number());

        let context = Context {
            block_number: header.number(),
            coin_base: *header.proposer(),
            timestamp: if self.eth_compatibility {
                header.timestamp() / 1000
            } else {
                header.timestamp()
            },
            difficulty: U256::default(),
            last_hashes: ::std::sync::Arc::new(last_hashes),
            quota_used: *header.quota_used(),
            block_quota_limit: max_quota,
            account_quota_limit: u64::max_value().into(),
        };
        let block_data_provider = Arc::new(EvmBlockDataProvider::new(context.clone()));

        let sender = *signed.sender();

        // Try different quota to run tx.
        let exec_tx = |quota| {
            let mut tx = signed.as_unsigned().clone();
            tx.gas = quota;
            let tx = tx.fake_sign(sender);

            // The same transaction will get different result in different state.
            // And the estimate action will change the state, so it should take the most primitive
            // state for each estimate.
            let state = self.state_at(id).ok_or_else(|| {
                ExecutionError::Internal("Estimate Error CallError::StatePruned".to_owned())
            })?;
            let state = Rc::new(RefCell::new(state));

            CitaExecutive::new(block_data_provider.clone(), state, &context.clone()).exec(&tx)
        };
        let check_quota = |quota| {
            exec_tx(quota).ok().map_or((false, U256::from(0)), |r| {
                (r.exception.is_none(), r.quota_used)
            })
        };

        // Try block_quota_limit first
        let (run_ok, quota_used) = check_quota(max_quota);
        let lower = if !run_ok {
            trace!("estimate_quota failed with {}.", max_quota);
            return Err(format!(
                "Requires quota higher than upper limit({max_quota}) or some internal errors"
            ));
        } else {
            quota_used
        };

        //Try lower (quota_used)
        let estimate_quota = &mut [0u8; 32];
        let (run_ok, quota_used) = check_quota(lower);
        if run_ok {
            quota_used.to_big_endian(estimate_quota);
            return Ok(estimate_quota.to_vec());
        }

        // Binary search the point between `lower` and `upper`, with the precision which means
        // the estimate quota deviation　less than precision.
        fn binary_search<F>(
            mut lower: U256,
            mut upper: U256,
            mut check_quota: F,
            precision: U256,
        ) -> U256
        where
            F: FnMut(U256) -> (bool, U256),
        {
            while upper - lower > precision {
                let mid = (lower + upper) / 2;
                trace!(
                    "estimate_quota : lower {} .. mid {} .. upper {}",
                    lower,
                    mid,
                    upper
                );
                let (c, _) = check_quota(mid);
                if c {
                    upper = mid;
                } else {
                    lower = mid;
                }
            }
            upper
        }

        let quota_used = binary_search(lower, max_quota, check_quota, precision);
        quota_used.to_big_endian(estimate_quota);
        Ok(estimate_quota.to_vec())
    }

    fn sign_call(&self, request: CallRequest) -> SignedTransaction {
        let from = request.from.unwrap_or_else(Address::zero);
        let action = if request.to.0 == [0; 20] {
            Action::Create
        } else {
            Action::Call(request.to)
        };
        Transaction {
            nonce: "".to_string(),
            action,
            gas: U256::from(50_000_000),
            gas_price: U256::zero(),
            value: U256::zero(),
            data: request.data.map_or_else(Vec::new, |d| d.to_vec()),
            block_limit: u64::max_value(),
            chain_id: U256::default(),
            version: 0u32,
        }
        .fake_sign(from)
    }

    fn call(&self, t: &SignedTransaction, block_tag: BlockTag) -> Result<CitaExecuted, CallError> {
        let header = self.block_header(block_tag).ok_or(CallError::StatePruned)?;
        let last_hashes = self.build_last_hashes(Some(header.hash().unwrap()), header.number());
        let context = Context {
            block_number: header.number(),
            coin_base: *header.proposer(),
            timestamp: if self.eth_compatibility {
                header.timestamp() / 1000
            } else {
                header.timestamp()
            },
            difficulty: U256::default(),
            last_hashes: ::std::sync::Arc::new(last_hashes),
            quota_used: *header.quota_used(),
            block_quota_limit: *header.quota_limit(),
            account_quota_limit: u64::max_value().into(),
        };
        // context.block_quota_limit = U256::from(self.sys_config.block_quota_limit);

        // FIXME: Need to implement state_at
        // that's just a copy of the state.
        //        let mut state = self.state_at(block_tag).ok_or(CallError::StatePruned)?;

        let block_data_provider = EvmBlockDataProvider::new(context.clone());

        let state_root = if let Some(h) = self.block_header(block_tag) {
            *h.state_root()
        } else {
            error!("Can not get state root from trie db!");
            return Err(CallError::StatePruned);
        };

        let state = match CitaState::from_existing(
            Arc::<TrieDb<RocksDB>>::clone(&self.state_db),
            state_root,
        ) {
            Ok(state_db) => state_db,
            Err(e) => {
                error!("Can not get state from trie db! error: {:?}", e);
                return Err(CallError::StatePruned);
            }
        };

        let state = Rc::new(RefCell::new(state));
        CitaExecutive::new(Arc::new(block_data_provider), state, &context)
            .exec(t)
            .map_err(Into::into)
    }

    fn load_executed_result(&self, height: u64) -> ExecutedResult {
        self.executed_result_by_height(height)
    }

    fn grow(&mut self, closed_block: &ClosedBlock) -> ExecutedResult {
        info!(
            "executor grow according to ClosedBlock(height: {}, hash: {:?}, parent_hash: {:?}, \
             timestamp: {}, state_root: {:?}, transaction_root: {:?}, proposer: {:?})",
            closed_block.number(),
            closed_block.hash().unwrap(),
            closed_block.parent_hash(),
            closed_block.timestamp(),
            closed_block.state_root(),
            closed_block.transactions_root(),
            closed_block.proposer(),
        );

        {
            *self.current_header.write() = closed_block.header().clone();
        }

        let executed_info = closed_block.protobuf();

        // Must make sure write into database before load_sys_config
        self.write_batch(closed_block);

        let mut executed_result = ExecutedResult::new();
        let consensus_config = ConsensusConfig::default();
        executed_result.set_config(consensus_config);
        executed_result.set_executed_info(executed_info);
        executed_result
    }

    fn exit(&mut self, rollback_id: BlockTag) {
        self.rollback_current_height(rollback_id);
        self.close();
    }

    fn clone_executor_reader(&mut self) -> Self {
        let current_header = self.current_header.read().clone();
        let state_db = self.state_db.clone();
        let db = self.db.clone();
        let eth_compatibility = self.eth_compatibility;
        let core_chain = Chain::init_chain(self.core_chain.db.clone());
        Executor {
            current_header: RwLock::new(current_header),
            state_db,
            db,
            eth_compatibility,
            core_chain,
        }
    }

    fn receipt_at(&self, tx_hash: H256) -> Option<RichReceipt> {
        self.core_chain.get_rich_receipt(tx_hash)
    }

    fn receipt_proof(&self, tx_hash: H256) -> Option<ReceiptProof> {
        if let Some(rich_receipt) = self.core_chain.get_rich_receipt(tx_hash) {
            if let Some(transaction_index) = self.core_chain.transaction_index(tx_hash) {
                if let Some(receipts) = self.core_chain.block_receipts(transaction_index.block_hash)
                {
                    if let Some(receipt_proof) = cita_merklehash::Tree::from_hashes(
                        receipts
                            .receipts
                            .iter()
                            .map(|r| r.rlp_bytes().to_vec().crypt_hash())
                            .collect::<Vec<_>>(),
                        cita_merklehash::merge,
                    )
                    .get_proof_by_input_index(rich_receipt.transaction_index)
                    {
                        if let Some(roots_info) =
                            self.roots_info(BlockTag::Height(rich_receipt.block_number))
                        {
                            let mut receipt =
                                receipts.receipts[rich_receipt.transaction_index].clone();
                            receipt.state_root = None;
                            let receipt_proof = cita_merklehash::Proof::from(receipt_proof);
                            return Some(ReceiptProof {
                                receipt: receipt.rlp_bytes().to_vec(),
                                receipt_proof: receipt_proof.rlp_bytes().to_vec(),
                                roots_info: Some(roots_info),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    fn roots_info(&self, tag: BlockTag) -> Option<RootsInfo> {
        let block_header = self.block_header(tag)?;
        Some(RootsInfo {
            height: block_header.number(),
            state_root: block_header.state_root().0.to_vec(),
            receipt_root: block_header.receipts_root().0.to_vec(),
        })
    }

    fn storage_at(&self, address: Address, key: H256, block_tag: BlockTag) -> Option<H256> {
        self.state_at(block_tag)
            .and_then(|mut s| s.get_storage(&address, &key).ok())
    }
}
