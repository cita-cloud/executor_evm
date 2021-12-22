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

use std::cell::RefCell;
use std::cmp;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::core_executor::cita_executive::CitaExecutive;
use crate::core_executor::data_provider::BlockDataProvider;
use crate::core_executor::exception::ExecutedException;
use crate::core_executor::libexecutor::executor::CitaTrieDb;
use crate::core_executor::tx_gas_schedule::TxGasSchedule;
pub use crate::types::block::{Block, BlockBody, OpenBlock};
use crate::types::context::{Context, LastHashes};
use crate::types::errors::Error;
use crate::types::errors::ReceiptError;
use crate::types::errors::{AuthenticationError, ExecutionError};
use crate::types::receipt::Receipt;
use crate::types::transaction::SignedTransaction;
use crate::types::{Address, Bloom as LogBloom, H256, U256};
use cita_vm::{
    evm::Error as EVMError, state::State as CitaState, state::StateObjectInfo, Error as VmError,
};
use hashable::Hashable;
use libproto::executor::{ExecutedInfo, ReceiptWithOption};
use rlp::Encodable;

pub struct ExecutedBlock {
    pub block: OpenBlock,
    pub receipts: Vec<Receipt>,
    pub state: Arc<RefCell<CitaState<CitaTrieDb>>>,
    pub current_quota_used: U256,
    pub state_root: H256,
    last_hashes: Arc<LastHashes>,
    account_gas_limit: U256,
    account_gas: HashMap<Address, U256>,
    eth_compatibility: bool,
}

impl Deref for ExecutedBlock {
    type Target = OpenBlock;

    fn deref(&self) -> &OpenBlock {
        &self.block
    }
}

impl DerefMut for ExecutedBlock {
    fn deref_mut(&mut self) -> &mut OpenBlock {
        &mut self.block
    }
}

impl ExecutedBlock {
    pub fn create(
        block: OpenBlock,
        trie_db: Arc<CitaTrieDb>,
        state_root: H256,
        last_hashes: Arc<LastHashes>,
        eth_compatibility: bool,
    ) -> Result<Self, Error> {
        let state = CitaState::from_existing(Arc::<CitaTrieDb>::clone(&trie_db), state_root)
            .expect("Get state from trie db");

        // Need only one state reference for the whole block transaction.
        let state = Arc::new(RefCell::new(state));
        let r = ExecutedBlock {
            block,
            state,
            state_root,
            last_hashes,
            account_gas_limit: 4_294_967_296u64.into(),
            account_gas: HashMap::new(),
            current_quota_used: Default::default(),
            receipts: Default::default(),
            eth_compatibility,
        };

        Ok(r)
    }

    pub fn transactions(&self) -> &[SignedTransaction] {
        self.body.transactions()
    }

    /// Transaction execution env info.
    pub fn get_context(&self) -> Context {
        Context {
            block_number: self.number(),
            coin_base: *self.proposer(),
            timestamp: if self.eth_compatibility {
                self.timestamp() / 1000
            } else {
                self.timestamp()
            },
            difficulty: U256::default(),
            last_hashes: Arc::clone(&self.last_hashes),
            quota_used: self.current_quota_used,
            block_quota_limit: *self.quota_limit(),
            account_quota_limit: 0.into(),
        }
    }

    pub fn apply_transaction(&mut self, t: &SignedTransaction) {
        let mut context = self.get_context();
        self.account_gas
            .entry(*t.sender())
            .or_insert(self.account_gas_limit);

        //FIXME: set coin_base according to conf.
        context.account_quota_limit = *self
            .account_gas
            .get(t.sender())
            .expect("account should exist in account_gas_limit");

        let block_data_provider = EvmBlockDataProvider::new(context.clone());

        let _tx_quota_used =
            match CitaExecutive::new(Arc::new(block_data_provider), self.state.clone(), &context)
                .exec(t)
            {
                Ok(ret) => {
                    // Note: ret.quota_used was a current transaction quota used.
                    // FIXME: hasn't handle some errors
                    let receipt_error = ret.exception.map(|error| -> ReceiptError {
                        match error {
                            ExecutedException::Vm(VmError::Evm(EVMError::OutOfGas)) => {
                                ReceiptError::OutOfQuota
                            }
                            ExecutedException::Vm(VmError::Evm(
                                EVMError::InvalidJumpDestination,
                            )) => ReceiptError::BadJumpDestination,
                            ExecutedException::Vm(VmError::Evm(EVMError::InvalidOpcode)) => {
                                ReceiptError::BadInstruction
                            }
                            ExecutedException::Vm(VmError::Evm(EVMError::OutOfStack)) => {
                                ReceiptError::OutOfStack
                            }
                            ExecutedException::Vm(VmError::Evm(
                                EVMError::MutableCallInStaticContext,
                            )) => ReceiptError::MutableCallInStaticContext,
                            ExecutedException::Vm(VmError::Evm(EVMError::StackUnderflow)) => {
                                ReceiptError::StackUnderflow
                            }
                            ExecutedException::Vm(VmError::Evm(EVMError::OutOfBounds)) => {
                                ReceiptError::OutOfBounds
                            }
                            ExecutedException::Reverted => ReceiptError::Reverted,
                            _ => ReceiptError::Internal,
                        }
                    });

                    let tx_quota_used = if receipt_error.is_some()
                        && receipt_error != Some(ReceiptError::Internal)
                        && receipt_error != Some(ReceiptError::Reverted)
                    {
                        t.gas
                    } else {
                        ret.quota_used
                    };

                    // Note: quota_used in Receipt is self.current_quota_used, this will be
                    // handled by get_rich_receipt() while getting a single transaction receipt.
                    let cumulative_quota_used = context.quota_used + tx_quota_used;
                    let receipt = Receipt::new(
                        None,
                        cumulative_quota_used,
                        ret.logs,
                        receipt_error,
                        ret.account_nonce,
                        t.get_transaction_hash(),
                    );

                    self.receipts.push(receipt);
                    // return ret.quota_used rather than tx_quota_used for compatibility
                    ret.quota_used
                }
                Err(err) => {
                    // FIXME: hasn't handle some errors.
                    let receipt_error = match err {
                        ExecutionError::NotEnoughBaseGas => Some(ReceiptError::NotEnoughBaseQuota),
                        // FIXME: need to handle this two situation.
                        ExecutionError::BlockQuotaLimitReached => {
                            Some(ReceiptError::BlockQuotaLimitReached)
                        }
                        ExecutionError::AccountQuotaLimitReached => {
                            Some(ReceiptError::AccountQuotaLimitReached)
                        }
                        ExecutionError::InvalidNonce => Some(ReceiptError::InvalidNonce),
                        ExecutionError::NotEnoughBalance => Some(ReceiptError::NotEnoughCash),
                        ExecutionError::Authentication(
                            AuthenticationError::NoTransactionPermission,
                        ) => Some(ReceiptError::NoTransactionPermission),
                        ExecutionError::Authentication(
                            AuthenticationError::NoContractPermission,
                        ) => Some(ReceiptError::NoContractPermission),
                        ExecutionError::Authentication(AuthenticationError::NoCallPermission) => {
                            Some(ReceiptError::NoCallPermission)
                        }
                        ExecutionError::Internal { .. } => Some(ReceiptError::ExecutionInternal),
                        ExecutionError::InvalidTransaction => {
                            Some(ReceiptError::TransactionMalformed)
                        }
                        _ => Some(ReceiptError::Internal),
                    };

                    let schedule = TxGasSchedule::default();
                    // Bellow has a error, need gas*price before compare with balance
                    let tx_quota_used = match err {
                        ExecutionError::Internal(_) => t.gas,
                        _ => cmp::min(
                            self.state
                                .borrow_mut()
                                .balance(t.sender())
                                .unwrap_or_else(|_| U256::from(0)),
                            U256::from(schedule.tx_gas),
                        ),
                    };

                    let cumulative_quota_used = context.quota_used + tx_quota_used;
                    trace!(
                        "context quota used: {:?}, tx quota used： {:?}",
                        context.quota_used,
                        tx_quota_used
                    );
                    let receipt = Receipt::new(
                        None,
                        cumulative_quota_used,
                        Vec::new(),
                        receipt_error,
                        0.into(),
                        t.get_transaction_hash(),
                    );

                    self.receipts.push(receipt);
                    tx_quota_used
                }
            };
    }

    #[allow(dead_code)]
    fn deal_err_quota_cost(
        &self,
        sender: &Address,
        coin_base: &Address,
        quota: U256,
        quota_price: U256,
    ) -> U256 {
        if quota_price == U256::zero() {
            return quota;
        }
        let sender_balance = self.state.borrow_mut().balance(sender).unwrap();
        let tx_fee = quota * quota_price;
        trace!("fee -{:?}, sender balance-{:?}", tx_fee, sender_balance);
        let real_fee = cmp::min(sender_balance, tx_fee);

        if self
            .state
            .borrow_mut()
            .sub_balance(sender, real_fee)
            .is_err()
        {
            error!("Sub balance failed. tx_fee: {:?}", real_fee);
        } else {
            let _ = self.state.borrow_mut().add_balance(coin_base, real_fee);
        }
        if real_fee == sender_balance {
            sender_balance.checked_div(quota_price).unwrap()
        } else {
            quota
        }
    }

    /// Turn this into a `ClosedBlock`.
    pub fn close(self) -> ClosedBlock {
        // Rebuild block
        let mut block = Block::new(self.block);
        let state_root = self.state.borrow().root;
        block.set_state_root(state_root);
        let receipts_root = cita_merklehash::Tree::from_hashes(
            self.receipts
                .iter()
                .map(|r| r.rlp_bytes().to_vec().crypt_hash())
                .collect::<Vec<_>>(),
            cita_merklehash::merge,
        )
        .get_root_hash()
        .cloned()
        .unwrap_or(cita_merklehash::HASH_NULL);

        block.set_receipts_root(receipts_root);
        block.set_quota_used(self.current_quota_used);

        // blocks blooms
        let log_bloom = self
            .receipts
            .clone()
            .into_iter()
            .fold(LogBloom::zero(), |mut b, r| {
                b |= r.log_bloom;
                b
            });

        block.set_log_bloom(log_bloom);
        block.rehash();

        // Note: It is ok to new a state, because no cache and checkpoint used.
        let mut state = CitaState::from_existing(
            Arc::<CitaTrieDb>::clone(&self.state.borrow().db),
            self.state.borrow().root,
        )
        .expect("Get state from trie db");

        state.cache = RefCell::new(self.state.borrow_mut().cache.to_owned().into_inner());

        ClosedBlock {
            block,
            receipts: self.receipts,
            state,
        }
    }
}

// Block that prepared to commit to db.
// The CloseBlock will be share in two thread.
// #[derive(Debug)]
pub struct ClosedBlock {
    /// Protobuf Block
    pub block: Block,
    pub receipts: Vec<Receipt>,
    pub state: CitaState<CitaTrieDb>,
}

impl ClosedBlock {
    pub fn protobuf(&self) -> ExecutedInfo {
        let mut executed_info = ExecutedInfo::new();

        executed_info
            .mut_header()
            .set_prevhash(self.parent_hash().0.to_vec());
        executed_info.mut_header().set_timestamp(self.timestamp());
        executed_info.mut_header().set_height(self.number());
        executed_info
            .mut_header()
            .set_state_root(self.state_root().0.to_vec());
        executed_info
            .mut_header()
            .set_transactions_root(self.transactions_root().0.to_vec());
        executed_info
            .mut_header()
            .set_receipts_root(self.receipts_root().0.to_vec());
        executed_info
            .mut_header()
            .set_log_bloom(self.log_bloom().0.to_vec());
        executed_info
            .mut_header()
            .set_quota_used(self.quota_used().as_u64());
        executed_info
            .mut_header()
            .set_quota_limit(self.quota_limit().low_u64());

        executed_info.receipts = self
            .receipts
            .clone()
            .into_iter()
            .map(|receipt| {
                let mut receipt_proto_option = ReceiptWithOption::new();
                receipt_proto_option.set_receipt(receipt.protobuf());
                receipt_proto_option
            })
            .collect();
        executed_info
            .mut_header()
            .set_proposer(self.proposer().0.to_vec());
        executed_info
    }

    pub fn clear_cache(&mut self) {
        self.state.clear();
    }
}

impl Deref for ClosedBlock {
    type Target = Block;

    fn deref(&self) -> &Block {
        &self.block
    }
}

impl DerefMut for ClosedBlock {
    fn deref_mut(&mut self) -> &mut Block {
        &mut self.block
    }
}

pub struct EvmBlockDataProvider {
    context: Context,
}

impl EvmBlockDataProvider {
    pub fn new(context: Context) -> Self {
        EvmBlockDataProvider { context }
    }
}

impl BlockDataProvider for EvmBlockDataProvider {
    fn get_block_hash(&self, number: &U256) -> H256 {
        // TODO: comment out what this function expects from context, since it will produce panics if the latter is inconsistent
        if *number < U256::from(self.context.block_number)
            && number.low_u64() >= cmp::max(256, self.context.block_number) - 256
        {
            let index = self.context.block_number - number.low_u64() - 1;
            assert!(
                index < self.context.last_hashes.len() as u64,
                "Inconsistent context, should contain at least {:?} last hashes",
                index + 1
            );
            let r = self.context.last_hashes[index as usize];
            trace!(
                "ext: blockhash({}) -> {} self.context.block_number={}\n",
                number,
                r,
                self.context.block_number
            );
            r
        } else {
            trace!(
                "ext: blockhash({}) -> null self.context.block_number={}\n",
                number,
                self.context.block_number
            );
            H256::zero()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlp;

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_encode_and_decode() {
        let mut stx = SignedTransaction::default();
        stx.data = vec![1; 200];
        let transactions = vec![stx; 200];
        let body = BlockBody { transactions };
        let body_rlp = rlp::encode(&body);
        let body: BlockBody = rlp::decode(&body_rlp).unwrap();
        let body_encoded = rlp::encode(&body).to_vec();

        assert_eq!(body_rlp, body_encoded);
    }

    #[test]
    fn test_encode_and_decode_null() {
        let transactions = vec![];
        let body = BlockBody { transactions };
        let body_rlp = rlp::encode(&body);
        let body: BlockBody = rlp::decode(&body_rlp).unwrap();
        let body_encoded = rlp::encode(&body).to_vec();

        assert_eq!(body_rlp, body_encoded);
    }
}
