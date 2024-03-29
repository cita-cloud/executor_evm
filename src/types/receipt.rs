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

//! Receipt

use super::Bytes;

use crate::types::LowerHex;
use std::str::FromStr;

use crate::types::block_number::BlockNumber;
use crate::types::errors::ReceiptError;
use crate::types::log::{LocalizedLog, Log};
use crate::types::{Address, Bloom as LogBloom, H256, U256};
use cita_cloud_proto::evm::Receipt as CloudReceipt;
use libproto::executor::{Receipt as ProtoReceipt, ReceiptErrorWithOption, StateRoot};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub state_root: Option<H256>,
    pub quota_used: U256,
    pub log_bloom: LogBloom,
    pub logs: Vec<Log>,
    pub error: Option<ReceiptError>,
    pub account_nonce: U256,
    pub transaction_hash: H256,
}

impl Receipt {
    pub fn new(
        state_root: Option<H256>,
        quota_used: U256,
        logs: Vec<Log>,
        error: Option<ReceiptError>,
        account_nonce: U256,
        transaction_hash: H256,
    ) -> Receipt {
        Receipt {
            state_root,
            quota_used,
            log_bloom: logs.iter().fold(LogBloom::default(), |b, l| b | l.bloom()),
            logs,
            error,
            account_nonce,
            transaction_hash,
        }
    }

    pub fn protobuf(&self) -> ProtoReceipt {
        let mut receipt_proto = ProtoReceipt::new();
        let mut state_root_option = StateRoot::new();
        let mut receipt_error_with_option = ReceiptErrorWithOption::new();

        if let Some(state_root) = self.state_root {
            state_root_option.set_state_root(state_root.0.to_vec());
            receipt_proto.set_state_root(state_root_option);
        }

        if let Some(error) = self.error {
            receipt_error_with_option.set_error(error.protobuf());
            receipt_proto.set_error(receipt_error_with_option);
        }

        receipt_proto.set_quota_used(self.quota_used.lower_hex());
        receipt_proto.set_log_bloom(self.log_bloom.0.to_vec());
        receipt_proto.logs = self
            .logs
            .clone()
            .into_iter()
            .map(|log_entry| log_entry.protobuf())
            .collect();
        receipt_proto.set_account_nonce(self.account_nonce.as_u64());
        receipt_proto.set_transaction_hash(self.transaction_hash.0.to_vec());
        receipt_proto
    }

    pub fn from_with_state_root(mut receipt: ProtoReceipt, state_root: Option<H256>) -> Self {
        let quota_used: U256 = U256::from_str(receipt.get_quota_used()).unwrap();
        let account_nonce: U256 = U256::from(receipt.get_account_nonce());
        let transaction_hash: H256 = H256::from_slice(receipt.get_transaction_hash());
        let mut error = None;

        let logs = receipt
            .get_logs()
            .iter()
            .map(|log_entry| {
                let address: Address = Address::from_slice(log_entry.get_address());
                let topics: Vec<H256> = log_entry
                    .get_topics()
                    .iter()
                    .map(|topic| H256::from_slice(topic))
                    .collect();
                let data: Bytes = Bytes::from(log_entry.get_data());
                Log {
                    address,
                    topics,
                    data,
                }
            })
            .collect();

        if receipt.error.is_some() {
            {
                error = Some(ReceiptError::from_proto(receipt.take_error().get_error()));
            }
        }

        Receipt::new(
            state_root,
            quota_used,
            logs,
            error,
            account_nonce,
            transaction_hash,
        )
    }
}

impl From<ProtoReceipt> for Receipt {
    fn from(receipt: ProtoReceipt) -> Self {
        let state_root = if receipt.state_root.is_some() {
            Some(H256::from_slice(
                receipt.clone().take_state_root().get_state_root(),
            ))
        } else {
            None
        };

        let quota_used: U256 = U256::from_str(receipt.get_quota_used()).unwrap();
        let account_nonce: U256 = U256::from(receipt.get_account_nonce());
        let transaction_hash: H256 = H256::from_slice(receipt.get_transaction_hash());
        let mut error = None;

        let logs = receipt
            .get_logs()
            .iter()
            .map(|log_entry| {
                let address: Address = Address::from_slice(log_entry.get_address());
                let topics: Vec<H256> = log_entry
                    .get_topics()
                    .iter()
                    .map(|topic| H256::from_slice(topic))
                    .collect();
                let data: Bytes = Bytes::from(log_entry.get_data());
                Log {
                    address,
                    topics,
                    data,
                }
            })
            .collect();

        if receipt.error.is_some() {
            #[allow(clippy::redundant_clone)]
            {
                error = Some(ReceiptError::from_proto(
                    receipt.clone().take_error().get_error(),
                ));
            }
        }

        Receipt::new(
            state_root,
            quota_used,
            logs,
            error,
            account_nonce,
            transaction_hash,
        )
    }
}

impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        if let Some(ref root) = self.state_root {
            s.begin_list(7);
            s.append(root);
        } else {
            s.begin_list(6);
        }
        s.append(&self.quota_used);
        s.append(&self.log_bloom);
        s.append_list(&self.logs);
        s.append(&self.error);
        s.append(&self.account_nonce);
        s.append(&self.transaction_hash);
    }
}

impl Decodable for Receipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? == 6 {
            Ok(Receipt {
                state_root: None,
                quota_used: rlp.val_at(0)?,
                log_bloom: rlp.val_at(1)?,
                logs: rlp.list_at(2)?,
                error: rlp.val_at(3)?,
                account_nonce: rlp.val_at(4)?,
                transaction_hash: rlp.val_at(5)?,
            })
        } else {
            Ok(Receipt {
                state_root: Some(rlp.val_at(0)?),
                quota_used: rlp.val_at(1)?,
                log_bloom: rlp.val_at(2)?,
                logs: rlp.list_at(3)?,
                error: rlp.val_at(4)?,
                account_nonce: rlp.val_at(5)?,
                transaction_hash: rlp.val_at(6)?,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct RichReceipt {
    pub transaction_hash: H256,
    pub transaction_index: usize,
    pub block_hash: H256,
    pub block_number: BlockNumber,
    pub cumulative_quota_used: U256,
    pub quota_used: U256,
    pub contract_address: Option<Address>,
    pub logs: Vec<LocalizedLog>,
    pub log_bloom: LogBloom,
    pub state_root: Option<H256>,
    pub error: Option<ReceiptError>,
}

impl From<RichReceipt> for CloudReceipt {
    fn from(receipt: RichReceipt) -> Self {
        let mut cumulative_quota_used = [0; 32];
        receipt
            .cumulative_quota_used
            .to_big_endian(&mut cumulative_quota_used);
        let mut quota_used = [0; 32];
        receipt.quota_used.to_big_endian(&mut quota_used);
        let contract_address = match receipt.contract_address {
            Some(address) => address.0.to_vec(),
            None => vec![0; 20],
        };
        let state_root = match receipt.state_root {
            Some(root) => root.0.to_vec(),
            None => vec![0; 32],
        };
        Self {
            transaction_hash: receipt.transaction_hash.0.to_vec(),
            transaction_index: receipt.transaction_index as u64,
            block_hash: receipt.block_hash.0.to_vec(),
            block_number: receipt.block_number,
            cumulative_quota_used: cumulative_quota_used.to_vec(),
            quota_used: quota_used.to_vec(),
            contract_address,
            logs: receipt.logs.into_iter().map(Into::into).collect(),
            state_root,
            logs_bloom: receipt.log_bloom.0.to_vec(),
            error_message: receipt
                .error
                .map(ReceiptError::description)
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::log::Log;

    #[test]
    fn test_no_state_root() {
        let r = Receipt::new(
            None,
            0x40cae.into(),
            vec![Log {
                address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                topics: vec![],
                data: vec![0u8; 32],
            }],
            None,
            1.into(),
            H256::from_str("2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee")
                .unwrap(),
        );
        let encoded = ::rlp::encode(&r);
        println!("encode ok");
        let decoded: Receipt = ::rlp::decode(&encoded).unwrap();
        println!("decoded: {decoded:?}");
        assert_eq!(decoded, r);
    }

    #[test]
    fn test_basic() {
        let r = Receipt::new(
            Some(
                H256::from_str("2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee")
                    .unwrap(),
            ),
            0x40cae.into(),
            vec![Log {
                address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                topics: vec![],
                data: vec![0u8; 32],
            }],
            None,
            1.into(),
            H256::from_str("2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee")
                .unwrap(),
        );
        let encoded = ::rlp::encode(&r);
        let decoded: Receipt = ::rlp::decode(&encoded).unwrap();
        println!("decoded: {decoded:?}");
        assert_eq!(decoded, r);
    }

    #[test]
    fn test_with_error() {
        let r = Receipt::new(
            Some(
                H256::from_str("2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee")
                    .unwrap(),
            ),
            0x40cae.into(),
            vec![Log {
                address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                topics: vec![],
                data: vec![0u8; 32],
            }],
            Some(ReceiptError::NoTransactionPermission),
            1.into(),
            H256::from_str("2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee")
                .unwrap(),
        );
        let encoded = ::rlp::encode(&r);
        let decoded: Receipt = ::rlp::decode(&encoded).unwrap();
        println!("decoded: {decoded:?}");
        assert_eq!(decoded, r);
    }
}
