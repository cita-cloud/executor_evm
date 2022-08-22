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

use super::Bytes;
use crate::types::block_number::BlockNumber;
use crate::types::BloomTools;
use crate::types::{Address, Bloom, H256};
use cita_cloud_proto::evm::Log as CloudLog;
use libproto::executor::LogEntry as ProtoLog;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::Deref;

type Topic = Vec<H256>;

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Topic,
    pub data: Bytes,
}

impl Encodable for Log {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(3);
        stream.append(&self.address);
        stream.append_list(&self.topics);
        stream.append(&self.data);
    }
}

impl Decodable for Log {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Log {
            address: rlp.val_at(0)?,
            topics: rlp.list_at(1)?,
            data: rlp.val_at(2)?,
        })
    }
}

impl Log {
    pub fn bloom(&self) -> Bloom {
        self.topics
            .iter()
            .fold(Bloom::from_raw(self.address.as_bytes()), |bloom, topic| {
                let mut bloom = bloom;
                bloom.accrue_raw(topic.as_bytes());
                bloom
            })
    }

    pub fn protobuf(&self) -> ProtoLog {
        let mut proto_log = ProtoLog::new();

        proto_log.set_address(self.address.0.to_vec());
        proto_log.topics = self
            .topics
            .clone()
            .into_iter()
            .map(|topic| topic.0.to_vec())
            .collect();
        proto_log.set_data(self.data.clone());
        proto_log
    }
}

/// Log localized.
#[derive(Default, Debug, Eq, PartialEq, Clone)]
pub struct LocalizedLog {
    pub log: Log,
    pub block_hash: H256,
    pub block_number: BlockNumber,
    pub transaction_hash: H256,
    pub transaction_index: usize,
    pub log_index: usize,
    pub transaction_log_index: usize,
}

impl Deref for LocalizedLog {
    type Target = Log;

    fn deref(&self) -> &Self::Target {
        &self.log
    }
}

impl From<LocalizedLog> for CloudLog {
    fn from(log: LocalizedLog) -> Self {
        Self {
            address: log.log.address.0.to_vec(),
            topics: log
                .log
                .topics
                .into_iter()
                .map(|topic| topic.0.to_vec())
                .collect(),
            data: log.log.data.to_vec(),
            block_hash: log.block_hash.0.to_vec(),
            block_number: log.block_number,
            transaction_hash: log.transaction_hash.0.to_vec(),
            transaction_index: log.transaction_index as u64,
            log_index: log.log_index as u64,
            transaction_log_index: log.transaction_log_index as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bloom, Log};
    use crate::types::{Address, H256};
    use std::str::FromStr;

    #[test]
    fn test_address_log_bloom() {
        let address = Address::default();
        let log = Log {
            address,
            topics: vec![],
            data: vec![],
        };
        let bloom = Bloom::from_str(
            "
            0000000000000000008000000000000000000000000000000000000000000000
            0000000000000000000000000000000200000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000100000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(log.bloom(), bloom);
    }

    #[test]
    fn test_address_and_topic_log_bloom() {
        let address = Address::default();
        let topics = vec![H256::zero()];
        let log = Log {
            address,
            topics,
            data: vec![],
        };
        let bloom: Bloom = Bloom::from_str(
            "
            0000000000000000008000000000000000000000000000000000000000000000
            0000000000000000000000000000000200000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000002000000000000000000080000000000000000000000000000000000
            0000000000000000000000000000000100000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000002000
            0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(log.bloom(), bloom);
    }

    #[test]
    fn test_address_topic_and_data_log_bloom() {
        let address = Address::default();
        let topics = vec![H256::zero()];
        let data = b"test".to_vec();
        let log = Log {
            address,
            topics,
            data,
        };
        let bloom = Bloom::from_str(
            "
            0000000000000000008000000000000000000000000000000000000000000000
            0000000000000000000000000000000200000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000002000000000000000000080000000000000000000000000000000000
            0000000000000000000000000000000100000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000002000
            0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(log.bloom(), bloom);
    }
}
