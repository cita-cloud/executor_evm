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

use crate::types::H256;
use cita_cloud_proto::evm::block_number::Lable;

pub type TransactionHash = H256;
pub type BlockNumber = u64;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum BlockTag {
    Tag(Tag),
    Height(u64),
    Hash(H256),
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Tag {
    Latest,
    Earliest,
    Pending,
}

impl From<cita_cloud_proto::evm::BlockNumber> for BlockTag {
    fn from(block_number: cita_cloud_proto::evm::BlockNumber) -> Self {
        match block_number.lable.unwrap() {
            Lable::Height(number) => BlockTag::Height(number),
            Lable::Hash(hash) => BlockTag::Hash(H256::from_slice(&hash)),
            Lable::Tag(tag) => match tag.as_str() {
                "earliest" => BlockTag::Tag(Tag::Earliest),
                "pending" => BlockTag::Tag(Tag::Pending),
                _ => BlockTag::Tag(Tag::Latest),
            },
        }
    }
}
