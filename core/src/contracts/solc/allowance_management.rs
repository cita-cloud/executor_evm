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

//! Allowance management.
use std::collections::HashMap;
use std::str::FromStr;

use crate::authentication::AllowanceType;
use crate::contracts::solc::ContractCallExt;
use crate::contracts::tools::{decode as decode_tools, method as method_tools};
use crate::libexecutor::executor::Executor;
use crate::types::block_number::BlockTag;
use crate::types::reserved_addresses;
use cita_types::{Address, H160};

const ALLOWANCES: &[u8] = &*b"queryDoornum()";

lazy_static! {
    static ref ALLOWANCES_HASH: Vec<u8> = method_tools::encode_to_vec(ALLOWANCES);
    static ref CONTRACT_ADDRESS: H160 = H160::from_str(reserved_addresses::ALLOWANCE).unwrap();
}

#[derive(PartialEq, Clone, Default, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord)]
pub struct Doornum {
    pub door: Address,
    pub num: Vec<u8>,
}

impl Doornum {
    pub fn new(door: Address, num: Vec<u8>) -> Self {
        Doornum { door, num }
    }

    pub fn set_door(&mut self, addr: Address) {
        self.door = addr;
    }

    pub fn get_door(&self) -> Address {
        self.door
    }

    pub fn set_num(&mut self, num: Vec<u8>) {
        self.num = num;
    }

    pub fn get_num(&self) -> &Vec<u8> {
        &self.num
    }
}

pub struct AllowanceManagement<'a> {
    executor: &'a Executor,
}

impl<'a> AllowanceManagement<'a> {
    pub fn new(executor: &'a Executor) -> Self {
        AllowanceManagement { executor }
    }

    pub fn load_account_allowances(&self, block_tag: BlockTag) -> HashMap<Address, AllowanceType> {
        let mut account_allowances = HashMap::new();
        let doornums = self
            .allowance(block_tag)
            .unwrap_or_else(Self::default_doornums);
        for doornum in doornums {
            account_allowances.insert(doornum.door, AllowanceType::from(doornum.num));
        }

        account_allowances
    }

    /// allowance array
    pub fn allowance(&self, block_tag: BlockTag) -> Option<Vec<Doornum>> {
        self.executor
            .call_method(
                &*CONTRACT_ADDRESS,
                &*ALLOWANCES_HASH.as_slice(),
                None,
                block_tag,
            )
            .ok()
            .and_then(|output| decode_tools::to_doornum_vec(&output))
    }

    pub fn default_doornums() -> Vec<Doornum> {
        info!("Use default doornums.");
        Vec::new()
    }
}
