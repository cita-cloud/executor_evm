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

use super::block::{ClosedBlock, ExecutedBlock, OpenBlock};
use super::executor::Executor;

#[cfg_attr(feature = "cargo-clippy", allow(clippy::large_enum_variant))]
pub enum StatusOfFsm {
    Initialize(OpenBlock),
    Pause(ExecutedBlock, usize),
    Execute(ExecutedBlock, usize),
    Finalize(ExecutedBlock),
}

impl std::fmt::Display for StatusOfFsm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match *self {
            StatusOfFsm::Initialize(ref open_block) => write!(
                f,
                "StatusOfFSM::Initialize(height: {}, parent_hash: {:?}, timestamp: {})",
                open_block.number(),
                open_block.parent_hash(),
                open_block.timestamp(),
            ),
            StatusOfFsm::Pause(ref executed_block, index) => write!(
                f,
                "StatusOfFSM::Pause(height: {}, parent_hash: {:?}, state_root: {:?}, timestamp: {}, index: {})",
                executed_block.number(),
                executed_block.parent_hash(),
                executed_block.state_root,
                executed_block.timestamp(),
                index,
            ),
            StatusOfFsm::Execute(ref executed_block, index) => write!(
                f,
                "StatusOfFSM::Execute(height: {}, parent_hash: {:?}, state_root: {:?}, timestamp: {}, index: {})",
                executed_block.number(),
                executed_block.parent_hash(),
                executed_block.state_root,
                executed_block.timestamp(),
                index,
            ),
            StatusOfFsm::Finalize(ref executed_block) => write!(
                f,
                "StatusOfFSM::Finalize(height: {}, parent_hash: {:?}, state_root: {:?}, timestamp: {})",
                executed_block.number(),
                executed_block.parent_hash(),
                executed_block.state_root,
                executed_block.timestamp(),
            ),
        }
    }
}

pub trait Fsm {
    fn before_fsm(&mut self, open_block: OpenBlock) -> ClosedBlock;
    fn fsm_initialize(&self, open_block: OpenBlock) -> StatusOfFsm;
    fn fsm_pause(&self, executed_block: ExecutedBlock, index: usize) -> StatusOfFsm;
    fn fsm_execute(&self, executed_block: ExecutedBlock, index: usize) -> StatusOfFsm;
    fn fsm_finalize(&self, executed_block: ExecutedBlock) -> ClosedBlock;
}

impl Fsm for Executor {
    fn before_fsm(&mut self, open_block: OpenBlock) -> ClosedBlock {
        let mut status = StatusOfFsm::Initialize(open_block);
        loop {
            trace!("executor is at {}", status);
            status = match status {
                StatusOfFsm::Initialize(open_block) => self.fsm_initialize(open_block),
                StatusOfFsm::Pause(executed_block, index) => self.fsm_pause(executed_block, index),
                StatusOfFsm::Execute(executed_block, index) => {
                    self.fsm_execute(executed_block, index)
                }
                StatusOfFsm::Finalize(executed_block) => return self.fsm_finalize(executed_block),
            }
        }
    }

    fn fsm_initialize(&self, open_block: OpenBlock) -> StatusOfFsm {
        let executed_block = self.to_executed_block(open_block);
        StatusOfFsm::Pause(executed_block, 0)
    }

    fn fsm_pause(&self, executed_block: ExecutedBlock, index: usize) -> StatusOfFsm {
        if index == executed_block.body().transactions().len() {
            StatusOfFsm::Finalize(executed_block)
        } else {
            StatusOfFsm::Execute(executed_block, index + 1)
        }
    }

    fn fsm_execute(&self, mut executed_block: ExecutedBlock, index: usize) -> StatusOfFsm {
        let transaction = executed_block.body().transactions[index - 1].clone();
        executed_block.apply_transaction(&transaction);
        StatusOfFsm::Pause(executed_block, index)
    }

    fn fsm_finalize(&self, executed_block: ExecutedBlock) -> ClosedBlock {
        executed_block
            .state
            .borrow_mut()
            .commit()
            .expect("Commit state error.");
        executed_block.close()
    }
}
