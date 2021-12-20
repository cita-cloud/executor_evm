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

use crate::core_executor::libexecutor::block::OpenBlock;
use crate::core_executor::libexecutor::command::Commander;
use crate::core_executor::libexecutor::executor::Executor;
use crate::core_executor::libexecutor::fsm::Fsm;
use crate::tests::helpers;
use crate::types::Address;
use cita_crypto::{CreateKey, KeyPair};
use test::Bencher;

fn generate_block(executor: &Executor, txs: u32) -> OpenBlock {
    let keypair = KeyPair::gen_keypair();
    let privkey = keypair.privkey();
    let data = helpers::generate_contract();
    helpers::create_block(
        &executor,
        Address::from_low_u64_le(0),
        &data,
        (0, txs),
        &privkey,
    )
}

#[bench]
fn test_block_with_10000_tx(b: &mut Bencher) {
    // One block with 10000 tx bench test takes 271.51ms
    let mut executor = helpers::init_executor();
    let block = generate_block(&executor, 10000);

    b.iter(|| {
        executor.before_fsm(block.clone());
    });
}

#[bench]
fn test_block_with_30000_tx(b: &mut Bencher) {
    // One block with 30000 tx bench test takes 886.39ms
    let mut executor = helpers::init_executor();
    let block = generate_block(&executor, 30000);

    b.iter(|| {
        executor.before_fsm(block.clone());
    });
}

#[bench]
fn test_block_with_50000_tx(b: &mut Bencher) {
    // One block with 50000 tx bench test takes 1424.51ms
    let mut executor = helpers::init_executor();
    let block = generate_block(&executor, 50000);

    b.iter(|| {
        executor.before_fsm(block.clone());
    });
}

#[bench]
fn test_block_with_10000_tx_write_db(b: &mut Bencher) {
    // One block with 10000 tx bench test takes 1551.8ms
    let mut executor = helpers::init_executor();
    let block = generate_block(&executor, 10000);

    b.iter(|| {
        let mut closed_block = executor.before_fsm(block.clone());
        executor.grow(&closed_block);
        closed_block.clear_cache();
    });
}
