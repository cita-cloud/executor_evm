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

use crate::core_executor::data_provider::{BlockDataProvider, Store as VMSubState};
use crate::types::Bytes;
use crate::types::{Address, H160, H256, U256, U512};
use cita_trie::DB;
use cita_vm::{
    evm::{
        self, Context as EVMContext, Contract, InterpreterParams, InterpreterResult, Log as EVMLog,
    },
    state::{State, StateObjectInfo},
    summary, Error as VmError,
};
use rlp::RlpStream;
use std::cell::RefCell;
use std::sync::Arc;

use crate::core_executor::cita_vm_helper::{call_pure, get_interpreter_conf};
use crate::core_executor::exception::ExecutedException;
use crate::core_executor::tx_gas_schedule::TxGasSchedule;
use crate::types::context::Context;
use crate::types::errors::ExecutionError;
use crate::types::log::Log;
use crate::types::transaction::{Action, SignedTransaction};
use ethbloom::{Bloom, Input as BloomInput};

/// See: https://github.com/ethereum/EIPs/issues/659
const MAX_CREATE_CODE_SIZE: u64 = std::u64::MAX;

// FIXME: CITAExecutive need rename to Executive after all works ready.
pub struct CitaExecutive<'a, B> {
    block_provider: Arc<dyn BlockDataProvider>,
    state_provider: Arc<RefCell<State<B>>>,
    context: &'a Context,
}

impl<'a, B: DB + 'static> CitaExecutive<'a, B> {
    pub fn new(
        block_provider: Arc<dyn BlockDataProvider>,
        state: Arc<RefCell<State<B>>>,
        context: &'a Context,
    ) -> Self {
        Self {
            block_provider,
            state_provider: state,
            context,
        }
    }

    pub fn exec(&mut self, t: &SignedTransaction) -> Result<ExecutedResult, ExecutionError> {
        let sender = *t.sender();
        let nonce = self.state_provider.borrow_mut().nonce(&sender)?;
        trace!("transaction sender: {:?}, nonce: {:?}", sender, nonce);
        self.state_provider.borrow_mut().inc_nonce(&sender)?;

        let tx_gas_schedule = TxGasSchedule::default();
        let base_gas_required = match t.action {
            Action::Create => tx_gas_schedule.tx_create_gas,
            _ => tx_gas_schedule.tx_gas,
        } + match t.version {
            0..=2 => 0,
            _ => t.data.len() * tx_gas_schedule.tx_data_non_zero_gas,
        };
        if sender != Address::zero() && t.gas < U256::from(base_gas_required) {
            // FIXME: It is better to change NotEnoughBaseGas to
            //    NotEnoughBaseGas {
            //        required: U256,
            //        got: U256,
            //    }
            // Need to change VmError defined in cita-vm.
            return Err(ExecutionError::NotEnoughBaseGas);
        }

        if t.action == Action::AbiStore && !self.transact_set_abi(&t.data) {
            return Err(ExecutionError::InvalidTransaction);
        }

        // Prepaid t.gas for the transaction.
        self.prepaid(t.sender(), t.gas, t.gas_price, t.value)?;
        let init_gas = t.gas - U256::from(base_gas_required);

        let store = VMSubState {
            evm_context: build_evm_context(&self.context.clone()),
            evm_cfg: get_interpreter_conf(),
            ..Default::default()
        };
        let store = Arc::new(RefCell::new(store));

        let result = match t.action {
            Action::Store | Action::AbiStore => {
                // Maybe use tx_gas_schedule.tx_data_non_zero_gas for each byte store, it is more reasonable.
                // But for the data compatible, just let it as tx_gas_schedule.create_data_gas for now.
                let store_gas_used = U256::from(t.data.len() * tx_gas_schedule.create_data_gas);
                if let Some(gas_left) = init_gas.checked_sub(store_gas_used) {
                    Ok(InterpreterResult::Normal(vec![], gas_left.as_u64(), vec![]))
                } else {
                    // FIXME: Should not return an error after self.prepaid().
                    // But for compatibility, should keep this. Need to be upgrade in new version.
                    return Err(ExecutionError::NotEnoughBaseGas);
                }
            }
            Action::Create => {
                // Note: Fees has been handle in cita_vm.
                let params = ExecutiveParams {
                    code_address: None,
                    sender,
                    to_address: None,
                    gas: init_gas,
                    gas_price: t.gas_price(),
                    value: t.value,
                    nonce,
                    data: Some(t.data.clone()),
                };

                let mut vm_exec_params = build_vm_exec_params(&params, self.state_provider.clone());
                if !self.payment_required() {
                    vm_exec_params.disable_transfer_value = true;
                }
                create(
                    self.block_provider.clone(),
                    self.state_provider.clone(),
                    store.clone(),
                    &vm_exec_params.into(),
                    CreateKind::FromAddressAndNonce,
                )
            }

            Action::AmendData => {
                unimplemented!()
            }
            Action::Call(ref address) => {
                let params = ExecutiveParams {
                    code_address: Some(*address),
                    sender,
                    to_address: Some(*address),
                    gas: init_gas,
                    gas_price: t.gas_price(),
                    value: t.value,
                    nonce,
                    data: Some(t.data.clone()),
                };
                let mut vm_exec_params = build_vm_exec_params(&params, self.state_provider.clone());
                if !self.payment_required() {
                    vm_exec_params.disable_transfer_value = true;
                }
                call(
                    self.block_provider.clone(),
                    self.state_provider.clone(),
                    store.clone(),
                    &vm_exec_params.into(),
                )
            }
        };

        let mut finalize_result = self.finalize(result, store, t.gas, sender, t.gas_price());
        finalize_result.account_nonce = nonce;
        Ok(finalize_result)
    }

    fn finalize(
        &mut self,
        result: Result<InterpreterResult, VmError>,
        store: Arc<RefCell<VMSubState>>,
        gas_limit: U256,
        sender: Address,
        gas_price: U256,
    ) -> ExecutedResult {
        let mut finalize_result = ExecutedResult::default();

        match result {
            Ok(InterpreterResult::Normal(output, gas_left, logs)) => {
                let refund = get_refund(store.clone(), sender, gas_limit.as_u64(), gas_left);
                let gas_left = gas_left + refund;
                if self.payment_required() {
                    if let Err(e) = liquidtion(
                        self.state_provider.clone(),
                        store.clone(),
                        sender,
                        gas_price,
                        gas_limit.as_u64(),
                        gas_left,
                    ) {
                        finalize_result.exception = Some(ExecutedException::Vm(e));
                        return finalize_result;
                    }
                }
                // Handle self destruct: Kill it.
                // Note: must after ends of the transaction.
                for e in store.borrow_mut().selfdestruct.drain() {
                    self.state_provider.borrow_mut().kill_contract(&e);
                }
                self.state_provider
                    .borrow_mut()
                    .kill_garbage(&store.borrow().inused.clone());
                finalize_result.quota_used = gas_limit - U256::from(gas_left);
                finalize_result.quota_left = U256::from(gas_left);
                finalize_result.logs = transform_logs(logs);
                finalize_result.logs_bloom = logs_to_bloom(&finalize_result.logs);
                trace!(
                    "Get data after executed the transaction [Normal]: {:?}",
                    output
                );
                finalize_result.output = output;
            }
            Ok(InterpreterResult::Revert(output, gas_left)) => {
                let refund = get_refund(store.clone(), sender, gas_limit.as_u64(), gas_left);
                let gas_left = gas_left + refund;
                if self.payment_required() {
                    if let Err(e) = liquidtion(
                        self.state_provider.clone(),
                        store.clone(),
                        sender,
                        gas_price,
                        gas_limit.as_u64(),
                        gas_left,
                    ) {
                        finalize_result.exception = Some(ExecutedException::Vm(e));
                        return finalize_result;
                    }
                }
                self.state_provider
                    .borrow_mut()
                    .kill_garbage(&store.borrow().inused.clone());

                finalize_result.quota_used = gas_limit - U256::from(gas_left);
                finalize_result.quota_left = U256::from(gas_left);
                finalize_result.exception = Some(ExecutedException::Reverted);
                trace!(
                    "Get data after executed the transaction [Revert]: {:?}",
                    output
                );
                finalize_result.output = output;
            }
            Ok(InterpreterResult::Create(output, gas_left, logs, addr)) => {
                let refund = get_refund(store.clone(), sender, gas_limit.as_u64(), gas_left);
                let gas_left = gas_left + refund;
                if self.payment_required() {
                    if let Err(e) = liquidtion(
                        self.state_provider.clone(),
                        store.clone(),
                        sender,
                        gas_price,
                        gas_limit.as_u64(),
                        gas_left,
                    ) {
                        finalize_result.exception = Some(ExecutedException::Vm(e));
                        return finalize_result;
                    }
                }

                for e in store.borrow_mut().selfdestruct.drain() {
                    self.state_provider.borrow_mut().kill_contract(&e);
                }
                self.state_provider
                    .borrow_mut()
                    .kill_garbage(&store.borrow().inused.clone());
                finalize_result.quota_used = gas_limit - U256::from(gas_left);
                finalize_result.quota_left = U256::from(gas_left);
                finalize_result.logs = transform_logs(logs);
                finalize_result.logs_bloom = logs_to_bloom(&finalize_result.logs);
                finalize_result.contract_address = Some(addr);

                trace!(
                "Get data after executed the transaction [Create], contract address: {:?}, contract data : {:?}",
                finalize_result.contract_address, output
                );
            }
            Err(e) => {
                if self.payment_required() {
                    if let Err(e) = liquidtion(
                        self.state_provider.clone(),
                        store.clone(),
                        sender,
                        gas_price,
                        gas_limit.as_u64(),
                        0,
                    ) {
                        finalize_result.exception = Some(ExecutedException::Vm(e));
                        return finalize_result;
                    }
                }
                self.state_provider
                    .borrow_mut()
                    .kill_garbage(&store.borrow().inused.clone());

                finalize_result.exception = Some(ExecutedException::Vm(e));
                finalize_result.quota_used = gas_limit;
                finalize_result.quota_left = U256::from(0);
            }
        }

        finalize_result
    }

    fn payment_required(&self) -> bool {
        false
    }

    fn prepaid(
        &mut self,
        sender: &H160,
        gas: U256,
        gas_price: U256,
        value: U256,
    ) -> Result<(), ExecutionError> {
        if self.payment_required() {
            let balance = self.state_provider.borrow_mut().balance(sender)?;
            let gas_cost = gas.full_mul(gas_price);
            let total_cost = U512::from(value) + gas_cost;

            // Avoid unaffordable transactions
            let balance512 = U512::from(balance);
            if balance512 < total_cost {
                return Err(ExecutionError::NotEnoughBalance);
            }

            let inner = gas_cost.0;
            let mut gas_arr = [0; 4];
            gas_arr.copy_from_slice(&inner[..4]);

            self.state_provider
                .borrow_mut()
                .sub_balance(sender, U256(gas_arr))?;
        }
        Ok(())
    }

    fn transact_set_abi(&mut self, data: &[u8]) -> bool {
        if data.len() <= 20 {
            return false;
        }
        let account = H160::from_slice(&data[..20]);
        let abi = &data[20..];

        let account_exist = self
            .state_provider
            .borrow_mut()
            .exist(&account)
            .unwrap_or(false);
        info!("Account-{:?} in state is {:?}", account, account_exist);

        account_exist
            && self
                .state_provider
                .borrow_mut()
                .set_abi(&account, abi.to_vec())
                .is_ok()
    }
}

/// Function create creates a new contract.
pub fn create<B: DB + 'static>(
    block_provider: Arc<dyn BlockDataProvider>,
    state_provider: Arc<RefCell<State<B>>>,
    store: Arc<RefCell<VMSubState>>,
    request: &InterpreterParams,
    create_kind: CreateKind,
) -> Result<evm::InterpreterResult, VmError> {
    debug!("create request={:?}", request);
    let address = match create_kind {
        CreateKind::FromAddressAndNonce => {
            // Generate new address created from address, nonce
            create_address_from_address_and_nonce(&request.sender, &request.nonce)
        }
        CreateKind::FromSaltAndCodeHash => {
            // Generate new address created from sender salt and code hash
            create_address_from_salt_and_code_hash(
                &request.sender,
                request.extra,
                request.input.clone(),
            )
        }
    };
    debug!("create address={:?}", address);
    // Ensure there's no existing contract already at the designated address
    if !can_create(state_provider.clone(), &address)? {
        return Err(VmError::ContractAlreadyExist);
    }
    // Make a checkpoint here
    state_provider.borrow_mut().checkpoint();
    // Create a new contract
    let balance = state_provider.borrow_mut().balance(&address)?;
    state_provider.borrow_mut().new_contract(
        &address,
        balance,
        // The init nonce for a new contract is one, see above documents.
        U256::zero(),
        // The init code should be none. Consider a situation: ContractA will create
        // ContractB with address 0x1ff...fff, but ContractB's init code contains some
        // op like "get code hash from 0x1ff..fff or get code size form 0x1ff...fff",
        // The right result should be "summary(none)" and "0".
        vec![],
    );
    let mut reqchan = request.clone();
    reqchan.address = address;
    reqchan.receiver = address;
    reqchan.is_create = false;
    reqchan.input = vec![];
    reqchan.contract = evm::Contract {
        code_address: address,
        code_data: request.input.clone(),
    };
    let r = call(
        block_provider.clone(),
        state_provider.clone(),
        store,
        &reqchan,
    );
    match r {
        Ok(evm::InterpreterResult::Normal(output, gas_left, logs)) => {
            // Ensure code size
            if output.len() as u64 > MAX_CREATE_CODE_SIZE {
                state_provider.borrow_mut().revert_checkpoint();
                return Err(VmError::ExccedMaxCodeSize);
            }
            let tx_gas_schedule = TxGasSchedule::default();
            // Pay every byte returnd from CREATE
            let gas_code_deposit: u64 =
                tx_gas_schedule.create_data_gas as u64 * output.len() as u64;
            if gas_left < gas_code_deposit {
                state_provider.borrow_mut().revert_checkpoint();
                return Err(VmError::Evm(evm::Error::OutOfGas));
            }
            let gas_left = gas_left - gas_code_deposit;
            state_provider
                .borrow_mut()
                .set_code(&address, output.clone())?;
            state_provider.borrow_mut().discard_checkpoint();
            let r = Ok(evm::InterpreterResult::Create(
                output, gas_left, logs, address,
            ));
            debug!("create result={:?}", r);
            debug!("create gas_left={:?}", gas_left);
            r
        }
        Ok(evm::InterpreterResult::Revert(output, gas_left)) => {
            state_provider.borrow_mut().revert_checkpoint();
            let r = Ok(evm::InterpreterResult::Revert(output, gas_left));
            debug!("create gas_left={:?}", gas_left);
            debug!("create result={:?}", r);
            r
        }
        Err(e) => {
            debug!("create err={:?}", e);
            state_provider.borrow_mut().revert_checkpoint();
            Err(e)
        }
        _ => unimplemented!(),
    }
}

/// Function call enters into the specific contract.
pub fn call<B: DB + 'static>(
    block_provider: Arc<dyn BlockDataProvider>,
    state_provider: Arc<RefCell<State<B>>>,
    store: Arc<RefCell<VMSubState>>,
    request: &InterpreterParams,
) -> Result<evm::InterpreterResult, VmError> {
    // Here not need check twice,becauce prepay is subed ,but need think call_static
    /*if !request.disable_transfer_value && state_provider.borrow_mut().balance(&request.sender)? < request.value {
        return Err(err::Error::NotEnoughBalance);
    }*/
    // Run
    state_provider.borrow_mut().checkpoint();
    let store_son = Arc::new(RefCell::new(store.borrow_mut().clone()));

    let r = call_pure(
        block_provider.clone(),
        state_provider.clone(),
        store_son.clone(),
        request,
    );
    match r {
        Ok(evm::InterpreterResult::Normal(output, gas_left, logs)) => {
            state_provider.borrow_mut().discard_checkpoint();
            store.borrow_mut().merge(store_son);
            Ok(evm::InterpreterResult::Normal(output, gas_left, logs))
        }
        Ok(evm::InterpreterResult::Revert(output, gas_left)) => {
            state_provider.borrow_mut().revert_checkpoint();
            Ok(evm::InterpreterResult::Revert(output, gas_left))
        }
        Err(e) => {
            state_provider.borrow_mut().revert_checkpoint();
            Err(e)
        }
        _ => unimplemented!(),
    }
}

pub fn build_evm_context(context: &Context) -> EVMContext {
    EVMContext {
        gas_limit: context.block_quota_limit.as_u64(),
        coinbase: context.coin_base,
        number: U256::from(context.block_number),
        timestamp: context.timestamp,
        difficulty: context.difficulty,
    }
}

/// Function get_refund returns the real ammount to refund for a transaction.
fn get_refund(
    store: Arc<RefCell<VMSubState>>,
    origin: Address,
    gas_limit: u64,
    gas_left: u64,
) -> u64 {
    let refunds_bound = match store.borrow().refund.get(&origin) {
        Some(&data) => data,
        None => 0u64,
    };
    // Get real ammount to refund
    std::cmp::min(refunds_bound, (gas_limit - gas_left) >> 1)
}

/// Liquidtion for a transaction.
fn liquidtion<B: DB + 'static>(
    state_provider: Arc<RefCell<State<B>>>,
    store: Arc<RefCell<VMSubState>>,
    sender: Address,
    gas_price: U256,
    gas_limit: u64,
    gas_left: u64,
) -> Result<(), VmError> {
    trace!(
        "gas_price: {:?}, gas limit:{:?}, gas left: {:?}",
        gas_price,
        gas_limit,
        gas_left,
    );
    state_provider
        .borrow_mut()
        .add_balance(&sender, gas_price * gas_left)?;
    state_provider.borrow_mut().add_balance(
        &store.borrow().evm_context.coinbase,
        gas_price * (gas_limit - gas_left),
    )?;
    Ok(())
}

fn transform_logs(logs: Vec<EVMLog>) -> Vec<Log> {
    logs.into_iter()
        .map(|log| {
            let EVMLog(address, topics, data) = log;

            Log {
                address,
                topics,
                data,
            }
        })
        .collect()
}

fn logs_to_bloom(logs: &[Log]) -> Bloom {
    let mut bloom = Bloom::default();

    logs.iter().for_each(|log| accrue_log(&mut bloom, log));
    bloom
}

fn accrue_log(bloom: &mut Bloom, log: &Log) {
    bloom.accrue(BloomInput::Raw(&log.address.0));
    for topic in &log.topics {
        let input = BloomInput::Hash(&topic.0);
        bloom.accrue(input);
    }
}

/// Returns new address created from address and nonce.
pub fn create_address_from_address_and_nonce(address: &Address, nonce: &U256) -> Address {
    let mut stream = RlpStream::new_list(2);
    stream.append(address);
    stream.append(nonce);
    Address::from(H256::from_slice(summary(stream.as_raw()).as_slice()))
}

/// Returns new address created from sender salt and code hash.
/// See: EIP 1014.
pub fn create_address_from_salt_and_code_hash(
    address: &Address,
    salt: H256,
    code: Vec<u8>,
) -> Address {
    let code_hash = &summary(&code[..])[..];
    let mut buffer = [0u8; 1 + 20 + 32 + 32];
    buffer[0] = 0xff;
    buffer[1..=20].copy_from_slice(&address[..]);
    buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
    buffer[(1 + 20 + 32)..].copy_from_slice(code_hash);
    Address::from(H256::from_slice(summary(&buffer[..]).as_slice()))
}

/// If a contract creation is attempted, due to either a creation transaction
/// or the CREATE (or future CREATE2) opcode, and the destination address
/// already has either nonzero nonce, or nonempty code, then the creation
/// throws immediately, with exactly the same behavior as would arise if the
/// first byte in the init code were an invalid opcode. This applies
/// retroactively starting from genesis.
///
/// See: EIP 684
pub fn can_create<B: DB + 'static>(
    state_provider: Arc<RefCell<State<B>>>,
    address: &Address,
) -> Result<bool, VmError> {
    let a = state_provider.borrow_mut().nonce(address)?;
    let b = state_provider.borrow_mut().code(address)?;
    Ok(a.is_zero() && b.is_empty())
}

#[derive(Clone, Debug)]
pub struct ExecutiveParams {
    /// Address of currently executed code.
    pub code_address: Option<Address>,
    /// Sender of current part of the transaction.
    pub sender: Address,
    /// Receive address. Usually equal to code_address,
    pub to_address: Option<Address>,
    /// Gas paid up front for transaction execution
    pub gas: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Transaction value.
    pub value: U256,
    /// nonce
    pub nonce: U256,
    /// Input data.
    pub data: Option<Bytes>,
}

impl Default for ExecutiveParams {
    /// Returns default ActionParams initialized with zeros
    fn default() -> ExecutiveParams {
        ExecutiveParams {
            code_address: None,
            sender: Address::zero(),
            to_address: None,
            gas: U256::zero(),
            gas_price: U256::zero(),
            value: U256::zero(),
            nonce: U256::zero(),
            data: None,
        }
    }
}

pub fn build_vm_exec_params<B: DB + 'static>(
    params: &ExecutiveParams,
    state_provider: Arc<RefCell<State<B>>>,
) -> VmExecParams {
    let mut vm_exec_params = VmExecParams {
        origin: params.sender,
        sender: params.sender,
        ..Default::default()
    };
    if let Some(data) = params.to_address {
        vm_exec_params.to_address = data;
        vm_exec_params.storage_address = data;
        vm_exec_params.code_address = data;
        vm_exec_params.code_data = state_provider.borrow_mut().code(&data).unwrap_or_default();
    }

    vm_exec_params.gas_price = params.gas_price;
    vm_exec_params.gas = params.gas.as_u64();
    vm_exec_params.value = params.value;
    vm_exec_params.data = params.data.clone().unwrap_or_default();
    vm_exec_params.nonce = params.nonce;
    vm_exec_params
}

#[derive(Clone, Debug, Default)]
pub struct VmExecParams {
    pub origin: Address,
    pub storage_address: Address,
    /// Address of currently executed code.
    pub code_address: Address,
    pub code_data: Vec<u8>,
    /// Sender of current part of the transaction.
    pub sender: Address,
    /// Receive address. Usually equal to code_address,
    pub to_address: Address,
    /// Gas paid up front for transaction execution
    pub gas: u64,
    /// Gas price.
    pub gas_price: U256,
    pub base_fee: U256,
    /// Transaction value.
    pub value: U256,
    /// nonce
    pub nonce: U256,
    /// Input data.
    pub data: Bytes,
    pub read_only: bool,
    pub extra: H256,
    pub depth: u64,
    pub disable_transfer_value: bool,
}

impl From<InterpreterParams> for VmExecParams {
    fn from(params: InterpreterParams) -> Self {
        Self {
            origin: params.origin,
            storage_address: params.address,
            code_address: params.contract.code_address,
            code_data: params.contract.code_data,
            sender: params.sender,
            to_address: params.receiver,
            gas: params.gas_limit,
            gas_price: params.gas_price,
            value: params.value,
            nonce: params.nonce,
            data: params.input.clone(),
            read_only: params.read_only,
            extra: params.extra,
            depth: params.depth,
            disable_transfer_value: params.disable_transfer_value,
            base_fee: params.base_fee,
        }
    }
}

impl From<VmExecParams> for InterpreterParams {
    fn from(params: VmExecParams) -> Self {
        Self {
            origin: params.origin,
            address: params.storage_address,
            contract: Contract {
                code_address: params.code_address,
                code_data: params.code_data,
            },
            sender: params.sender,
            receiver: params.to_address,
            gas_limit: params.gas,
            gas_price: params.gas_price,
            value: params.value,
            nonce: params.nonce,
            input: params.data.clone(),
            read_only: params.read_only,
            extra: params.extra,
            depth: params.depth,
            is_create: false,
            disable_transfer_value: params.disable_transfer_value,
            base_fee: params.base_fee,
        }
    }
}

/// A selector for func create_address_from_address_and_nonce() and
/// create_address_from_salt_and_code_hash()
pub enum CreateKind {
    FromAddressAndNonce, // use create_address_from_address_and_nonce
    FromSaltAndCodeHash, // use create_address_from_salt_and_code_hash
}

#[derive(Default, Debug)]
pub struct ExecutedResult {
    pub state_root: H256,
    pub transaction_hash: H256,
    pub quota_used: U256,
    pub quota_left: U256,
    pub logs_bloom: Bloom,
    pub logs: Vec<Log>,
    pub exception: Option<ExecutedException>,
    pub contract_address: Option<Address>,
    pub account_nonce: U256,

    // Note: if the transaction is a cita-evm call, needn't to handle the refund.
    // FIXME: Maybe it is better to handle refund out of evm.
    pub is_evm_call: bool,

    /// Transaction output.
    pub output: Bytes,
}
