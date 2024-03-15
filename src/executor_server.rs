use std::sync::Arc;

use crate::core_executor::libexecutor::call_request::CallRequest;
use crate::core_executor::libexecutor::command::{Command, CommandResp, Commander};
use crate::core_executor::libexecutor::executor::Executor;
use crate::core_executor::libexecutor::ExecutedResult;
use crate::types::block::OpenBlock;
use crate::types::block_number::{BlockTag, Tag};
use crate::types::{Address, H256};
use cita_cloud_proto::blockchain::raw_transaction::Tx as CloudTx;
use cita_cloud_proto::blockchain::Block as CloudBlock;
use cita_cloud_proto::common::{Hash as CloudHash, HashResponse};
use cita_cloud_proto::evm::rpc_service_server::RpcService;
use cita_cloud_proto::evm::{
    Balance as CloudBalance, BlockNumber, ByteAbi as CloudByteAbi, ByteCode as CloudByteCode,
    ByteQuota as CloudByteQuota, GetAbiRequest, GetBalanceRequest, GetCodeRequest,
    GetStorageAtRequest, GetTransactionCountRequest, Nonce as CloudNonce, Receipt as CloudReceipt,
    ReceiptProof, RootsInfo,
};
use cita_cloud_proto::executor::executor_service_server::ExecutorService;
use cita_cloud_proto::executor::{
    CallRequest as CloudCallRequest, CallResponse as CloudCallResponse,
};
use cita_cloud_proto::status_code::StatusCodeEnum;
use parking_lot::RwLock;
use tonic::{Code, Request, Response, Status};

pub struct ExecutedFinal {
    pub status: StatusCodeEnum,
    pub result: ExecutedResult,
}

#[derive(Clone)]
pub struct ExecutorServer {
    pub executor: Arc<RwLock<Executor>>,
}

#[tonic::async_trait]
impl ExecutorService for ExecutorServer {
    #[instrument(skip_all)]
    async fn exec(&self, request: Request<CloudBlock>) -> Result<Response<HashResponse>, Status> {
        cloud_util::tracer::set_parent(&request);
        let block = request.into_inner();
        debug!("get exec request: {:x?}", block);
        let mut open_blcok = OpenBlock::from(block.clone());
        info!("exec method invoke, height: {}", open_blcok.header.number());

        if let Some(body) = block.body {
            for raw_tx in body.body {
                match raw_tx.tx {
                    Some(CloudTx::NormalTx(utx)) => {
                        debug!(
                            "exec normal_tx hash: {}",
                            hex::encode(utx.transaction_hash.clone())
                        );
                        open_blcok.insert_cloud_tx(utx);
                    }
                    Some(CloudTx::UtxoTx(utxo)) => info!(
                        "block contains utxo(0x{})`",
                        hex::encode(&utxo.transaction_hash)
                    ),
                    None => {
                        return Ok(Response::new(HashResponse {
                            status: Some(StatusCodeEnum::NoneBlockBody.into()),
                            hash: None,
                        }));
                    }
                }
            }
        }

        let executed_final = self.executor.write().rpc_exec(open_blcok);

        let header = executed_final.result.get_executed_info().get_header();
        let state_root = header.get_state_root();
        let receipt_root = header.get_receipts_root();
        // hash = state_root ^ receipt_root, replace of state_root
        let hash = if header.height != 0 {
            state_root
                .iter()
                .zip(receipt_root.iter())
                .map(|(x, y)| x ^ y)
                .collect()
        } else {
            state_root.to_vec()
        };
        if executed_final.status.is_success().is_ok() {
            info!(
                "height: {}, state_root: 0x{}, receipt_root: 0x{}, app_hash: 0x{}",
                header.get_height(),
                hex::encode(state_root),
                hex::encode(receipt_root),
                hex::encode(&hash)
            );
            Ok(Response::new(HashResponse {
                status: Some(StatusCodeEnum::Success.into()),
                hash: Some(CloudHash { hash }),
            }))
        } else {
            info!(
                "exec: not success: {:?}, state_root: 0x{}, receipt_root: 0x{}, app_hash: 0x{}",
                header.get_height(),
                hex::encode(state_root),
                hex::encode(receipt_root),
                hex::encode(&hash)
            );
            Ok(Response::new(HashResponse {
                status: Some(executed_final.status.into()),
                hash: Some(CloudHash { hash }),
            }))
        }
    }

    #[instrument(skip_all)]
    async fn call(
        &self,
        request: Request<CloudCallRequest>,
    ) -> Result<Response<CloudCallResponse>, Status> {
        cloud_util::tracer::set_parent(&request);

        let cloud_call_request = request.into_inner();
        debug!("get call request: {:x?}", cloud_call_request);
        match self.executor.read().rpc_call(cloud_call_request.into()) {
            Ok(value) => Ok(Response::new(CloudCallResponse { value })),
            Err(str) => Err(Status::new(Code::InvalidArgument, str)),
        }
    }
}

#[tonic::async_trait]
impl RpcService for ExecutorServer {
    #[instrument(skip_all)]
    async fn get_transaction_receipt(
        &self,
        request: Request<CloudHash>,
    ) -> Result<Response<CloudReceipt>, Status> {
        cloud_util::tracer::set_parent(&request);
        let cloud_hash = request.into_inner();
        debug!("get_transaction_receipt request: {:x?}", cloud_hash);

        match self
            .executor
            .write()
            .operate(Command::ReceiptAt(H256::from_slice(
                cloud_hash.hash.as_slice(),
            ))) {
            CommandResp::ReceiptAt(Some(rich_receipt)) => Ok(Response::new(rich_receipt.into())),
            _ => Err(Status::new(Code::InvalidArgument, "Not get the receipt")),
        }
    }

    #[instrument(skip_all)]
    async fn get_code(
        &self,
        request: Request<GetCodeRequest>,
    ) -> Result<Response<CloudByteCode>, Status> {
        cloud_util::tracer::set_parent(&request);
        let raw_request = request.into_inner();
        debug!("get_code request: {:x?}", raw_request);

        if raw_request.address.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Address is none"));
        }

        if raw_request.block_number.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Block number is none"));
        }

        let resp = self.executor.write().operate(Command::CodeAt(
            Address::from_slice(raw_request.address.unwrap().address.as_slice()),
            raw_request.block_number.unwrap().into(),
        ));

        match resp {
            CommandResp::CodeAt(Some(byte_code)) => Ok(Response::new(CloudByteCode { byte_code })),
            _ => Err(Status::new(Code::InvalidArgument, "Not get the bytecode")),
        }
    }

    #[instrument(skip_all)]
    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<CloudBalance>, Status> {
        cloud_util::tracer::set_parent(&request);
        let raw_request = request.into_inner();
        debug!("get_balance request: {:x?}", raw_request);

        if raw_request.address.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Address is none"));
        }

        if raw_request.block_number.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Block number is none"));
        }

        let resp = self.executor.write().operate(Command::BalanceAt(
            Address::from_slice(raw_request.address.unwrap().address.as_slice()),
            raw_request.block_number.unwrap().into(),
        ));

        match resp {
            CommandResp::BalanceAt(Some(value)) => Ok(Response::new(CloudBalance { value })),
            _ => Err(Status::new(Code::InvalidArgument, "Not get the balance")),
        }
    }

    #[instrument(skip_all)]
    async fn get_transaction_count(
        &self,
        request: Request<GetTransactionCountRequest>,
    ) -> Result<Response<CloudNonce>, Status> {
        cloud_util::tracer::set_parent(&request);
        let raw_request = request.into_inner();
        debug!("get_transaction_count request: {:x?}", raw_request);

        if raw_request.address.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Address is none"));
        }

        if raw_request.block_number.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Block number is none"));
        }

        let resp = self.executor.write().operate(Command::NonceAt(
            Address::from_slice(raw_request.address.unwrap().address.as_slice()),
            raw_request.block_number.unwrap().into(),
        ));

        match resp {
            CommandResp::NonceAt(Some(value)) => {
                let mut nonce = vec![0; 32];
                value.to_big_endian(&mut nonce);
                Ok(Response::new(CloudNonce { nonce }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "Not get the nonce")),
        }
    }

    #[instrument(skip_all)]
    async fn get_abi(
        &self,
        request: Request<GetAbiRequest>,
    ) -> Result<Response<CloudByteAbi>, Status> {
        cloud_util::tracer::set_parent(&request);
        let raw_request = request.into_inner();
        debug!("get_abi request: {:x?}", raw_request);

        if raw_request.address.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Address is none"));
        }

        if raw_request.block_number.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Block number is none"));
        }

        let resp = self.executor.write().operate(Command::AbiAt(
            Address::from_slice(raw_request.address.unwrap().address.as_slice()),
            raw_request.block_number.unwrap().into(),
        ));

        match resp {
            CommandResp::AbiAt(Some(bytes_abi)) => Ok(Response::new(CloudByteAbi { bytes_abi })),
            _ => Err(Status::new(Code::InvalidArgument, "Not get the abi")),
        }
    }

    #[instrument(skip_all)]
    async fn estimate_quota(
        &self,
        request: Request<CloudCallRequest>,
    ) -> Result<Response<CloudByteQuota>, Status> {
        cloud_util::tracer::set_parent(&request);
        let call_request = CallRequest::from(request.into_inner());
        debug!("estimate_quota request: {:x?}", call_request);
        let block_tag = match call_request.height {
            Some(height) => BlockTag::Height(height),
            None => BlockTag::Tag(Tag::Pending),
        };
        let resp = self
            .executor
            .write()
            .operate(Command::EstimateQuota(call_request, block_tag));

        match resp {
            CommandResp::EstimateQuota(Ok(bytes_quota)) => {
                Ok(Response::new(CloudByteQuota { bytes_quota }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "estimate quota failed")),
        }
    }

    #[instrument(skip_all)]
    async fn get_receipt_proof(
        &self,
        request: Request<CloudHash>,
    ) -> Result<Response<ReceiptProof>, Status> {
        let cloud_hash = request.into_inner();
        debug!("get_receipt_proof request: {:x?}", cloud_hash);
        let resp = self
            .executor
            .write()
            .operate(Command::ReceiptProof(H256::from_slice(
                cloud_hash.hash.as_slice(),
            )));

        match resp {
            CommandResp::ReceiptProof(Some(receipt_proof)) => Ok(Response::new(receipt_proof)),
            _ => Err(Status::new(
                Code::InvalidArgument,
                "Not get the receipt proof",
            )),
        }
    }

    #[instrument(skip_all)]
    async fn get_roots_info(
        &self,
        request: Request<BlockNumber>,
    ) -> Result<Response<RootsInfo>, Status> {
        let block_number = request.into_inner();
        debug!("get_roots_info request: {:?}", block_number);
        let resp = self
            .executor
            .write()
            .operate(Command::RootsInfo(block_number.into()));

        match resp {
            CommandResp::RootsInfo(Some(roots_info)) => Ok(Response::new(roots_info)),
            _ => Err(Status::new(Code::InvalidArgument, "Not get the roots info")),
        }
    }

    #[instrument(skip_all)]
    async fn get_storage_at(
        &self,
        request: Request<GetStorageAtRequest>,
    ) -> Result<Response<CloudHash>, Status> {
        let raw_request = request.into_inner();
        debug!("get_storage_at request: {:?}", raw_request);

        if raw_request.address.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Address is none"));
        }

        if raw_request.position.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Position is none"));
        }

        if raw_request.block_number.is_none() {
            return Err(Status::new(Code::InvalidArgument, "Block number is none"));
        }

        let resp = self.executor.write().operate(Command::StorageAt(
            Address::from_slice(raw_request.address.unwrap().address.as_slice()),
            H256::from_slice(raw_request.position.unwrap().hash.as_slice()),
            raw_request.block_number.unwrap().into(),
        ));

        match resp {
            CommandResp::StorageAt(Some(value)) => Ok(Response::new(CloudHash {
                hash: value.0.to_vec(),
            })),
            _ => Err(Status::new(Code::InvalidArgument, "Not storage slot info")),
        }
    }
}
