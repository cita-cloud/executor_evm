use crate::core_executor::libexecutor::call_request::CallRequest;
use crate::core_executor::libexecutor::command::{Command, CommandResp};
use crate::core_executor::libexecutor::ExecutedResult;
use crate::types::block::OpenBlock;
use crate::types::block_number::{BlockTag, Tag};
use crate::types::Bytes;
use crate::types::{Address, H256};
use cita_cloud_proto::blockchain::raw_transaction::Tx as CloudTx;
use cita_cloud_proto::blockchain::Block as CloudBlock;
use cita_cloud_proto::common::{Address as CloudAddress, Hash as CloudHash, HashResponse};
use cita_cloud_proto::evm::rpc_service_server::RpcService;
use cita_cloud_proto::evm::{
    Balance as CloudBalance, ByteAbi as CloudByteAbi, ByteCode as CloudByteCode,
    ByteQuota as CloudByteQuota, Nonce as CloudNonce, Receipt as CloudReceipt,
};
use cita_cloud_proto::executor::executor_service_server::ExecutorService;
use cita_cloud_proto::executor::{
    CallRequest as CloudCallRequest, CallResponse as CloudCallResponse,
};
use cita_cloud_proto::status_code::StatusCodeEnum;
use crossbeam_channel::{Receiver, Sender};
use log::{debug, info, warn};
use tonic::{Code, Request, Response, Status};

pub struct ExecutedFinal {
    pub status: StatusCodeEnum,
    pub result: ExecutedResult,
}

#[derive(Clone)]
pub struct ExecutorServer {
    pub exec_req_sender: Sender<OpenBlock>,
    pub exec_resp_receiver: Receiver<ExecutedFinal>,
    pub call_req_sender: Sender<CloudCallRequest>,
    pub call_resp_receiver: Receiver<Result<Bytes, String>>,
    pub command_req_sender: Sender<Command>,
    pub command_resp_receiver: Receiver<CommandResp>,
}

fn check_cloud_block(block: &CloudBlock) -> bool {
    if let Some(header) = &block.header {
        if header.prevhash.len() != 32
            || header.transactions_root.len() != 32
            || (header.height == 0 && header.proposer.len() != 32)
            || (header.height != 0 && header.proposer.len() != 20)
        {
            return false;
        }
    } else {
        return false;
    }
    if let Some(body) = &block.body {
        for raw_tx in &body.body {
            if let Some(CloudTx::NormalTx(utx)) = &raw_tx.tx {
                if utx.transaction_hash.len() != 32 {
                    return false;
                }
                if let Some(tx) = &utx.transaction {
                    if tx.chain_id.len() > 32
                        || tx.nonce.len() > 128
                        || (tx.to.len() != 20 && tx.to.len() != 0)
                        || tx.value.len() > 32
                    {
                        return false;
                    }
                } else {
                    return false;
                }
                if let Some(witness) = &utx.witness {
                    if witness.sender.len() != 20 {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
    }
    return true;
}

#[tonic::async_trait]
impl ExecutorService for ExecutorServer {
    async fn exec(&self, request: Request<CloudBlock>) -> Result<Response<HashResponse>, Status> {
        let block = request.into_inner();
        if !check_cloud_block(&block) {
            return Err(Status::new(
                Code::InvalidArgument,
                "Not allowed rpc invoke.",
            ));
        }

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

        if self.exec_req_sender.send(open_blcok).is_err() {
            warn!("exec: sending on a disconnected channel");
            return Ok(Response::new(HashResponse {
                status: Some(StatusCodeEnum::InternalChannelDisconnected.into()),
                hash: None,
            }));
        }

        match self.exec_resp_receiver.recv() {
            Ok(executed_final) => {
                let header = executed_final.result.get_executed_info().get_header();
                let state_root = header.get_state_root();
                if executed_final.status.is_success().is_ok() {
                    info!(
                        "height: {}, state_root: 0x{}",
                        header.get_height(),
                        hex::encode(state_root)
                    );
                    Ok(Response::new(HashResponse {
                        status: Some(StatusCodeEnum::Success.into()),
                        hash: Some(CloudHash {
                            hash: state_root.to_vec(),
                        }),
                    }))
                } else {
                    info!(
                        "exec: not success: {:?}, state_root: 0x{}",
                        executed_final.status,
                        hex::encode(state_root)
                    );
                    Ok(Response::new(HashResponse {
                        status: Some(executed_final.status.into()),
                        hash: Some(CloudHash {
                            hash: state_root.to_vec(),
                        }),
                    }))
                }
            }
            Err(recv_error) => {
                warn!("exec: recv error: {}", recv_error.to_string());
                Ok(Response::new(HashResponse {
                    status: Some(StatusCodeEnum::InternalChannelDisconnected.into()),
                    hash: None,
                }))
            }
        }
    }

    async fn call(
        &self,
        request: Request<CloudCallRequest>,
    ) -> Result<Response<CloudCallResponse>, Status> {
        let cloud_request = request.into_inner();
        if cloud_request.to.len() != 20
            || (!cloud_request.from.is_empty() && cloud_request.from.len() != 20)
        {
            return Err(Status::new(
                Code::InvalidArgument,
                "Call request's from or to address invalid",
            ));
        }
        let _ = self.call_req_sender.send(cloud_request);

        match self.call_resp_receiver.recv() {
            Ok(call_result) => match call_result {
                Ok(value) => Ok(Response::new(CloudCallResponse { value })),
                Err(str) => Err(Status::new(Code::InvalidArgument, str)),
            },
            Err(recv_error) => Err(Status::new(Code::InvalidArgument, recv_error.to_string())),
        }
    }
}

#[tonic::async_trait]
impl RpcService for ExecutorServer {
    async fn get_transaction_receipt(
        &self,
        request: Request<CloudHash>,
    ) -> Result<Response<CloudReceipt>, Status> {
        let cloud_hash = request.into_inner();
        let hash = cloud_hash.hash;
        if hash.len() != 32 {
            return Err(Status::new(
                Code::InvalidArgument,
                "Transaction hash length must be 32.",
            ));
        }
        let _ = self
            .command_req_sender
            .send(Command::ReceiptAt(H256::from_slice(hash.as_slice())));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::ReceiptAt(Some(rich_receipt))) => {
                Ok(Response::new(rich_receipt.into()))
            }
            _ => Err(Status::new(Code::InvalidArgument, "Not get the receipt")),
        }
    }

    async fn get_code(
        &self,
        request: Request<CloudAddress>,
    ) -> Result<Response<CloudByteCode>, Status> {
        let cloud_address = request.into_inner();
        let address = cloud_address.address;
        if address.len() != 20 {
            return Err(Status::new(
                Code::InvalidArgument,
                "Contract address length must be 20.",
            ));
        }
        let _ = self.command_req_sender.send(Command::CodeAt(
            Address::from_slice(address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::CodeAt(Some(byte_code))) => {
                Ok(Response::new(CloudByteCode { byte_code }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "Not get the bytecode")),
        }
    }

    async fn get_balance(
        &self,
        request: Request<CloudAddress>,
    ) -> Result<Response<CloudBalance>, Status> {
        let cloud_address = request.into_inner();
        let address = cloud_address.address;
        if address.len() != 20 {
            return Err(Status::new(
                Code::InvalidArgument,
                "Address length must be 20.",
            ));
        }
        let _ = self.command_req_sender.send(Command::BalanceAt(
            Address::from_slice(address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::BalanceAt(Some(value))) => Ok(Response::new(CloudBalance { value })),
            _ => Err(Status::new(Code::InvalidArgument, "Not get the balance")),
        }
    }

    async fn get_transaction_count(
        &self,
        request: Request<CloudAddress>,
    ) -> Result<Response<CloudNonce>, Status> {
        let cloud_address = request.into_inner();
        let address = cloud_address.address;
        if address.len() != 20 {
            return Err(Status::new(
                Code::InvalidArgument,
                "Address length must be 20.",
            ));
        }
        let _ = self.command_req_sender.send(Command::NonceAt(
            Address::from_slice(address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::NonceAt(Some(value))) => {
                let mut nonce = vec![0; 32];
                value.to_big_endian(&mut nonce);
                Ok(Response::new(CloudNonce { nonce }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "Not get the nonce")),
        }
    }

    async fn get_abi(
        &self,
        request: Request<CloudAddress>,
    ) -> Result<Response<CloudByteAbi>, Status> {
        let cloud_address = request.into_inner();
        let address = cloud_address.address;
        if address.len() != 20 {
            return Err(Status::new(
                Code::InvalidArgument,
                "Contract address length must be 20.",
            ));
        }
        let _ = self.command_req_sender.send(Command::AbiAt(
            Address::from_slice(address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::AbiAt(Some(bytes_abi))) => {
                Ok(Response::new(CloudByteAbi { bytes_abi }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "Not get the abi")),
        }
    }

    async fn estimate_quota(
        &self,
        request: Request<CloudCallRequest>,
    ) -> Result<Response<CloudByteQuota>, Status> {
        let cloud_request = request.into_inner();
        if cloud_request.to.len() != 20
            || (!cloud_request.from.is_empty() && cloud_request.from.len() != 20)
        {
            return Err(Status::new(
                Code::InvalidArgument,
                "Call request's from or to address invalid",
            ));
        }
        let call_request = CallRequest::from(cloud_request);
        let _ = self.command_req_sender.send(Command::EstimateQuota(
            call_request,
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::EstimateQuota(Ok(bytes_quota))) => {
                Ok(Response::new(CloudByteQuota { bytes_quota }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "estimate quota failed")),
        }
    }
}
