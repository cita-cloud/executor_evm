use crate::core_executor::libexecutor::command::{Command, CommandResp};
use crate::core_executor::libexecutor::ExecutedResult;
use crate::types::block::OpenBlock;
use crate::types::block_number::{BlockTag, Tag};
use crate::types::Bytes;
use crate::types::{Address, H256};
use cita_cloud_proto::blockchain::raw_transaction::Tx as CloudTx;
use cita_cloud_proto::blockchain::Block as CloudBlock;
use cita_cloud_proto::common::{Address as CloudAddress, Hash as CloudHash, HashRespond};
use cita_cloud_proto::evm::rpc_service_server::RpcService;
use cita_cloud_proto::evm::{
    Balance as CloudBalance, ByteAbi as CloudByteAbi, ByteCode as CloudByteCode,
    Nonce as CloudNonce, Receipt as CloudReceipt,
};
use cita_cloud_proto::executor::executor_service_server::ExecutorService;
use cita_cloud_proto::executor::{
    CallRequest as CloudCallRequest, CallResponse as CloudCallResponse,
};
use crossbeam_channel::{Receiver, Sender};
use status_code::StatusCode;
use tonic::{Code, Request, Response, Status};

pub struct ExecutedFinal {
    pub status: StatusCode,
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

#[tonic::async_trait]
impl ExecutorService for ExecutorServer {
    async fn exec(
        &self,
        request: Request<CloudBlock>,
    ) -> std::result::Result<Response<HashRespond>, Status> {
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
                        return Ok(Response::new(HashRespond {
                            status: Some(StatusCode::NoneBlockBody.into()),
                            hash: None,
                        }));
                    }
                }
            }
        }

        if self.exec_req_sender.send(open_blcok).is_err() {
            warn!("exec: sending on a disconnected channel");
            return Ok(Response::new(HashRespond {
                status: Some(StatusCode::InternalChannelDisconnected.into()),
                hash: None,
            }));
        }

        match self.exec_resp_receiver.recv() {
            Ok(executed_final) => {
                if executed_final.status.is_success().is_ok() {
                    let header = executed_final.result.get_executed_info().get_header();
                    let state_root = header.get_state_root();
                    info!(
                        "height: {}, state_root: 0x{}",
                        header.get_height(),
                        hex::encode(state_root)
                    );
                    Ok(Response::new(HashRespond {
                        status: Some(StatusCode::Success.into()),
                        hash: Some(CloudHash {
                            hash: state_root.to_vec(),
                        }),
                    }))
                } else {
                    Ok(Response::new(HashRespond {
                        status: Some(executed_final.status.into()),
                        hash: None,
                    }))
                }
            }
            Err(recv_error) => {
                warn!("exec: recv error: {}", recv_error.to_string());
                Ok(Response::new(HashRespond {
                    status: Some(StatusCode::InternalChannelDisconnected.into()),
                    hash: None,
                }))
            }
        }
    }

    async fn call(
        &self,
        request: Request<CloudCallRequest>,
    ) -> std::result::Result<Response<CloudCallResponse>, Status> {
        let cloud_call_request = request.into_inner();
        let _ = self.call_req_sender.send(cloud_call_request);

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
        let _ = self
            .command_req_sender
            .send(Command::ReceiptAt(H256::from_slice(
                cloud_hash.hash.as_slice(),
            )));

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
        let _ = self.command_req_sender.send(Command::CodeAt(
            Address::from_slice(cloud_address.address.as_slice()),
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
        let _ = self.command_req_sender.send(Command::BalanceAt(
            Address::from_slice(cloud_address.address.as_slice()),
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
        let _ = self.command_req_sender.send(Command::NonceAt(
            Address::from_slice(cloud_address.address.as_slice()),
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
        let _ = self.command_req_sender.send(Command::AbiAt(
            Address::from_slice(cloud_address.address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::AbiAt(Some(bytes_abi))) => {
                Ok(Response::new(CloudByteAbi { bytes_abi }))
            }
            _ => Err(Status::new(Code::InvalidArgument, "Not get the abi")),
        }
    }
}
