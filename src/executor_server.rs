use crate::core_executor::libexecutor::command::{Command, CommandResp};
use crate::core_executor::libexecutor::ExecutedResult;
use crate::types::block::OpenBlock;
use crate::types::block_number::{BlockTag, Tag};
use crate::types::Bytes;
use crate::types::{Address, H256};
use cita_cloud_proto::blockchain::CompactBlock as CloudCompactBlock;
use cita_cloud_proto::common::{Address as CloudAddress, Hash as CloudHash};
use cita_cloud_proto::controller::raw_transaction::Tx as CloudTx;
use cita_cloud_proto::controller::RawTransaction as CloudRawTransaction;
use cita_cloud_proto::evm::rpc_service_server::RpcService;
use cita_cloud_proto::evm::{
    Balance as CloudBalance, ByteCode as CloudByteCode, Receipt as CloudReceipt,
};
use cita_cloud_proto::executor::executor_service_server::ExecutorService;
use cita_cloud_proto::executor::{
    CallRequest as CloudCallRequest, CallResponse as CloudCallResponse,
};
use crossbeam_channel::{Receiver, Sender};
use prost::Message;
use std::path::Path;
use tokio::fs;
use tonic::{Code, Request, Response, Status};

#[derive(Clone)]
pub struct ExecutorServer {
    pub exec_req_sender: Sender<OpenBlock>,
    pub exec_resp_receiver: Receiver<ExecutedResult>,
    pub call_req_sender: Sender<CloudCallRequest>,
    pub call_resp_receiver: Receiver<Result<Bytes, String>>,
    pub command_req_sender: Sender<Command>,
    pub command_resp_receiver: Receiver<CommandResp>,
}

#[tonic::async_trait]
impl ExecutorService for ExecutorServer {
    async fn exec(
        &self,
        request: Request<CloudCompactBlock>,
    ) -> std::result::Result<Response<CloudHash>, Status> {
        let block = request.into_inner();
        let mut open_blcok = OpenBlock::from(block.clone());
        info!("exec method invoke, height: {}", open_blcok.header.number());

        if let Some(body) = block.body {
            for tx_hash in body.tx_hashes {
                let filename = hex::encode(&tx_hash);
                let root_path = Path::new(".");
                let tx_path = root_path.join("txs").join(filename);

                let tx_bytes = fs::read(tx_path).await.unwrap();

                let raw_tx = CloudRawTransaction::decode(&tx_bytes[..]).unwrap();
                match raw_tx.tx {
                    Some(CloudTx::NormalTx(utx)) => open_blcok.insert_cloud_tx(utx),
                    Some(unknown) => info!("block contains unknown tx: `{:?}`", unknown),
                    None => info!("block contains empty tx"),
                }
            }
        }

        let _ = self.exec_req_sender.send(open_blcok);
        match self.exec_resp_receiver.recv() {
            Ok(executed_result) => {
                let header = executed_result.get_executed_info().get_header();
                let state_root = header.get_state_root();
                info!(
                    "height: {}, state_root: {}",
                    header.get_height(),
                    hex::encode(state_root)
                );
                Ok(Response::new(CloudHash {
                    hash: state_root.to_vec(),
                }))
            }
            Err(recv_error) => Err(Status::new(Code::Internal, recv_error.to_string())),
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
                Err(str) => Err(Status::new(Code::Internal, str)),
            },
            Err(recv_error) => Err(Status::new(Code::Internal, recv_error.to_string())),
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
            .send(Command::ReceiptAt(H256::from(cloud_hash.hash.as_slice())));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::ReceiptAt(Some(rich_receipt))) => {
                Ok(Response::new(rich_receipt.into()))
            }
            _ => Err(Status::new(Code::NotFound, "Not get the receipt")),
        }
    }

    async fn get_code(
        &self,
        request: Request<CloudAddress>,
    ) -> Result<Response<CloudByteCode>, Status> {
        let cloud_addres = request.into_inner();
        let _ = self.command_req_sender.send(Command::CodeAt(
            Address::from(cloud_addres.address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::CodeAt(Some(byte_code))) => {
                Ok(Response::new(CloudByteCode { byte_code }))
            }
            _ => Err(Status::new(Code::NotFound, "Not get the bytecode")),
        }
    }

    async fn get_balance(
        &self,
        request: Request<CloudAddress>,
    ) -> Result<Response<CloudBalance>, Status> {
        let cloud_addres = request.into_inner();
        let _ = self.command_req_sender.send(Command::BalanceAt(
            Address::from(cloud_addres.address.as_slice()),
            BlockTag::Tag(Tag::Pending),
        ));

        match self.command_resp_receiver.recv() {
            Ok(CommandResp::BalanceAt(Some(value))) => Ok(Response::new(CloudBalance { value })),
            _ => Err(Status::new(Code::NotFound, "Not get the balance")),
        }
    }
}
