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

#[macro_use]
extern crate util;
#[macro_use]
extern crate cita_logger as logger;
#[macro_use]
extern crate crossbeam_channel;
use cita_cloud_proto::blockchain::CompactBlock as CloudCompactBlock;
use cita_cloud_proto::common::Hash as CloudHash;
use cita_cloud_proto::controller::raw_transaction::Tx as CloudTx;
use cita_cloud_proto::controller::RawTransaction as CloudRawTransaction;
use cita_cloud_proto::executor::executor_service_server::{ExecutorService, ExecutorServiceServer};
use cita_cloud_proto::executor::{
    CallRequest as CloudCallRequest, CallResponse as CloudCallResponse,
};
use clap::{App, Arg};
use common_types::block::OpenBlock;
use common_types::block_number::{BlockTag, Tag};
use common_types::Bytes;
use core_executor::libexecutor::block::ClosedBlock;
use core_executor::libexecutor::call_request::CallRequest;
use core_executor::libexecutor::command::Commander;
use core_executor::libexecutor::executor::Executor;
use core_executor::libexecutor::fsm::FSM;
use crossbeam_channel::{Receiver, Sender};
use git_version::git_version;
use prost::Message;
use std::path::Path;
use std::thread;
use tokio::fs;
use tonic::transport::Server;
use tonic::{Code, Request, Response, Status};
use util::set_panic_handler;

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/executor_chaincode";

pub struct ExecutorServer {
    exec_req_sender: Sender<OpenBlock>,
    exec_resp_receiver: Receiver<ClosedBlock>,
    call_req_sender: Sender<CloudCallRequest>,
    call_resp_receiver: Receiver<Result<Bytes, String>>,
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
            Ok(close_block) => {
                let stat_root = close_block.state.root.to_vec();
                info!("{}", hex::encode(stat_root.clone()));
                Ok(Response::new(CloudHash { hash: stat_root }))
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let matches = App::new("CITA-CLOUD EVM EXECUTOR")
        .author("Rivtower Technologies.")
        .version("0.1.0")
        .about("Supply evm interpreter")
        .subcommand(App::new("git").about("print information from git"))
        .subcommand(
            App::new("run")
                .about("run this service")
                .arg(
                    Arg::new("grpc-port")
                        .short('p')
                        .long("port")
                        .takes_value(true)
                        .about("Set executor port, default 50002"),
                )
                .arg(
                    Arg::new("eth-compatibility")
                        .short('c')
                        .long("compatibility")
                        .about("Sets eth compatibility, default false"),
                ),
        )
        .arg(
            Arg::new("stdout")
                .short('s')
                .long("stdout")
                .about("Log to console")
        )
        .get_matches();

    let stdout = matches.is_present("stdout");
    micro_service_init!("citacloud-executor", "CITA-CLOUD:executor", stdout);

    if let Some(_args) = matches.subcommand_matches("git") {
        info!("git version: {}", GIT_VERSION);
        info!("homepage: {}", GIT_HOMEPAGE);
    } else if let Some(opts) = matches.subcommand_matches("run") {
        let grpc_port = opts.value_of("port").unwrap_or("50002");
        let eth_compatibility = opts.is_present("compatibility");

        info!("grpc port of this service: {}", grpc_port);
        let executor_addr = format!("127.0.0.1:{}", grpc_port).parse()?;

        let (_fsm_req_sender, fsm_req_receiver) = crossbeam_channel::unbounded();
        let (fsm_resp_sender, _fsm_resp_receiver) = crossbeam_channel::unbounded();
        let (_command_req_sender, command_req_receiver) = crossbeam_channel::bounded(0);
        let (command_resp_sender, _command_resp_receiver) = crossbeam_channel::bounded(0);

        let data_path = String::from("./data");
        let mut executor = Executor::init(
            "",
            data_path,
            fsm_req_receiver,
            fsm_resp_sender,
            command_req_receiver,
            command_resp_sender,
            eth_compatibility,
        );

        let (exec_req_sender, exec_req_receiver) = crossbeam_channel::unbounded();
        let (exec_resp_sender, exec_resp_receiver) = crossbeam_channel::unbounded();
        let (call_req_sender, call_req_receiver) = crossbeam_channel::bounded(0);
        let (call_resp_sender, call_resp_receiver) = crossbeam_channel::bounded(0);

        let handle = thread::spawn(move || loop {
            select! {
                recv(exec_req_receiver) -> open_block => {
                    match open_block {
                        Ok(open_block) => {
                            let close_block = executor.into_fsm(open_block);
                            executor.write_batch(&close_block);
                            *executor.current_header.write() = close_block.header().clone();
                            let _ = exec_resp_sender.send(close_block);
                        },
                        Err(e) => warn!("receive exec_req_receiver error: {}", e),
                    }
                },
                recv(call_req_receiver) -> cloud_call_request => {
                    match cloud_call_request {
                        Ok(cloud_call_request) => {
                            let call_result = executor.eth_call(CallRequest::from(cloud_call_request), BlockTag::Tag(Tag::Pending));
                            let _ = call_resp_sender.send(call_result);
                        },
                        Err(e) => warn!("receive call_req_receiver error: {}", e),
                    }
                },
            }
        });

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let executor_svc = ExecutorServiceServer::new(ExecutorServer {
                    exec_req_sender,
                    exec_resp_receiver,
                    call_req_sender,
                    call_resp_receiver,
                });
                Server::builder()
                    .add_service(executor_svc)
                    .serve(executor_addr)
                    .await
                    .unwrap();
            });


        handle.join().expect("unreachable!");
    }

    Ok(())
}
