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

use cita_cloud_proto::blockchain::CompactBlock;
use cita_cloud_proto::common::Hash;
use cita_cloud_proto::controller::raw_transaction::Tx;
use cita_cloud_proto::controller::RawTransaction;
use cita_cloud_proto::executor::executor_service_server::{ExecutorService, ExecutorServiceServer};
use cita_cloud_proto::executor::{CallRequest as CloudCallRequest, CallResponse};
use cita_directories::DataPath;
use clap::{App, Arg};
use common_types::block::OpenBlock;
use core_executor::libexecutor::executor::Executor;
use core_executor::libexecutor::fsm::FSM;
use git_version::git_version;
use log::info;
use prost::Message;
use std::path::Path;
use tokio::fs;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Code};
use core_executor::libexecutor::command::Commander;
use core_executor::libexecutor::call_request::CallRequest;
use common_types::block_number::{BlockTag, Tag};

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/executor_chaincode";

pub struct RunOpts {
    /// Sets genesis block path
    genesis_path: String,

    /// Sets eth compatibility
    eth_compatibility: bool,
}

pub struct ExecutorServer {
    opts: RunOpts,
}

#[tonic::async_trait]
impl ExecutorService for ExecutorServer {
    async fn exec(
        &self,
        request: Request<CompactBlock>,
    ) -> std::result::Result<Response<Hash>, Status> {
        let (fsm_req_sender, fsm_req_receiver) = crossbeam_channel::unbounded();
        let (fsm_resp_sender, fsm_resp_receiver) = crossbeam_channel::unbounded();
        let (command_req_sender, command_req_receiver) = crossbeam_channel::bounded(0);
        let (command_resp_sender, command_resp_receiver) = crossbeam_channel::bounded(0);

        let data_path = DataPath::root_node_path();
        let mut executor = Executor::init(
            &self.opts.genesis_path,
            data_path,
            fsm_req_receiver.clone(),
            fsm_resp_sender.clone(),
            command_req_receiver.clone(),
            command_resp_sender.clone(),
            self.opts.eth_compatibility,
        );

        let block = request.into_inner();
        let mut open_blcok = OpenBlock::from(block.clone());

        if let Some(body) = block.body {
            for tx_hash in body.tx_hashes {
                let filename = hex::encode(&tx_hash);
                let root_path = Path::new(".");
                let tx_path = root_path.join("txs").join(filename);

                let tx_bytes = fs::read(tx_path).await.unwrap();

                let raw_tx = RawTransaction::decode(&tx_bytes[..]).unwrap();
                match raw_tx.tx {
                    Some(Tx::NormalTx(utx)) => open_blcok.insert_cloud_tx(utx),
                    Some(unknown) => info!("block contains unknown tx: `{:?}`", unknown),
                    None => info!("block contains empty tx"),
                }
            }
        }

        let fsm_resp = executor.into_fsm(open_blcok);
        Ok(Response::new(Hash {
            hash: fsm_resp.state.root.to_vec(),
        }))
    }

    async fn call(
        &self,
        request: Request<CloudCallRequest>,
    ) -> std::result::Result<Response<CallResponse>, Status> {
        let (fsm_req_sender, fsm_req_receiver) = crossbeam_channel::unbounded();
        let (fsm_resp_sender, fsm_resp_receiver) = crossbeam_channel::unbounded();
        let (command_req_sender, command_req_receiver) = crossbeam_channel::bounded(0);
        let (command_resp_sender, command_resp_receiver) = crossbeam_channel::bounded(0);

        let data_path = DataPath::root_node_path();
        let executor = Executor::init(
            &self.opts.genesis_path,
            data_path,
            fsm_req_receiver.clone(),
            fsm_resp_sender.clone(),
            command_req_receiver.clone(),
            command_resp_sender.clone(),
            self.opts.eth_compatibility,
        );

        let cloud_call_request = request.into_inner();
        match executor.eth_call(CallRequest::from(cloud_call_request), BlockTag::Tag(Tag::Pending)) {
            Ok(value) => { Ok(Response::new(CallResponse { value })) }
            Err(str) => { Err(Status::new(Code::Internal, str)) }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let matches = App::new("CITA-CLOUD EVM EXECUTOR")
        .author("Rivtower Technologies.")
        .version("0.2.0")
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
                    Arg::new("genesis_path")
                        .short('g')
                        .long("genesis")
                        .takes_value(true)
                        .about("Set genesis block path, default genesis.json"),
                )
                .arg(
                    Arg::new("eth-compatibility")
                        .short('c')
                        .long("compatibility")
                        .about("Sets eth compatibility, default false"),
                ),
        )
        .get_matches();

    log4rs::init_file("executor-log4rs.yaml", Default::default()).unwrap();
    if let Some(_args) = matches.subcommand_matches("git") {
        info!("git version: {}", GIT_VERSION);
        info!("homepage: {}", GIT_HOMEPAGE);
    } else if let Some(opts) = matches.subcommand_matches("run") {
        let grpc_port = opts.value_of_t("port").unwrap_or(50002);
        let genesis_path = opts
            .value_of("genesis")
            .unwrap_or("genesis.json")
            .to_string();
        let eth_compatibility = opts.is_present("compatibility");

        info!("grpc port of this service: {}", grpc_port);
        let executor_addr = format!("127.0.0.1:{}", grpc_port).parse()?;

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let executor_svc = ExecutorServiceServer::new(ExecutorServer {
                    opts: RunOpts {
                        genesis_path,
                        eth_compatibility,
                    },
                });
                Server::builder()
                    .add_service(executor_svc)
                    .serve(executor_addr)
                    .await
                    .unwrap();
            })
    }

    Ok(())
}
