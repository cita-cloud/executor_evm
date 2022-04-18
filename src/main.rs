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
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate crossbeam_channel;
extern crate libproto;

use crate::config::ExecutorConfig;
use crate::executor_server::ExecutedFinal;
use crate::health_check::HealthCheckServer;
use crate::panic_hook::set_panic_handler;
use cita_cloud_proto::evm::rpc_service_server::RpcServiceServer;
use cita_cloud_proto::executor::executor_service_server::ExecutorServiceServer;
use cita_cloud_proto::health_check::health_server::HealthServer;
use clap::{crate_authors, crate_version, Arg, Command};
use core_executor::libexecutor::call_request::CallRequest;
use core_executor::libexecutor::command::Commander;
use core_executor::libexecutor::executor::Executor;
use core_executor::libexecutor::fsm::Fsm;
use executor_server::ExecutorServer;
use git_version::git_version;
use hashable::Hashable;
use libproto::{ExecutedHeader, ExecutedInfo, ExecutedResult};
use prost::Message;
use status_code::StatusCode;
use std::path::Path;
use std::thread;
use tonic::transport::Server;
use types::block::OpenBlock;
use types::block_number::{BlockTag, Tag};
// extern crate enum_primitive;

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/executor_evm";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ::std::env::set_var("RUST_BACKTRACE", "full");
    set_panic_handler();

    let matches = Command::new("CITA-CLOUD EVM EXECUTOR")
        .author(crate_authors!())
        .version(crate_version!())
        .about("Supply evm interpreter")
        .subcommand(Command::new("git").about("print information from git"))
        .subcommand(
            Command::new("run")
                .about("run this service")
                .arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .takes_value(true)
                        .help("config file path"),
                )
                .arg(
                    Arg::new("log")
                        .short('l')
                        .long("log")
                        .takes_value(true)
                        .help("log config file path"),
                ),
        )
        .get_matches();

    if let Some(_args) = matches.subcommand_matches("git") {
        println!("git version: {}", GIT_VERSION);
        println!("homepage: {}", GIT_HOMEPAGE);
    } else if let Some(opts) = matches.subcommand_matches("run") {
        let config = ExecutorConfig::new(opts.value_of("config").unwrap_or("config.toml"));

        // init log4rs
        log4rs::init_file(
            opts.value_of("log").unwrap_or("executor-log4rs.yaml"),
            Default::default(),
        )
        .map_err(|e| println!("log init err: {}", e))
        .unwrap();

        let grpc_port = config.executor_port.to_string();
        info!("grpc port of this service: {}", grpc_port);

        let executor_addr = format!("0.0.0.0:{}", grpc_port).parse()?;

        // db_path must be relative path
        assert!(
            !Path::new(&config.db_path).is_absolute(),
            "db_path must be relative path"
        );
        let mut executor = Executor::init(&config);

        let (exec_req_sender, exec_req_receiver) = crossbeam_channel::unbounded::<OpenBlock>();
        let (exec_resp_sender, exec_resp_receiver) = crossbeam_channel::unbounded();
        let (call_req_sender, call_req_receiver) = crossbeam_channel::bounded(0);
        let (call_resp_sender, call_resp_receiver) = crossbeam_channel::bounded(0);
        let (command_req_sender, command_req_receiver) = crossbeam_channel::bounded(0);
        let (command_resp_sender, command_resp_receiver) = crossbeam_channel::bounded(0);

        let handle = thread::spawn(move || loop {
            select! {
                recv(exec_req_receiver) -> open_block => {
                    match open_block {
                        Ok(open_block) => {
                            // open_block is next block
                            if open_block.number() == executor.get_current_height() + 1 {
                                let cloud_header = executor.get_current_header().to_cloud_protobuf().header.unwrap();
                                let mut block_header_bytes = Vec::with_capacity(cloud_header.encoded_len());
                                cloud_header.encode(&mut block_header_bytes).map_err(|_| {
                                    warn!("encode block cloud_header failed");
                                    StatusCode::EncodeError
                                }).unwrap();
                                if &block_header_bytes.crypt_hash() == open_block.parent_hash() {
                                    let mut close_block = executor.before_fsm(open_block.clone());
                                    let executed_result = executor.grow(&close_block);
                                    close_block.clear_cache();
                                    executor.core_chain.set_db_result(&executed_result, &open_block);
                                    let _ = exec_resp_sender.send(ExecutedFinal{
                                        status: StatusCode::Success,
                                        result: executed_result,
                                    });
                                    continue;
                                } else {
                                    panic!("block's parent_hash({:?})  is not consistent with current_hash({:?})",
                                        &block_header_bytes.crypt_hash(),
                                        open_block.parent_hash()
                                    );
                                }
                            }
                            // handle re-enter-block & genesis block
                            if let Some(reserve_header) = executor.block_header_by_height(open_block.number()) {
                                // timestamp != 0, re-enter-block, else, genesis block
                                if reserve_header.timestamp() != 0 {
                                    let mut header = ExecutedHeader::new();
                                    header.set_state_root(reserve_header.state_root().0.to_vec());

                                    let mut exc_info = ExecutedInfo::new();
                                    exc_info.set_header(header);

                                    let mut exc_res = ExecutedResult::new();
                                    exc_res.set_executed_info(exc_info);
                                    // handle re-enter-block, divide valid or invalid re-enter-block
                                    if reserve_header.open_header() == &open_block.header {
                                        info!(
                                            "block({}) re-enter",
                                            open_block.number()
                                        );
                                        exec_resp_sender.send(ExecutedFinal{
                                            status: StatusCode::ReenterBlock,
                                            result: exc_res,
                                        }).unwrap();
                                    } else {
                                        warn!(
                                            "invalid block({}) re-enter",
                                            open_block.number()
                                        );
                                        exec_resp_sender.send(ExecutedFinal{
                                            status: StatusCode::ReenterInvalidBlock,
                                            result: exc_res,
                                        }).unwrap();
                                    }
                                } else {
                                    // execute genesis block
                                    let mut close_block = executor.before_fsm(open_block.clone());
                                    let executed_result = executor.grow(&close_block);
                                    close_block.clear_cache();
                                    executor.core_chain.set_db_result(&executed_result, &open_block);
                                    let _ = exec_resp_sender.send(ExecutedFinal{
                                        status: StatusCode::Success,
                                        result: executed_result,
                                    });
                                }
                            } else { panic!("current height: {}, open_block number: {}",
                                executor.get_current_height(), open_block.number()); }
                        },
                        Err(e) => panic!("receive exec_req_receiver error: {}", e),
                    }
                },
                recv(call_req_receiver) -> cloud_call_request => {
                    match cloud_call_request {
                        Ok(cloud_call_request) => {
                            debug!("get call request: {:x?}", cloud_call_request);
                            let call_result = executor.eth_call(CallRequest::from(cloud_call_request), BlockTag::Tag(Tag::Pending));
                            let _ = call_resp_sender.send(call_result);
                        },
                        Err(e) => panic!("receive call_req_receiver error: {}", e),
                    }
                },
                recv(command_req_receiver) -> command_request => {
                    match command_request {
                        Ok(command_request) => {
                            trace!("executor receive {}", command_request);
                            let _ = command_resp_sender.send(executor.operate(command_request));
                        },
                        Err(e) => panic!("receive command_req_receiver error: {}", e),
                    }
                }
            }
        });

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let inner = ExecutorServer {
                    exec_req_sender,
                    exec_resp_receiver,
                    call_req_sender,
                    call_resp_receiver,
                    command_req_sender,
                    command_resp_receiver,
                };
                let executor_svc = ExecutorServiceServer::new(inner.clone());
                let rpc_svc = RpcServiceServer::new(inner);
                Server::builder()
                    .add_service(executor_svc)
                    .add_service(rpc_svc)
                    .add_service(HealthServer::new(HealthCheckServer {}))
                    .serve(executor_addr)
                    .await
                    .unwrap();
            });

        handle.join().expect("unreachable!");
    }

    Ok(())
}

mod config;
pub mod core_chain;
pub mod core_executor;
mod executor_server;
mod health_check;
mod panic_hook;
mod trie_db;
pub mod types;
