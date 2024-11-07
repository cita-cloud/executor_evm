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
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate libproto;

use crate::config::ExecutorConfig;
use crate::health_check::HealthCheckServer;
use cita_cloud_proto::evm::rpc_service_server::RpcServiceServer;
use cita_cloud_proto::executor::executor_service_server::ExecutorServiceServer;
use cita_cloud_proto::health_check::health_server::HealthServer;
use cita_cloud_proto::EXECUTOR_DESCRIPTOR_SET;
use clap::{crate_authors, crate_version, Arg, Command};
use cloud_util::metrics::{run_metrics_exporter, MiddlewareLayer};
use core_executor::libexecutor::executor::Executor;
use executor_server::ExecutorServer;
#[macro_use]
extern crate tracing as logger;
use std::error::Error;
use std::path::Path;
use std::time::Duration;
use tonic::transport::Server;
use tonic_web::GrpcWebLayer;
// extern crate enum_primitive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let matches = Command::new("CITA-CLOUD EVM EXECUTOR")
        .author(crate_authors!())
        .version(crate_version!())
        .about(clap_about() + "\nSupply evm interpreter")
        .subcommand(
            Command::new("run").about("run this service").arg(
                Arg::new("config")
                    .short('c')
                    .long("config")
                    .help("config file path"),
            ),
        )
        .get_matches();

    if let Some(opts) = matches.subcommand_matches("run") {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = runtime.block_on(run(opts)) {
            warn!("unreachable: {:?}", e);
        }
    }

    Ok(())
}

async fn run(opts: &clap::ArgMatches) -> Result<(), Box<dyn Error>> {
    let rx_signal = cloud_util::graceful_shutdown::graceful_shutdown();

    let config_path = if let Some(c) = opts.get_one::<String>("config") {
        c.clone()
    } else {
        "config.toml".to_string()
    };
    let config = ExecutorConfig::new(config_path.as_str());

    let http2_keepalive_interval = config.http2_keepalive_interval;
    let http2_keepalive_timeout = config.http2_keepalive_timeout;
    let tcp_keepalive = config.tcp_keepalive;

    let config_for_tracer = config.clone();
    tokio::spawn(async move {
        // init tracer
        cloud_util::tracer::init_tracer(
            config_for_tracer.domain.clone(),
            &config_for_tracer.log_config,
        )
        .map_err(|e| println!("tracer init err: {e}"))
        .unwrap()
    });
    let grpc_port = config.executor_port.to_string();
    info!("grpc port of executor_evm: {grpc_port}");
    let executor_addr = format!("[::]:{grpc_port}").parse()?;
    assert!(
        !Path::new(&config.db_path).is_absolute(),
        "db_path must be relative path"
    );

    let inner = ExecutorServer {
        executor: Executor::init(&config),
    };
    let executor_svc =
        ExecutorServiceServer::new(inner.clone()).max_decoding_message_size(usize::MAX);
    let rpc_svc = RpcServiceServer::new(inner).max_decoding_message_size(usize::MAX);

    let layer = if config.enable_metrics {
        tokio::spawn(async move {
            run_metrics_exporter(config.metrics_port).await.unwrap();
        });

        Some(
            tower::ServiceBuilder::new()
                .layer(MiddlewareLayer::new(config.metrics_buckets))
                .into_inner(),
        )
    } else {
        None
    };

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(EXECUTOR_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();

    info!("start executor_evm grpc server");
    if layer.is_some() {
        info!("metrics on");
        Server::builder()
            .accept_http1(true)
            .http2_keepalive_interval(Some(Duration::from_secs(http2_keepalive_interval)))
            .http2_keepalive_timeout(Some(Duration::from_secs(http2_keepalive_timeout)))
            .tcp_keepalive(Some(Duration::from_secs(tcp_keepalive)))
            .layer(layer.unwrap())
            .layer(GrpcWebLayer::new())
            .add_service(reflection)
            .add_service(executor_svc)
            .add_service(rpc_svc)
            .add_service(HealthServer::new(HealthCheckServer {}))
            .serve_with_shutdown(
                executor_addr,
                cloud_util::graceful_shutdown::grpc_serve_listen_term(rx_signal),
            )
            .await?;
    } else {
        info!("metrics off");
        Server::builder()
            .accept_http1(true)
            .http2_keepalive_interval(Some(Duration::from_secs(http2_keepalive_interval)))
            .http2_keepalive_timeout(Some(Duration::from_secs(http2_keepalive_timeout)))
            .tcp_keepalive(Some(Duration::from_secs(tcp_keepalive)))
            .layer(GrpcWebLayer::new())
            .add_service(reflection)
            .add_service(executor_svc)
            .add_service(rpc_svc)
            .add_service(HealthServer::new(HealthCheckServer {}))
            .serve_with_shutdown(
                executor_addr,
                cloud_util::graceful_shutdown::grpc_serve_listen_term(rx_signal),
            )
            .await?;
    }
    Ok(())
}

pub fn clap_about() -> String {
    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    name + " " + version + "\n" + authors
}

mod config;
pub mod core_chain;
pub mod core_executor;
mod executor_server;
mod health_check;
mod trie_db;
pub mod types;
