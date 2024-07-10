# executor_evm

`CITA-Cloud`中[executor微服务](https://github.com/cita-cloud/cita_cloud_proto/blob/master/protos/executor.proto)的实现，基于[EVM](https://learnblockchain.cn/2019/04/09/easy-evm/)。

## 编译docker镜像
```
docker build -t citacloud/executor_evm .
```

## 使用方法

```
$ executor -h
executor 6.7.0
Yieazy <yuitta@163.com>:Rivtower Technologies <contact@rivtower.com>
Supply evm interpreter

Usage: executor [COMMAND]

Commands:
  run   run this service
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### executor-run

运行`executor`服务。

```
$ executor run -h
run this service

Usage: executor run [OPTIONS]

Options:
  -c, --config <config>  config file path
  -h, --help             Print help
```

参数：
1. `config` 微服务配置文件。

    参见示例`example/config.toml`。

    其中`[executor_evm]`段为微服务的配置：
    * `executor_port` 为本微服务的`gRPC`服务监听的端口号。
    * `eth_compatibility` 设置是否兼容以太坊。以太坊区块中的时间戳单位是秒，而联盟链一般区块中的时间戳是毫秒，为了兼容一些使用了时间戳的合约而设置了该配置项。设置为`true`的时候，会在之前时将区块中的时间戳除以`1000`，将单位从毫秒转换成秒。
    * `db_path` 设置状态数据库的路径。
    * `domain` 节点的域名

    其中`[executor_evm.log_config]`段为微服务日志的配置：
    * `max_level` 日志等级
    * `filter` 日志过滤配置
    * `service_name` 服务名称，用作日志文件名与日志采集的服务名称
    * `rolling_file_path` 日志文件路径
    * `agent_endpoint` jaeger 采集端地址


```
$ executor run -c example/config.toml
2023-02-08T08:29:09.898895Z  INFO executor: grpc port of executor_evm: 50002
2023-02-08T08:29:10.130872Z  WARN executor::core_executor::libexecutor::executor: Not found exist block within database.
2023-02-08T08:29:10.290947Z  INFO executor::core_chain: current_height: 0
2023-02-08T08:29:10.291043Z  INFO executor::core_executor::libexecutor::executor: executor init, current_height: 0, current_hash: 0x75a88272c753ad456cdebee34204665277e847288af916f3db52ef71f4c651d1
2023-02-08T08:29:10.317068Z  INFO executor: start executor_evm grpc server
2023-02-08T08:29:10.317118Z  INFO executor: metrics on
2023-02-08T08:29:10.318089Z  INFO cloud_util::metrics: exporting metrics to http://[::]:60002/metrics
```

## 设计
