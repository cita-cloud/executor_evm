# executor_evm

`CITA-Cloud`中[executor微服务](https://github.com/cita-cloud/cita_cloud_proto/blob/master/protos/executor.proto)的实现，基于[EVM](https://learnblockchain.cn/2019/04/09/easy-evm/)。

## 编译docker镜像
```
docker build -t citacloud/executor_evm .
```

## 使用方法

```
$ executor -h
CITA-CLOUD EVM EXECUTOR 6.4.0
Yieazy <yuitta@163.com>:Rivtower Technologies <contact@rivtower.com>
Supply evm interpreter

USAGE:
    executor [SUBCOMMAND]

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    help    Print this message or the help of the given subcommand(s)
    run     run this service
```

### executor-run

运行`executor`服务。

```
$ executor run -h
executor-run
run this service

USAGE:
    executor run [OPTIONS]

OPTIONS:
    -c, --config <config>    config file path
    -h, --help               Print help information
    -l, --log <log>          log config file path
```

参数：
1. `config` 微服务配置文件。

    参见示例`example/config.toml`。

    其中：
    * `executor_port` 为本微服务的`gRPC`服务监听的端口号。
    * `eth_compatibility` 设置是否兼容以太坊。以太坊区块中的时间戳单位是秒，而联盟链一般区块中的时间戳是毫秒，为了兼容一些使用了时间戳的合约而设置了该配置项。设置为`true`的时候，会在之前时将区块中的时间戳除以`1000`，将单位从毫秒转换成秒。
    * `db_path` 设置状态数据库的路径。
2. 日志配置文件。

    参见示例`executor-log4rs.yaml`。

    其中：

    * `level` 为日志等级。可选项有：`Error`，`Warn`，`Info`，`Debug`，`Trace`，默认为`Info`。
    * `appenders` 为输出选项，类型为一个数组。可选项有：标准输出(`stdout`)和滚动的日志文件（`journey-service`），默认为同时输出到两个地方。


```
$ executor run -c example/config.toml -l executor-log4rs.yaml
2022-03-14T06:46:19.059621203+00:00 INFO executor - grpc port of this service: 50002
2022-03-14T06:46:19.208136159+00:00 WARN executor::core_executor::libexecutor::executor - Not found exist block within database.
2022-03-14T06:46:19.358554819+00:00 INFO executor::core_chain - current_height: 0
2022-03-14T06:46:19.358686497+00:00 INFO executor::core_executor::libexecutor::executor - executor init, current_height: 0, current_hash: 0x75a88272c753ad456cdebee34204665277e847288af916f3db52ef71f4c651d1
```

## 设计
