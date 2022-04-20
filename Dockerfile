FROM rust:slim-bullseye AS buildstage
WORKDIR /build
COPY . /build/
RUN /bin/sh -c set -eux;\
    rustup component add rustfmt;\
    apt-get update;\
    apt-get install -y --no-install-recommends make wget librocksdb-dev libsnappy-dev liblz4-dev libzstd-dev libssl-dev pkg-config clang;\
    rm -rf /var/lib/apt/lists/*;\
    GRPC_HEALTH_PROBE_VERSION=v0.4.10;\
    wget -qO /bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64;\
    chmod +x /bin/grpc_health_probe;
RUN make release
FROM debian:bullseye-slim
COPY --from=buildstage /build/target/release/executor /usr/bin/
COPY --from=buildstage /bin/grpc_health_probe /usr/bin/
RUN /bin/sh -c set -eux;\
    apt-get update;\
    apt-get install -y --no-install-recommends libssl1.1;\
    rm -rf /var/lib/apt/lists/*;
CMD ["executor"]
