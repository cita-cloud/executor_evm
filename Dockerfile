FROM rust:slim-bullseye AS buildstage
WORKDIR /build
COPY . /build/
ENV PROTOC_NO_VENDOR 1
RUN rustup component add rustfmt && \
    apt-get update && \
    apt-get install -y --no-install-recommends make wget librocksdb-dev libsnappy-dev liblz4-dev libzstd-dev libssl-dev pkg-config clang protobuf-compiler && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN make release

FROM debian:bullseye-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl1.1 && \
    rm -rf  /var/log/*log /var/lib/apt/lists/* /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old
RUN useradd -m chain
USER chain
COPY --from=buildstage /build/target/release/executor /usr/bin/
COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.19 /ko-app/grpc-health-probe /usr/bin/
CMD ["executor"]
