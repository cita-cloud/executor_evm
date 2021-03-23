FROM rust:slim-buster AS buildstage
WORKDIR /build
COPY . /build/
RUN cp /build/mirror/config /usr/local/cargo/config;\
         cp /build/mirror/sources.list /etc/apt/sources.list;
RUN /bin/sh -c set -eux;\
    RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static rustup component add rustfmt;\
    apt-get update;\
    apt-get install -y --no-install-recommends git protobuf-compiler libssl-dev pkg-config clang;\
    rm -rf /var/lib/apt/lists/*;
RUN cargo build --release
FROM debian:buster-slim
COPY --from=buildstage /build/target/release/executor /usr/bin/
COPY ./mirror/sources.list /etc/apt/sources.list
RUN /bin/sh -c set -eux;\
    apt-get update;\
    apt-get install -y --no-install-recommends libssl1.1;\
    rm -rf /var/lib/apt/lists/*;
CMD ["executor"]