FROM rust:slim-buster AS buildstage
WORKDIR /build
COPY . /build/
RUN /bin/sh -c set -eux;\
    rustup component add rustfmt;\
    apt-get update;\
    apt-get install -y --no-install-recommends make git protobuf-compiler libssl-dev pkg-config clang;\
    rm -rf /var/lib/apt/lists/*;
RUN make release
FROM debian:buster-slim
COPY --from=buildstage /build/target/release/executor /usr/bin/
RUN /bin/sh -c set -eux;\
    apt-get update;\
    apt-get install -y --no-install-recommends libssl1.1;\
    rm -rf /var/lib/apt/lists/*;
CMD ["executor"]
