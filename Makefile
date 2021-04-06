CARGO=RUSTFLAGS='-A deprecated -Clink-arg=-Wl,--allow-multiple-definition' cargo

.PHONY: debug release test test-release bench fmt clean clippy

debug:
	$(CARGO) build --all

release:
	$(CARGO) build --all  --release

aarch64_debug:
	$(CARGO) build --all --target aarch64-unknown-linux-gnu

aarch64_release:
	$(CARGO) build --all  --release --target aarch64-unknown-linux-gnu

test:
	RUST_BACKTRACE=full $(CARGO) test --all 2>&1

test-release:
	RUST_BACKTRACE=full $(CARGO) test --release --all

bench:
	-rm target/bench.log
	cargo bench --all --no-run |tee target/bench.log
	cargo bench --all --jobs 1 |tee -a target/bench.log

fmt:
	cargo fmt --all -- --check

clean:
	rm -rf target/debug/
	rm -rf target/release/

clippy:
	$(CARGO) clippy --all
