# plugbox — one command gates everything: `make check`.
#
# The Rust target directory can be shared between checkouts via
# CARGO_TARGET_DIR; plugin artifacts are copied into plugins/dist/.

CARGO        ?= cargo
WASM_OUT     := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),plugins/target)/wasm32-wasip2/release
PLUGINS      := hello counter fetcher hostile sneaky
COVERAGE_MIN ?= 80
BENCH_ITERATIONS ?= 2000
BENCH_THREADS ?= 4

.PHONY: check fmt fmt-check lint test plugins coverage demo bench integration clean

check: fmt-check lint plugins coverage

plugins:
	cd plugins && $(CARGO) build --release --target wasm32-wasip2 --locked
	mkdir -p plugins/dist
	for p in $(PLUGINS); do cp $(WASM_OUT)/plugbox_$$p.wasm plugins/dist/$$p.wasm; done

fmt:
	$(CARGO) fmt
	cd plugins && $(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check
	cd plugins && $(CARGO) fmt --check

lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings
	cd plugins && $(CARGO) clippy --release --target wasm32-wasip2 --locked -- -D warnings

test: plugins
	$(CARGO) test --locked

# Tests run once, under coverage instrumentation, with a line-coverage gate on
# the library (the CLI entry point is excluded; it is exercised by `make demo`).
coverage: plugins
	$(CARGO) llvm-cov --locked --lib --tests --ignore-filename-regex 'src/main\.rs' \
		--fail-under-lines $(COVERAGE_MIN) --summary-only

demo: plugins
	$(CARGO) run --release --locked --example demo

bench: plugins
	$(CARGO) run --release --locked -- bench --component plugins/dist/hello.wasm \
		--iterations $(BENCH_ITERATIONS) --threads $(BENCH_THREADS) --json docs/bench-results.json

# No Docker-based tests exist; kept for interface parity across projects.
integration:
	@echo "plugbox has no Docker integration tests; everything runs in make check."

clean:
	$(CARGO) clean
	rm -rf plugins/dist
