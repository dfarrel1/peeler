target_name=bare
navigation=--manifest-path=${target_name}/Cargo.toml
trace_tag=RUST_LOG=trace

build:
	cargo build ${navigation}

run: 
	cargo run ${navigation}

test: 
	cargo test ${navigation}

trace:
	${trace_tag} cargo run ${navigation}

release:
	cargo build ${navigation} --release

# gnu debugger, but it doesn't work on M1 (arm) macs
gdb:
	rust-gdb ${target_name}/target/debug/${target_name}

# refresh crates to speed up builds and runs
meta:
	cargo metadata ${navigation}

clippy:
	cargo clippy --fix --allow-dirty ${navigation}

clippycheck:
	cargo clippy -- -D warnings ${navigation}

tree:
	tree -L 4 -I 'target' 

fmt:
	cargo fmt --all ${navigation}

