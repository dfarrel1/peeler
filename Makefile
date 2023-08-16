tree:
	tree -L 4 -I 'target' 

clean:
	cargo clean

build:
	cargo build

run: 
	cargo run

test: 
	cargo test -- --nocapture

clippycheck:
	cargo clippy -- -D warnings

clippy:
	cargo clippy --fix --allow-dirty

fmt:
	cargo fmt --all

