.PHONY: tree data clean build run test clippycheck clippy fmt

tree:
	tree -L 4 -I 'target' 

data:
	python3.9 data/generator/generator.py 

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

