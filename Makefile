.PHONY: build release server upload clean

FILE ?=
URL ?= http://127.0.0.1:3000

build:
	cargo build

release:
	cargo build --release

server:
	cargo run -p server

upload:
	@if [ -z "$(FILE)" ]; then echo "usage: make upload FILE=./path/to/file [URL=http://127.0.0.1:3000]"; exit 1; fi
	cargo run -p client -- "$(FILE)"

clean:
	cargo clean
	rm -rf uploads