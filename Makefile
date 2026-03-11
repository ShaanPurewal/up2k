.PHONY: build server upload clean

FILE ?=
URL ?= http://127.0.0.1:3000

build:
	cargo build

server:
	cargo run -p server

upload:
	@if [ -z "$(FILE)" ]; then echo "usage: make upload FILE=./path/to/file [URL=http://127.0.0.1:3000]"; exit 1; fi
	cargo run -p client -- upload "$(FILE)" "$(URL)"

clean:
	cargo clean
	rm -rf uploads
