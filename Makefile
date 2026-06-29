BINS := pqc pqcd
BIN_DIR ?= bin

.PHONY: all test build install clean fmt

all: test build

test:
	go test ./...

fmt:
	gofmt -w .

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/pqc ./cmd/pqc
	go build -o $(BIN_DIR)/pqcd ./cmd/pqcd

install:
	go install ./cmd/pqc
	go install ./cmd/pqcd

clean:
	rm -rf $(BIN_DIR)

