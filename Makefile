.PHONY: init build clean test

init:
	git config core.hooksPath .githooks

build:
	go build

clean:
	go clean

test:
	go test -v ./... -count=1
