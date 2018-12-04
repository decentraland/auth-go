.PHONY: init build clean test coverage

init:
	git config core.hooksPath .githooks

build:
	go build

clean:
	go clean

test:
	go test -v ./... -count=1

coverage:
	go test -v ./... -count=1 -coverprofile cover.out \
	    && go tool cover -html=cover.out
