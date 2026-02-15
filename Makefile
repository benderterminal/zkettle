VERSION ?= dev

build:
	go build -ldflags "-X main.version=$(VERSION)" -o dist/zkettle .

build-all:
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o dist/zkettle-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o dist/zkettle-darwin-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o dist/zkettle-linux-arm64 .
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o dist/zkettle-linux-amd64 .

test:
	go test ./...

clean:
	rm -rf dist/

.PHONY: build build-all test clean
