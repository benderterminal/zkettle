VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o dist/zkettle .

build-all:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/zkettle-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/zkettle-darwin-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/zkettle-linux-arm64 .
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/zkettle-linux-amd64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/zkettle-windows-amd64.exe .

test:
	go test ./...

install: build
	@if [ -n "$(GOPATH)" ] && [ -d "$(GOPATH)/bin" ]; then \
		cp dist/zkettle $(GOPATH)/bin/zkettle; \
	elif [ -d "$(HOME)/go/bin" ]; then \
		cp dist/zkettle $(HOME)/go/bin/zkettle; \
	else \
		cp dist/zkettle /usr/local/bin/zkettle; \
	fi

clean:
	rm -rf dist/

.PHONY: build build-all test install clean
