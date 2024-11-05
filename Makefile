VERSION ?= $(shell git describe --tags)

.PHONY: all clean test decipher .version

decipher: .version out/decipher

all: test .version out/decipher out/darwin-amd64/decipher out/darwin-arm64/decipher out/linux-amd64/decipher out/linux-arm64/decipher out/windows-amd64/decipher

clean:
	rm -rf out

test: internal/
	go test ./...

GO_INTERNAL_FILES=$(shell find internal -name '*.go')

out/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	go build -o out/decipher -ldflags "-X main.Version=$(VERSION)" ./cmd/decipher

out/darwin-amd64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=darwin GOARCH=amd64 go build -o out/darwin-amd64/decipher -ldflags "-X main.Version=$(VERSION)" ./cmd/decipher

out/darwin-arm64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=darwin GOARCH=arm64 go build -o out/darwin-arm64/decipher -ldflags "-X main.Version=$(VERSION)" ./cmd/decipher

out/linux-amd64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=linux GOARCH=amd64 go build -o out/linux-amd64/decipher -ldflags "-X main.Version=$(VERSION)" ./cmd/decipher

out/linux-arm64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=linux GOARCH=arm64 go build -o out/linux-arm64/decipher -ldflags "-X main.Version=$(VERSION)" ./cmd/decipher

out/windows-amd64/decipher: out/.version cmd/decipher/main.go $(GO_INTERNAL_FILES)
	GOOS=windows GOARCH=amd64 go build -o out/windows-amd64/decipher -ldflags "-X main.Version=$(VERSION)" ./cmd/decipher

.version:
ifneq ($(strip $(shell cat out/.version 2>/dev/null || true)),$(VERSION))
	[ -d out ] || mkdir out
	echo "$(VERSION)" > out/.version
endif
