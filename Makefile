VERSION ?= $(shell git describe --tags)

.PHONY: all clean test what-is .version

what-is: .version out/what-is

all: test .version out/what-is out/darwin-amd64/what-is out/darwin-arm64/what-is out/linux-amd64/what-is out/linux-arm64/what-is out/windows-amd64/what-is

clean:
	rm -rf out

test: internal/
	go test ./...


out/what-is: out/.version cmd/ internal/
	go build -o out/what-is -ldflags "-X main.Version=$(VERSION)" ./cmd/what-is

out/darwin-amd64/what-is: out/.version cmd/ internal/
	GOOS=darwin GOARCH=amd64 go build -o out/darwin-amd64/what-is -ldflags "-X main.Version=$(VERSION)" ./cmd/what-is

out/darwin-arm64/what-is: out/.version cmd/ internal/
	GOOS=darwin GOARCH=arm64 go build -o out/darwin-arm64/what-is -ldflags "-X main.Version=$(VERSION)" ./cmd/what-is

out/linux-amd64/what-is: out/.version cmd/ internal/
	GOOS=linux GOARCH=amd64 go build -o out/linux-amd64/what-is -ldflags "-X main.Version=$(VERSION)" ./cmd/what-is

out/linux-arm64/what-is: out/.version cmd/ internal/
	GOOS=linux GOARCH=arm64 go build -o out/linux-arm64/what-is -ldflags "-X main.Version=$(VERSION)" ./cmd/what-is

out/windows-amd64/what-is: out/.version cmd/ internal/
	GOOS=windows GOARCH=amd64 go build -o out/windows-amd64/what-is -ldflags "-X main.Version=$(VERSION)" ./cmd/what-is

.version:
ifneq ($(strip $(shell cat out/.version 2>/dev/null || true)),$(VERSION))
	[ -d out ] || mkdir out
	echo "$(VERSION)" > out/.version
endif
