all: test what-is out/darwin-amd64/what-is out/darwin-arm64/what-is out/linux-amd64/what-is out/linux-arm64/what-is out/windows-amd64/what-is

clean:
	rm -rf out

test:
	go test ./...

what-is: out/what-is

out/what-is:
	go build -o out/what-is ./cmd/what-is

out/darwin-amd64/what-is:
	GOOS=darwin GOARCH=amd64 go build -o out/darwin-amd64/what-is ./cmd/what-is

out/darwin-arm64/what-is:
	GOOS=darwin GOARCH=arm64 go build -o out/darwin-arm64/what-is ./cmd/what-is

out/linux-amd64/what-is:
	GOOS=linux GOARCH=amd64 go build -o out/linux-amd64/what-is ./cmd/what-is

out/linux-arm64/what-is:
	GOOS=linux GOARCH=arm64 go build -o out/linux-arm64/what-is ./cmd/what-is

out/windows-amd64/what-is:
	GOOS=windows GOARCH=amd64 go build -o out/windows-amd64/what-is ./cmd/what-is
