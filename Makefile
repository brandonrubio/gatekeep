.PHONY: test vet fmt run demo oidc-demo build

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

build:
	go build -o bin/ ./cmd/...

run:
	go run ./cmd/server

demo:
	go run ./cmd/demo

oidc-demo:
	go run ./cmd/oidc-demo
