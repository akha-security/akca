.PHONY: build build-api build-policy test benchmark quality clean

build:
	cd engine && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o ../akca ./cmd/akca

build-api:
	cd engine && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o ../akca-api ./cmd/akca-api

build-policy:
	cd engine && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o ../akca-policy ./cmd/akca-policy

test:
	cd engine && go test ./... -short

benchmark:
	@tmpdir="$$(mktemp -d)"; trap 'rm -rf "$$tmpdir"' EXIT; \
	cd engine && go run ./cmd/akca benchmark --db "$$tmpdir/akca-benchmark.db" --output "$$tmpdir/benchmark-quality.json" --strict

quality:
	cd engine && test -z "$$(gofmt -l .)"
	cd engine && go test ./...
	cd engine && go vet ./...
	cd engine && go test -race ./...
	$(MAKE) benchmark

clean:
	rm -f akca akca-api akca-policy
