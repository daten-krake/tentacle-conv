.PHONY: build test vet fmt lint clean

build:
	go build ./...

test:
	go test ./... -v -count=1

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet fmt

clean:
	rm -f bin/*