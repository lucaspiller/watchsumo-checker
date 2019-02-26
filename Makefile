build:
	mkdir build
	go build -o build/checker

test:
	go test ./... -short

fmt:
	gofmt -w .
