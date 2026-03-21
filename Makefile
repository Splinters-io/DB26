.PHONY: build test clean recruiter dashboard

# Build all binaries
build: recruiter dashboard

recruiter:
	go build -o bin/recruiter ./cmd/recruiter/

dashboard:
	go build -o bin/dashboard ./cmd/dashboard/

# Run all tests
test:
	go test ./... -v -count=1

# Run tests with coverage
cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Vet and lint
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -rf bin/ coverage.out

# Run recruiter with sample args
run: recruiter
	./bin/recruiter -d testdata/domains_small.txt -s https://oob.dboz.uk
