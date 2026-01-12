IMAGE := "kuberhealthy/ssl-expiry-check"
TAG := "latest"

# Build the SSL expiry check container locally.
build:
	podman build -f Containerfile -t {{IMAGE}}:{{TAG}} .

# Run the unit tests for the SSL expiry check.
test:
	go test ./...

# Build the SSL expiry check binary locally.
binary:
	go build -o bin/ssl-expiry-check ./cmd/ssl-expiry-check
