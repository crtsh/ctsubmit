#!/bin/bash

# Update "stable" Go dependencies.
make generate
go get -u
go mod tidy

# Track the Go toolchain version used to run this update in the go directive.
go mod edit -go=$(go env GOVERSION | sed 's/^go//')
