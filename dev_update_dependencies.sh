#!/bin/bash

# Update "dev" Go dependencies.
make generate
go get -modfile=dev_go.mod -u
go mod tidy -modfile=dev_go.mod

# Track the Go toolchain version used to run this update in the go directive.
go mod edit -modfile=dev_go.mod -go=$(go env GOVERSION | sed 's/^go//')

# Run the find_optimal_parents.sh script to update optimal_parents.csv
SCRIPT_DIR=`cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd`
$SCRIPT_DIR/find_optimal_parents.sh
