#!/bin/bash

# Update "stable" Go dependencies.
make generate
go get -u
go mod tidy

# Track the Go toolchain version used to run this update in the go directive.
go mod edit -go=$(go env GOVERSION | sed 's/^go//')

# Keep the Dockerfile's golang builder image in step with the go directive.
SCRIPT_DIR=`cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd`
$SCRIPT_DIR/update_go_base_image.sh
