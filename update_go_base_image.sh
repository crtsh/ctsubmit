#!/bin/bash

# Pin the Dockerfile's golang builder image to the Go toolchain that produced
# the go directive, so a module's required Go version and the builder image can
# never drift apart (which would break the build with GOTOOLCHAIN=local on
# Alpine). Only acts when the Go version changes; Alpine-only digest refreshes
# for an unchanged version are left to Dependabot's docker updates.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
dockerfile="$SCRIPT_DIR/Dockerfile"

goversion=$(go env GOVERSION | sed 's/^go//')
current=$(sed -nE 's|^FROM docker\.io/library/golang:([0-9.]+)-alpine@.*|\1|p' "$dockerfile")

if [ "$current" = "$goversion" ]; then
	exit 0
fi

image="docker.io/library/golang:${goversion}-alpine"
digest=$(docker buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')

if [ -z "$digest" ]; then
	echo "update_go_base_image.sh: could not resolve digest for $image" >&2
	exit 1
fi

sed -i -E "s|(^FROM docker\.io/library/golang:)[^ ]+ (AS builder)|\1${goversion}-alpine@${digest} \2|" "$dockerfile"
echo "update_go_base_image.sh: pinned builder to golang:${goversion}-alpine@${digest}"
