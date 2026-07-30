#!/bin/bash

# Update "stable" Go dependencies.
make generate
go get -u
go mod tidy
