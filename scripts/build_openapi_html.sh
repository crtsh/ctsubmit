#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")"
npm list @redocly/cli || npm i @redocly/cli@2.46.1
npx @redocly/cli@2.46.1 build-docs ../docs/openapi.yaml -o ../docs/openapi.html
