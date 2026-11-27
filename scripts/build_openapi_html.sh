#!/bin/bash
# Run from the repo root so npm uses the checked-in package-lock.json.
cd "$(dirname "$(readlink -f "$0")")/.."
npm ci --no-audit --no-fund
# Suppress Redocly's update/announcement banners and opt out of its usage telemetry.
export REDOCLY_SUPPRESS_NOTIFICATIONS=true REDOCLY_TELEMETRY=off
./node_modules/.bin/redocly build-docs docs/openapi.yaml -o docs/openapi.html
