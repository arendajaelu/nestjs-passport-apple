#!/bin/sh
# Packs the library and compiles a strict-mode NestJS consumer against the
# resulting tarball, proving that published type definitions work in a clean
# project without @types/express or @types/passport-strategy installed.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONSUMER="$ROOT/test/types/nestjs-consumer"

TARBALL="$(cd "$ROOT" && npm pack --silent | tail -1)"
trap 'rm -f "$ROOT/$TARBALL"' EXIT

cd "$CONSUMER"
npm install --no-audit --no-fund --no-save "$ROOT/$TARBALL"
npm run typecheck
echo "consumer typecheck passed against $TARBALL"
