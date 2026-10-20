#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <application-repo> <out-dir> [service...]" >&2
  exit 1
fi

sdkgen="$(cd "$(dirname "$0")/.." && pwd)"
app="$(cd "$1" && pwd)"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
shift 2
services=("$@")
if [ "${#services[@]}" -eq 0 ]; then services=(user admin); fi
image="${SDKGEN_CRYSTAL_IMAGE:-crystallang/crystal:0.34.0}"

script='set -e; crystal build "$SDKGEN/main.cr" -o "$BIN"'
for service in "${services[@]}"; do
  [[ "$service" =~ ^[a-z][a-z0-9_-]*$ ]] || { echo "Invalid service name" >&2; exit 1; }
  script+="; mkdir -p \"\$OUT/src/$service\" \"\$OUT/src/test/$service\" \"\$OUT/deploy/web/$service\""
  script+="; \"\$BIN\" \"\$APP/src/$service/api.sdkgen\" -o \"\$OUT/src/$service/api.ts\" -t typescript_nodeserver"
  script+="; \"\$BIN\" \"\$APP/src/$service/api.sdkgen\" -o \"\$OUT/src/test/$service/client.ts\" -t typescript_nodeclient"
  script+="; \"\$BIN\" \"\$APP/src/$service/api.sdkgen\" -o \"\$OUT/deploy/web/$service/api.ts\" -t typescript_web"
done

if command -v crystal >/dev/null 2>&1; then
  SDKGEN="$sdkgen" APP="$app" OUT="$out" BIN="$out/.sdkgen" bash -c "$script"
  rm -f "$out/.sdkgen"
else
  docker run --rm --platform linux/amd64 \
    -v "$sdkgen":/sdkgen:ro -v "$app":/app:ro -v "$out":/out \
    -e SDKGEN=/sdkgen -e APP=/app -e OUT=/out -e BIN=/tmp/sdkgen \
    "$image" bash -c "$script"
fi
echo "generated in $out"
