#!/usr/bin/env bash
set -euo pipefail

# Usage: bash docker-build-image.sh <version> [image] [build-date]
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
version="${1:?Usage: bash docker-build-image.sh <version> [image] [build-date]}"
image="${2:-cli-proxy-api}"
build_date="${3:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
commit="$(git -C "$root" rev-parse --short HEAD)"

docker build \
  --file "$root/Dockerfile" \
  --tag "${image}:${version}" \
  --build-arg "VERSION=$version" \
  --build-arg "COMMIT=$commit" \
  --build-arg "BUILD_DATE=$build_date" \
  --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.created=$build_date" \
  "$root"
