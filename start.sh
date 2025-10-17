#!/usr/bin/env bash
set -euo pipefail

# Derive DB host from DB_HOST or DB_JDBC_URL
DB_HOST_DERIVED="${DB_HOST:-}"
if [[ -z "${DB_HOST_DERIVED}" && -n "${DB_JDBC_URL:-}" ]]; then
  DB_HOST_DERIVED="$(echo "${DB_JDBC_URL}" | sed -E 's#jdbc:postgresql://([^:/?]+).*#\1#')" || true
fi

if [[ -n "${DB_HOST_DERIVED}" ]]; then
  echo "Waiting for DNS to resolve: ${DB_HOST_DERIVED}"
  for i in $(seq 1 60); do
    if getent hosts "${DB_HOST_DERIVED}" >/dev/null 2>&1; then
      echo "DNS resolved for ${DB_HOST_DERIVED}"
      break
    fi
    echo "Attempt ${i}/60: DNS not resolved yet for ${DB_HOST_DERIVED}, retrying in 2s..."
    sleep 2
  done
fi

exec java -jar app.jar
