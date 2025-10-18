#!/usr/bin/env bash
set -euo pipefail

# Derive DB host from DB_HOST or DB_JDBC_URL
DB_HOST_DERIVED="${DB_HOST:-}"
if [[ -z "${DB_HOST_DERIVED}" && -n "${DB_JDBC_URL:-}" ]]; then
  DB_HOST_DERIVED="$(echo "${DB_JDBC_URL}" | sed -E 's#jdbc:postgresql://([^:/?]+).*#\1#')" || true
fi

# Safe startup logging (avoid printing secrets)
DB_PASSWORD_MASKED="<unset>"
if [[ -n "${DB_PASSWORD:-}" ]]; then
  DB_PASSWORD_MASKED="$(printf '%*s' ${#DB_PASSWORD} '' | tr ' ' '*')"
fi

echo "Startup: PORT=${PORT:-unset}"
echo "Startup: SPRING_PROFILES_ACTIVE=${SPRING_PROFILES_ACTIVE:-unset}"
echo "Startup: JAVA_TOOL_OPTIONS=${JAVA_TOOL_OPTIONS:-unset}"
echo "Startup: DB_JDBC_URL=${DB_JDBC_URL:-unset}"
echo "Startup: DB_USERNAME=${DB_USERNAME:-unset}"
echo "Startup: DB_PASSWORD=${DB_PASSWORD_MASKED}"
echo "Startup: DB_DEFAULT_SCHEMA=${DB_DEFAULT_SCHEMA:-unset}"
echo "Startup: DB_POOL_SIZE=${DB_POOL_SIZE:-unset}"
echo "Startup: DB_MIN_IDLE=${DB_MIN_IDLE:-unset}"
echo "Startup: DB_CONN_TIMEOUT_MS=${DB_CONN_TIMEOUT_MS:-unset}"
echo "Startup: DB_IDLE_TIMEOUT_MS=${DB_IDLE_TIMEOUT_MS:-unset}"
echo "Startup: DB_KEEPALIVE_MS=${DB_KEEPALIVE_MS:-unset}"
echo "Startup: DB_VALIDATION_TIMEOUT_MS=${DB_VALIDATION_TIMEOUT_MS:-unset}"
echo "Startup: DB_HOST=${DB_HOST:-unset}"
echo "Startup: Derived DB host=${DB_HOST_DERIVED:-unset}"

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
