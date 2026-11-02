#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT
curl -fsS "$BASE_URL/healthz" | grep -qx ok
curl -fsS -D /tmp/aegis-headers "$BASE_URL/home" -o /tmp/aegis-body
 grep -q 'location: /login' /tmp/aegis-headers
if curl -fsS "$BASE_URL/project/home/index.html" >/dev/null 2>&1; then echo 'private source leaked'; exit 1; fi
LOGIN_PASSWORD="${AEGIS_DEV_PASSWORD:-ChangeMeNow!42}"
curl -fsS -c "$COOKIE_JAR" -H 'content-type: application/json' -d "{\"username\":\"superadmin\",\"password\":\"$LOGIN_PASSWORD\"}" "$BASE_URL/login" | grep -q '"ok":true'
ME="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/me")"
CSRF="$(printf '%s' "$ME" | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p')"
test -n "$CSRF"
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/admin" | grep -q 'Admin Console'
if curl -fsS -b "$COOKIE_JAR" -X DELETE "$BASE_URL/api/admin/clear/views/all" >/dev/null 2>&1; then echo 'CSRF bypass'; exit 1; fi
curl -fsS -b "$COOKIE_JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE_URL/logout" -o /dev/null
printf 'AegisCore smoke checks passed.\n'
