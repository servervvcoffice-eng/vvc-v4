#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT
curl -fsS "$BASE_URL/healthz" | grep -qx ok
for unknown_path in /unknown /unknown/hello; do
  status="$(curl -sS -o /tmp/vvcoffice-404-body -w '%{http_code}' "$BASE_URL$unknown_path")"
  test "$status" = 404
  grep -q 'Page Not Found' /tmp/vvcoffice-404-body
done
curl -fsS -D /tmp/vvcoffice-headers "$BASE_URL/home" -o /tmp/vvcoffice-body
 grep -q 'location: /login' /tmp/vvcoffice-headers
curl -fsS -D /tmp/vvcoffice-root-headers "$BASE_URL/" -o /tmp/vvcoffice-root-body
 grep -q 'location: /login' /tmp/vvcoffice-root-headers
if curl -fsS "$BASE_URL/project/home/index.html" >/dev/null 2>&1; then echo 'private source leaked'; exit 1; fi
LOGIN_PASSWORD="${VVC_DEV_PASSWORD:-ChangeMeNow!42}"
curl -fsS -c "$COOKIE_JAR" -H 'content-type: application/json' -d "{\"username\":\"superadmin\",\"password\":\"$LOGIN_PASSWORD\"}" "$BASE_URL/login" | grep -q '"ok":true'
ME="$(curl -fsS -b "$COOKIE_JAR" "$BASE_URL/api/me")"
CSRF="$(printf '%s' "$ME" | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p')"
test -n "$CSRF"
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/admin" | grep -q 'VVC Office'
curl -fsS -b "$COOKIE_JAR" "$BASE_URL/" | grep -q 'VVC Office'
curl -fsS -b "$COOKIE_JAR" -D /tmp/vvcoffice-login-auth-headers "$BASE_URL/login" -o /dev/null
grep -q 'location: /home' /tmp/vvcoffice-login-auth-headers
if curl -fsS -b "$COOKIE_JAR" -X DELETE "$BASE_URL/api/admin/clear/views/all" >/dev/null 2>&1; then echo 'CSRF bypass'; exit 1; fi
curl -fsS -b "$COOKIE_JAR" -H "X-CSRF-Token: $CSRF" -X POST "$BASE_URL/logout" -o /dev/null
printf 'VVC Office smoke checks passed.\n'
