#!/usr/bin/env bash
# Walks through every behaviour that has to be screenshotted for Work 1.
# Start the API first:  cd secure-api && mvn spring-boot:run
#
# Usage: ./scripts/demo_api.sh [base-url]
set -uo pipefail

BASE="${1:-http://localhost:9090}"
USER_NAME="${DEMO_USER:-alice}"
USER_PASS="${DEMO_PASS:-Alice@Passw0rd}"

hr() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

if ! curl -s -o /dev/null --max-time 5 "${BASE}/auth/login" -X POST \
        -H 'Content-Type: application/json' -d '{}'; then
  echo "API is not reachable at ${BASE}. Start it with: cd secure-api && mvn spring-boot:run"
  exit 1
fi

hr "1. POST /auth/login - success returns a JWT"
LOGIN=$(curl -s -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USER_NAME}\",\"password\":\"${USER_PASS}\"}")
echo "${LOGIN}"
TOKEN=$(printf '%s' "${LOGIN}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
if [ -z "${TOKEN}" ]; then
  echo "Login failed - check the demo credentials."
  exit 1
fi

hr "2. GET /api/data without a token - expect 401"
curl -s -i "${BASE}/api/data" | head -n 1
curl -s "${BASE}/api/data"

hr "3. GET /api/data with the token - expect 200 and no passwordHash"
curl -s -i "${BASE}/api/data" -H "Authorization: Bearer ${TOKEN}" | head -n 1
curl -s "${BASE}/api/data" -H "Authorization: Bearer ${TOKEN}"

hr "4. SQL injection in the login body - expect 401"
curl -s -i -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}' | head -n 1
curl -s -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}'

hr "5. SQL injection in the search parameter - expect 400"
curl -s -i --get "${BASE}/api/posts" \
  --data-urlencode "q=' OR 1=1 --" \
  -H "Authorization: Bearer ${TOKEN}" | head -n 1

hr "6. XSS payload is stored escaped, not as markup"
curl -s -X POST "${BASE}/api/posts" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(1)>"}'

hr "7. Identity carried by the token"
curl -s "${BASE}/api/me" -H "Authorization: Bearer ${TOKEN}"

hr "8. DELETE as a non-admin user - expect 403"
curl -s -i -X DELETE "${BASE}/api/posts/1" \
  -H "Authorization: Bearer ${TOKEN}" | head -n 1

hr "9. Tampered token - expect 401"
curl -s -i "${BASE}/api/data" -H "Authorization: Bearer ${TOKEN%??}aa" | head -n 1

printf '\nDone. The expected status codes are printed above each response.\n'
