#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

API_URL=${API_URL:-http://localhost:8000}

if ! command -v jq >/dev/null 2>&1; then
  echo "Se requiere jq para ejecutar este script" >&2
  exit 1
fi

if [ -z "${TOKEN:-}" ]; then
  TOKEN=$(curl -s -X POST "$API_URL/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username": "admin", "password": "admin"}' | jq -r '.access_token')
fi

if [ -z "$TOKEN" ]; then
  echo "No se pudo obtener token de autenticación" >&2
  exit 1
fi

curl -sf -H "Authorization: Bearer $TOKEN" -F "file=@scripts/mocks_demo.zip" "$API_URL/api/admin/import"
