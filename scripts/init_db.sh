#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v poetry >/dev/null 2>&1; then
  echo "Poetry no encontrado. Instálelo para continuar." >&2
  exit 1
fi

cd backend
poetry run alembic upgrade head
