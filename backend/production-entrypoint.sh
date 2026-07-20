#!/bin/sh
set -eu

python scripts/production_preflight.py --create-directories
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 1 \
  --no-server-header \
  --timeout-keep-alive 5 \
  --timeout-graceful-shutdown 30 \
  --no-proxy-headers
