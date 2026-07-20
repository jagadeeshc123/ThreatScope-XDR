#!/bin/sh
set -eu

: "${THREATSCOPE_PUBLIC_HOST:?THREATSCOPE_PUBLIC_HOST is required}"
envsubst '${THREATSCOPE_PUBLIC_HOST}' < /etc/threatscope/nginx.conf.template > /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
