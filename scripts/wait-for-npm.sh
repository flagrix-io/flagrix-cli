#!/usr/bin/env bash
# Wait until npm serves <package>@<version>, both as its own document and in
# the package's version list. The MCP Registry checks npm when server.json is
# published, and a version npm has just accepted can take minutes to appear —
# publishing straight after `npm publish` got a 400 for 0.5.1.
#
# Usage: scripts/wait-for-npm.sh <package> <version> [timeout-seconds]
set -euo pipefail

pkg="$1"
version="$2"
timeout="${3:-900}"
deadline=$(( $(date +%s) + timeout ))

until
  [ "$(curl -s -o /dev/null -w '%{http_code}' "https://registry.npmjs.org/$pkg/$version")" = "200" ] &&
  curl -fsS "https://registry.npmjs.org/$pkg" | jq -e --arg v "$version" '.versions | has($v)' > /dev/null
do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "::error::npm still doesn't serve $pkg@$version after ${timeout}s"
    exit 1
  fi
  echo "Waiting for npm to serve $pkg@$version…"
  sleep 20
done
echo "npm serves $pkg@$version"
