#!/bin/sh
# DESIGN §8 (M7): JSON is serialized only through frego::json_out(), which can't throw on
# invalid UTF-8. Fails if .dump( appears anywhere else in our sources.
set -eu
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
hits=$(grep -rn --include='*.cpp' --include='*.hpp' '\.dump(' \
  "$root/events" "$root/net" "$root/platform" "$root/core" "$root/domain" "$root/plugins" "$root/apps" "$root/tests" \
  | grep -v "^$root/events/src/json.cpp:" || true)
if [ -n "$hits" ]; then
  echo "Use frego::json_out() instead of .dump():"
  echo "$hits"
  exit 1
fi
echo "ok: .dump( only in events/src/json.cpp"
