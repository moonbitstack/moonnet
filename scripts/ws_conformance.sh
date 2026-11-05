#!/usr/bin/env bash
# WebSocket conformance: Autobahn's fuzzing server drives the client end of the protocol. The
# suite runs in a container, the client is this repository's, and the verdict is the server's
# report rather than anything the client says about itself.
#
#   bash scripts/ws_conformance.sh [port]
#
# Needs docker. The port must be free on the host and is the one the server listens on inside
# the container too, because the suite checks the Host field against it.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
port="${1:-19001}"
agent=moonnet
work="$(mktemp -d)"
trap 'docker rm -f moonnet-autobahn >/dev/null 2>&1 || true; rm -rf "$work" 2>/dev/null || true' EXIT

if [ -z "${MOONNET_NO_BUILD:-}" ]; then
  (cd "$root" && moon build --target native)
fi

# 9.* measures throughput with messages from 64 KiB to 16 MiB, which is a performance run rather
# than a conformance one; 12.* and 13.* exercise permessage-deflate, which this adapter does not
# negotiate, so a client that never asks for the extension has nothing to answer.
cat >"$work/fuzzingserver.json" <<CONF
{
  "url": "ws://0.0.0.0:$port",
  "outdir": "/reports/clients",
  "cases": ["*"],
  "exclude-cases": ["9.*", "12.*", "13.*"],
  "exclude-agent-cases": {}
}
CONF
mkdir -p "$work/reports"

docker rm -f moonnet-autobahn >/dev/null 2>&1 || true
docker run -d --name moonnet-autobahn \
  -p "$port:$port" \
  -v "$work:/config:ro" \
  -v "$work/reports:/reports" \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingserver -s /config/fuzzingserver.json >/dev/null

# The server prints its case count once it is listening; asking it is the cheapest readiness
# check, and the client does that anyway.
for _ in $(seq 1 30); do
  if docker logs moonnet-autobahn 2>&1 | grep -q "will run"; then
    break
  fi
  sleep 1
done

(cd "$root" && moon run src/examples/04-ws-conformance --target native -- 127.0.0.1 "$port" 1 1000)
python3 "$root/scripts/ws_report.py" "$work/reports/clients/index.json" "$agent"
