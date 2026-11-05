#!/usr/bin/env bash
# Drive every adapter against a server of another implementation, over real sockets:
# HTTP/1.1, HTTP/2, HTTP/3 and WebSocket against nginx (in a container) and against a server
# built on mooncat. The client prints the same four lines whatever carried the exchange, so
# the script compares them.
#
#     bash scripts/http_interop.sh
#
# Needs docker for the nginx half; with no docker only the mooncat half runs.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
client="$root/_build/native/debug/build/examples/01-interop/01-interop.exe"
peer="$root/integration/mooncat-peer/_build/native/debug/build/main/main.exe"
work="$(mktemp -d)"
failures=0

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) exe=".exe" ;;
  *) exe="" ;;
esac
client="$root/_build/native/debug/build/examples/01-interop/01-interop$exe"
peer="$root/integration/mooncat-peer/_build/native/debug/build/main/main$exe"

cleanup() {
  [ -n "${peer_pid:-}" ] && kill "$peer_pid" 2>/dev/null
  command -v docker >/dev/null 2>&1 && docker rm -f moonnet-nginx >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

if [ -z "${MOONNET_NO_BUILD:-}" ]; then
  (cd "$root" && moon build --target native) || exit 1
  (cd "$root/integration/mooncat-peer" && moon build --target native) || exit 1
fi

certs() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 2 -nodes \
    -keyout "$work/key.pem" -out "$work/cert.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
}

check() {
  local name="$1" expected="$2" got="$3"
  if printf '%s' "$got" | grep -qx "$expected"; then
    printf 'ok   %-42s %s\n' "$name" "$expected"
  else
    printf 'FAIL %-42s wanted %s\n' "$name" "$expected"
    printf '%s\n' "$got" | sed 's/^/       got: /'
    failures=$((failures + 1))
  fi
}

# A server that binds its QUIC socket a moment after its TCP one would otherwise fail the
# first run for the wrong reason, so this waits for an answer rather than for a clock.
wait_for_h3() {
  local url="$1" flags="$2" i
  for i in $(seq 1 20); do
    if "$client" h3 "$url" $flags 2>&1 | grep -qx "status 200"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# What any server is asked: a request with no body, one with a body of a known size, and a
# WebSocket message that comes back. HTTP/3 is asked separately, because it is the one that
# took a QUIC connection to ask.
run_http() {
  local server="$1" scheme="$2" host="$3" port="$4" flags="$5"
  local base="$scheme://$host:$port"

  check "$server h1 status" "status 200" "$("$client" h1 "$base/" $flags 2>&1 | head -1)"
  check "$server h1 body"   "body 1.1 GET / 0" "$("$client" h1 "$base/" $flags 2>&1 | sed -n 3p)"
  check "$server h1 post"   "body abcdefghijklmnopqrstuvwxyz" \
    "$("$client" h1 "$base/echo" body=26 $flags 2>&1 | sed -n 3p)"

  check "$server h2 status" "status 200" "$("$client" h2 "$base/" $flags 2>&1 | head -1)"
  check "$server h2 alpn"   "alpn h2"    "$("$client" h2 "$base/" $flags 2>&1 | sed -n 2p)"
  check "$server h2 post"   "body abcdefghijklmnopqrstuvwxyz" \
    "$("$client" h2 "$base/echo" body=26 $flags 2>&1 | sed -n 3p)"

  local ws="$scheme"
  [ "$scheme" = "https" ] && ws="wss"
  check "$server ws status"  "status 101" "$("$client" ws "$ws://$host:$port/chat" message=ping $flags 2>&1 | head -1)"
  check "$server ws message" "message ping" \
    "$("$client" ws "$ws://$host:$port/chat" message=ping $flags 2>&1 | sed -n 2p)"
}

# One run of the client answers both questions, because a server may take one QUIC
# connection per process and a second run would then be asking a different question.
run_h3() {
  local server="$1" scheme="$2" host="$3" port="$4" flags="$5"
  local base="$scheme://$host:$port" out="" i
  for i in $(seq 1 15); do
    out="$("$client" h3 "$base/" $flags 2>&1)"
    printf '%s' "$out" | grep -qx "status 200" && break
    sleep 2
  done
  check "$server h3 status" "status 200" "$(printf '%s' "$out" | head -1)"
  check "$server h3 alpn"   "alpn h3"    "$(printf '%s' "$out" | sed -n 2p)"
  printf '%s' "$out" | sed -n 3p >"$work/h3.body"
}

certs

# The server of the family's own: no container, no image. It is started twice, because its
# HTTP/3 side takes one QUIC connection per process and the second run would be refused by
# the server rather than by this client.
start_peer() {
  local ready_by="${1:-h1}"
  "$peer" 18444 "$work/cert.pem" "$work/key.pem" >"$work/peer.log" 2>&1 &
  peer_pid=$!
  sleep 3
  local i
  for i in $(seq 1 20); do
    if "$client" "$ready_by" "https://127.0.0.1:18444/" insecure 2>&1 | grep -qx "status 200"; then
      return 0
    fi
    sleep 1
  done
  echo "the mooncat peer did not come up:"
  cat "$work/peer.log"
  return 1
}

start_peer h1 && run_http mooncat https 127.0.0.1 18444 insecure
kill "$peer_pid" 2>/dev/null
peer_pid=
sleep 1
start_peer h1 && run_h3 mooncat https 127.0.0.1 18444 insecure
kill "$peer_pid" 2>/dev/null
peer_pid=

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  cat >"$work/nginx.conf" <<'CONF'
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events { worker_connections 256; }
http {
  access_log off;
  server {
    listen 80;
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;
    ssl_certificate /certs/cert.pem;
    ssl_certificate_key /certs/key.pem;
    ssl_protocols TLSv1.3;
    add_header Alt-Svc 'h3=":443"; ma=86400' always;
    location / { default_type text/plain; return 200 "hello from nginx\n"; }
    location /echo { default_type text/plain; return 200 "\$request_method \$uri\n"; }
  }
}
CONF
  docker run -d --name moonnet-nginx -p 18080:80 -p 18443:443/tcp -p 18443:443/udp \
    -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$work:/certs:ro" nginx:latest >/dev/null
  sleep 3
  check "nginx h1 status" "status 200" "$("$client" h1 http://127.0.0.1:18080/ 2>&1 | head -1)"
  check "nginx h1 body"   "body hello from nginx" "$("$client" h1 http://127.0.0.1:18080/ 2>&1 | sed -n 3p)"
  check "nginx h2 status" "status 200" "$("$client" h2 https://localhost:18443/ insecure 2>&1 | head -1)"
  check "nginx h2 alpn"   "alpn h2"    "$("$client" h2 https://localhost:18443/ insecure 2>&1 | sed -n 2p)"
  run_h3 nginx https localhost 18443 insecure
  check "nginx h3 body" "body hello from nginx" "$(cat "$work/h3.body")"
else
  echo "skip nginx: no docker here"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures checks failed"
  exit 1
fi
echo "all checks passed"
