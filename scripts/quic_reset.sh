#!/usr/bin/env bash
# Drive a stream reset from this library against a QUIC implementation it did not write, and
# read both sides: the client says what it sent, the peer says which frames arrived, and the
# peer's own wire log says the same frames left in the other direction. A frame this side
# believes it sent is not evidence until the peer reports it.
#
#     bash scripts/quic_reset.sh
#
# Needs a Go toolchain (1.24 or later) for the peer, which is quic-go.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
failures=0

cleanup() {
  [ -n "${peer_pid:-}" ] && kill "$peer_pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

# The binary the build names, wherever it put it and whatever extension it added.
binary() {
  local dir="$1" name="$2" found
  found="$(cd "$dir" && ls -1 2>/dev/null | grep -E "^$name(\\.exe)?$" | head -1)"
  [ -n "$found" ] || { echo "no $name under $dir" >&2; exit 1; }
  echo "$dir/$found"
}

if [ -z "${MOONNET_NO_BUILD:-}" ]; then
  (cd "$root" && moon build src/examples/05-quic-reset --target native) || exit 1
fi
client="$(binary "$root/_build/native/debug/build/examples/05-quic-reset" 05-quic-reset)"

(cd "$root/integration/quic-reset-peer" && go build -o "$work/peer" .) || exit 1

# A certificate for the peer; the client is told to trust it and to skip the chain check, since a
# peer started by a script cannot be issued one a test root signs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 2 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# The peer's own log is half the evidence: at debug level quic-go writes every frame it
# received, which is where the frames this side sent are read from.
QUIC_GO_LOG_LEVEL=debug "$work/peer" --cert "$work/cert.pem" --key "$work/key.pem" \
  >"$work/peer.log" 2>&1 &
peer_pid=$!

# The port is the system's choice, so it is read out of the peer's first line rather than
# chosen here.
port=""
for _ in $(seq 1 50); do
  port="$(sed -n 's/^listening \([0-9]*\)$/\1/p' "$work/peer.log" | head -1)"
  [ -n "$port" ] && break
  sleep 0.2
done
if [ -z "$port" ]; then
  echo "the peer did not come up:"
  cat "$work/peer.log"
  exit 1
fi

"$client" 127.0.0.1 "$port" "ca=$work/cert.pem" insecure >"$work/client.log" 2>&1
status=$?

# The peer reports a frame when its application sees it, which is a moment after the client's
# last turn; the wait is for that line, not for a clock.
for _ in $(seq 1 50); do
  grep -q "^sent stop 8 55$" "$work/peer.log" && break
  sleep 0.2
done
kill "$peer_pid" 2>/dev/null
peer_pid=

if [ "$status" -ne 0 ]; then
  echo "the client exited $status:"
  cat "$work/client.log"
  cat "$work/peer.log"
  exit 1
fi

# A line the program printed, whole.
check() {
  local side="$1" file="$2" want="$3"
  if grep -qxF -- "$want" "$file"; then
    printf 'ok   %-6s  %s\n' "$side" "$want"
  else
    printf 'FAIL %-6s  %s\n' "$side" "$want"
    sed 's/^/       got: /' "$file"
    failures=$((failures + 1))
  fi
}

check client "$work/client.log" "alpn moonnet-reset"
check client "$work/client.log" "stream 0: peer reset 99"
check client "$work/client.log" "stream 0: reset sent 42"
check client "$work/client.log" "stream 4: echo echo:abc"
check client "$work/client.log" "stream 4: stop sent 7"
check client "$work/client.log" "stream 4: peer reset 7"
check client "$work/client.log" "stream 8: peer stop 55"
check client "$work/client.log" "stream 8: write refused 55"
check client "$work/client.log" "done"

# The same three cases as the peer's application saw them.
check peer "$work/peer.log" "alpn moonnet-reset"
check peer "$work/peer.log" "data 0 5"
check peer "$work/peer.log" "reset 0 42"
check peer "$work/peer.log" "data 4 3"
check peer "$work/peer.log" "stop 4 7"
check peer "$work/peer.log" "data 8 4"
check peer "$work/peer.log" "sent stop 8 55"

# And the frames on the peer's wire, which is where the reset this side owes a STOP_SENDING is
# visible: the stream it arrived on has no reader left to tell. These lines carry a timestamp, so
# they are looked for inside the line.
on_wire() {
  local want="$1"
  if grep -qF -- "$want" "$work/peer.log"; then
    printf 'ok   %-6s  %s\n' wire "$want"
  else
    printf 'FAIL %-6s  %s\n' wire "$want"
    grep -F -- "<- &wire." "$work/peer.log" | sed 's/^/       got: /'
    failures=$((failures + 1))
  fi
}

on_wire "<- &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x2a, FinalSize: 5}"
on_wire "<- &wire.StopSendingFrame{StreamID:4, ErrorCode:0x7}"
on_wire "<- &wire.ResetStreamFrame{StreamID: 8, ErrorCode: 0x37, FinalSize: 4}"

if [ "$failures" -ne 0 ]; then
  echo "$failures checks failed"
  echo "--- the peer log"
  cat "$work/peer.log"
  exit 1
fi
echo "all checks passed"
