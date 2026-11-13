#!/usr/bin/env bash
# Drive a stream reset from this library against QUIC implementations it did not write, and read
# both sides: the client says what it sent, the peer says which frames arrived, and the peer's own
# wire log says the same frames left in the other direction. A frame this side believes it sent is
# not evidence until the peer reports it.
#
#     bash scripts/quic_reset.sh
#
# Needs a Go toolchain (1.25 or later) for the peer, which is quic-go.
#
# The Go peer runs twice, because its Initial packet size decides whether the ServerHello carrying
# the hybrid key share fits in one datagram or spills into two, and a client that reassembles one
# and not the other would pass half these checks.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
failures=0

stop_peer() {
  if [ -n "${peer_pid:-}" ]; then
    kill "$peer_pid" 2>/dev/null
    wait "$peer_pid" 2>/dev/null
    peer_pid=
  fi
}

cleanup() {
  stop_peer
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

(cd "$root/integration/quic-reset-peer" && go build -o "$work/peer-go" .) || exit 1

# A certificate for the peer; the client is told to trust it and to skip the chain check, since a
# peer started by a script cannot be issued one a test root signs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 2 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# A line the program printed, whole.
check() {
  local side="$1" file="$2" want="$3"
  if grep -qxF -- "$want" "$file"; then
    printf 'ok   %-8s %s\n' "$side" "$want"
  else
    printf 'FAIL %-8s %s\n' "$side" "$want"
    sed 's/^/       got: /' "$file"
    failures=$((failures + 1))
  fi
}

# A line inside a longer one, for the peer's log, where every frame quic-go reads or writes is
# prefixed with a timestamp.
on_wire() {
  local file="$1" want="$2"
  if grep -qF -- "$want" "$file"; then
    printf 'ok   %-8s %s\n' wire "$want"
  else
    printf 'FAIL %-8s %s\n' wire "$want"
    grep -F -- "<- &wire." "$file" | sed 's/^/       got: /'
    failures=$((failures + 1))
  fi
}

# One run: start the peer, take the port it reports, drive the client through the three cases,
# then compare what each end says. `size` is the peer's Initial packet size.
run() {
  local tag="$1" size="$2"
  local dir="$work/$tag"
  mkdir -p "$dir"

  QUIC_GO_LOG_LEVEL=debug "$work/peer-go" --cert "$work/cert.pem" --key "$work/key.pem" \
    --initial "$size" >"$dir/peer.log" 2>&1 &
  peer_pid=$!

  # The port is the system's choice, so it is read out of the peer's first line rather than
  # chosen here.
  local port=""
  for _ in $(seq 1 50); do
    port="$(sed -n 's/^listening \([0-9]*\)$/\1/p' "$dir/peer.log" | head -1)"
    [ -n "$port" ] && break
    sleep 0.2
  done
  if [ -z "$port" ]; then
    echo "the $tag peer did not come up:"
    cat "$dir/peer.log"
    exit 1
  fi
  echo "-- $tag"

  "$client" 127.0.0.1 "$port" "ca=$work/cert.pem" insecure >"$dir/client.log" 2>&1
  local status=$?

  # The peer reports a frame when its application sees it, which is a moment after the client's
  # last turn; the wait is for that line, not for a clock.
  for _ in $(seq 1 50); do
    grep -q "^sent stop 8 55$" "$dir/peer.log" && break
    sleep 0.2
  done
  stop_peer

  if [ "$status" -ne 0 ]; then
    echo "the client exited $status:"
    cat "$dir/client.log"
    cat "$dir/peer.log"
    exit 1
  fi

  check client "$dir/client.log" "alpn moonnet-reset"
  check client "$dir/client.log" "stream 0: peer reset 99"
  check client "$dir/client.log" "stream 0: reset sent 42"
  check client "$dir/client.log" "stream 4: echo echo:abc"
  check client "$dir/client.log" "stream 4: stop sent 7"
  # The code the peer answers the stop with, which is the one the script chose for it.
  check client "$dir/client.log" "stream 4: peer reset 7"
  check client "$dir/client.log" "stream 8: peer stop 55"
  check client "$dir/client.log" "stream 8: write refused 55"
  check client "$dir/client.log" "done"

  # The same three cases as the peer's application saw them.
  check peer "$dir/peer.log" "alpn moonnet-reset"
  check peer "$dir/peer.log" "data 0 5"
  check peer "$dir/peer.log" "reset 0 42"
  check peer "$dir/peer.log" "data 4 3"
  check peer "$dir/peer.log" "stop 4 7"
  check peer "$dir/peer.log" "data 8 4"
  check peer "$dir/peer.log" "sent stop 8 55"

  # The key exchange the handshake settled on: 4588 is X25519MLKEM768. Without this line the
  # rest of the run says nothing about the hybrid share, whose ServerHello is the long one.
  check peer "$dir/peer.log" "curve 4588"
  # The frames on the peer's wire, which is where the reset this side owes a STOP_SENDING is
  # visible: the stream it arrived on has no reader left to tell. These lines carry a timestamp,
  # so they are looked for inside the line.
  on_wire "$dir/peer.log" "<- &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x2a, FinalSize: 5}"
  on_wire "$dir/peer.log" "<- &wire.StopSendingFrame{StreamID:4, ErrorCode:0x7}"
  on_wire "$dir/peer.log" "<- &wire.ResetStreamFrame{StreamID: 8, ErrorCode: 0x37, FinalSize: 4}"
}

run 1280-mtu 1280
run 1200-mtu 1200

if [ "$failures" -ne 0 ]; then
  echo "$failures checks failed"
  exit 1
fi
echo "all checks passed"
