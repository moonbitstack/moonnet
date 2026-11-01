#!/usr/bin/env bash
# tlsfuzzer's TLS 1.3 scripts against the moontls server in tls-peer. Each listed script must
# pass in full; the ones left out, and the cases excluded with -e, test what moontls does not
# implement yet: session resumption, client certificates, certificate compression, the CCM
# suites, ML-KEM, brainpool, Ed448, RSASSA-PSS keys and TLS 1.2.
#
#     moon build --target native
#     TLSFUZZER=path/to/tlsfuzzer PYTHON=python-with-tlslite-ng bash scripts/tls_fuzz.sh [script...]
set -u
only=" $* "

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$here")
peer="$root/_build/native/debug/build/examples/tls-peer/tls-peer.exe"
test -x "$peer" || { echo "build the peer first: moon build --target native"; exit 2; }
fuzzer=$(cd "${TLSFUZZER:?set TLSFUZZER to a tlsfuzzer checkout}" && pwd)
python=${PYTHON:-python3}
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
cd "$work"

for k in "rsa rsa:2048" "ec ec -pkeyopt ec_paramgen_curve:P-256" "ed ed25519"; do
  set -- $k; name=$1; shift
  openssl req -x509 -newkey "$@" -nodes -keyout $name.key -out $name.pem -days 365 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" 2>/dev/null
done
all=x25519,p256,p384,p521,x448,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192
"$peer" server 4433 rsa.pem rsa.key http > /dev/null 2>&1 &
"$peer" server 4434 ec.pem ec.key http > /dev/null 2>&1 &
"$peer" server 4435 ed.pem ed.key http > /dev/null 2>&1 &
"$peer" server 4436 rsa.pem rsa.key > /dev/null 2>&1 &
"$peer" server 4437 rsa.pem rsa.key http groups=$all > /dev/null 2>&1 &
sleep 1

# script, port, extra arguments
cases=(
  "ccs 4433" "conversation 4433" "count-tickets 4433" "crfg-curves 4433"
  "dhe-shared-secret-padding 4437" "ecdhe-curves 4433" "empty-alert 4433" "ffdhe-groups 4437"
  "ffdhe-sanity 4437" "finished-plaintext 4433" "finished 4433" "hrr 4433" "invalid-ciphers 4433"
  "keyshare-omitted 4433" "keyupdate 4433" "large-number-of-extensions 4433" "legacy-version 4433"
  "lengths 4436" "minerva 4434" "multiple-ccs-messages 4433" "nociphers 4433"
  "no-unknown-groups 4433 --groups x25519,secp256r1,secp384r1,secp521r1,x448"
  "obsolete-curves 4433 --relaxed" "pkcs-signature 4433" "record-layer-limits 4433"
  "record-padding 4433" "rsa-signatures 4433" "serverhello-random 4437" "shuffled-extentions 4433"
  "signature-algorithms 4433" "unencrypted-alert 4433" "unrecognised-groups 4437"
  "zero-content-type 4433" "zero-length-data 4433"
  "0rtt-garbage 4433"
  "eddsa 4435"
)
excluded_0rtt="handshake with invalid 0-RTT and unknown version (downgrade to TLS 1.2)"
excluded_eddsa="ed448 only"

pass=0; fail=0
for entry in "${cases[@]}"; do
  set -- $entry; name=$1; port=$2; shift 2
  [ "$only" = "  " ] || [[ "$only" == *" $name "* ]] || continue
  extra=("$@")
  case "$name" in
    0rtt-garbage) extra+=(-e "$excluded_0rtt") ;;
    eddsa) extra+=(-e "$excluded_eddsa") ;;
  esac
  log="$work/$name.log"
  (cd "$fuzzer" && PYTHONPATH=. timeout 900 "$python" "scripts/test-tls13-$name.py" -h localhost -p "$port" \
    "${extra[@]}" > "$log" 2>&1)
  rc=$?
  totals=$(grep -E '^(PASS|FAIL): ' "$log" | tr '\n' ' ')
  if [ $rc -eq 0 ]; then
    pass=$((pass + 1)); printf 'PASS %-32s %s\n' "$name" "$totals"
  else
    fail=$((fail + 1)); printf 'FAIL %-32s %s\n' "$name" "$totals"
    grep -E '^(AssertionError|\w*Error): ' "$log" | sort | uniq -c | sort -rn | head -5
  fi
done

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
