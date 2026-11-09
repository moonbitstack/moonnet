#!/usr/bin/env bash
# TLS 1.2 and 1.3 interop between moontls (through moonnet) and OpenSSL: moontls as a
# client against `openssl s_server`, and as a server under `openssl s_client`,
# across certificate keys, suites, groups, HelloRetryRequest, record sizes and
# padding, KeyUpdate, tickets, certificate requests, ALPN and SNI. Each case
# states what should happen, a handshake or a clean refusal; the run fails on
# any case that does something else.
#
#     moon build --target native
#     bash scripts/tls_interop.sh
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$here")
peer="$root/_build/native/debug/build/examples/tls-peer/tls-peer.exe"
test -x "$peer" || { echo "build the peer first: moon build --target native"; exit 2; }
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
cd "$work"

# A root, an intermediate, and a leaf for each key type, all for localhost.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key \
  -out root.pem -days 3650 -subj "/CN=interop root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mid.key -out mid.csr \
  -subj "/CN=interop intermediate" 2>/dev/null
openssl x509 -req -in mid.csr -CA root.pem -CAkey root.key -CAcreateserial -out mid.pem -days 3650 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n") 2>/dev/null
leaf() { # name keygen-args... ; the leaf is issued by the intermediate
  local name=$1; shift
  openssl req -newkey "$@" -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA mid.pem -CAkey mid.key -CAcreateserial -out "$name.crt" -days 3650 \
    -extfile <(printf "subjectAltName=DNS:localhost,DNS:alt.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n") 2>/dev/null
  cat "$name.crt" mid.pem > "$name.pem"
}
issue() { # name ca extensions x509-args... ; an EC P-256 leaf issued by `ca` directly
  local name=$1 ca=$2 ext=$3; shift 3
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial -out "$name.crt" \
    -extfile <(printf "$ext") "$@" 2>/dev/null
}
leaf ec256 ec -pkeyopt ec_paramgen_curve:P-256
leaf ec384 ec -pkeyopt ec_paramgen_curve:P-384
leaf ec521 ec -pkeyopt ec_paramgen_curve:P-521
leaf rsa2048 rsa:2048
leaf rsa4096 rsa:4096
leaf rsapss rsa-pss -pkeyopt rsa_keygen_bits:2048
leaf ed25519 ed25519
leaf ed448 ed448
san='subjectAltName=DNS:localhost,DNS:alt.test,IP:127.0.0.1\n'
server="${san}extendedKeyUsage=serverAuth\n"
issue alt root "$server" -days 3650
issue expired mid "$server" -not_before 20200101000000Z -not_after 20210101000000Z
issue premature mid "$server" -not_before 20990101000000Z -not_after 20991231000000Z
issue clientonly mid "${san}extendedKeyUsage=clientAuth\n" -days 3650
issue leafca mid "${san}basicConstraints=critical,CA:TRUE\n" -days 3650
# A second root under the same name, so the stray leaf names a trusted issuer it was not signed by.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout stray.key \
  -out stray.pem -days 3650 -subj "/CN=interop intermediate" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
issue strayleaf stray "$server" -days 3650
head -c 1048576 /dev/urandom > big.bin

pass=0; fail=0
report() { # verdict name detail
  if [ "$1" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
  printf '%-4s %-44s %s\n' "$1" "$2" "$3"
}
port=24433
# Each probe is bounded: under WSL a connect to a closed port can hang rather than be refused.
wait_port() { for _ in $(seq 30); do timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# s_server reads one certificate from -cert; the intermediate goes through -cert_chain.
chain() { printf '%s
' -cert "$1.crt" -key "$1.key" -cert_chain mid.pem; }

# moontls as the client. want is `ok` or `refused`; check, when given, must appear in the output.
client_case() { # name want check server-args... -- client-args...
  local name=$1 want=$2 check=$3; shift 3
  local sargs=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
  shift
  cargs=("$@")
  port=$((port + 1))
  openssl s_server -accept $port "${sargs[@]}" > "s.$port.log" 2>&1 &
  local pid=$!
  wait_port $port || { report FAIL "$name" "s_server did not start: $(head -c 200 s.$port.log)"; kill $pid 2>/dev/null; return; }
  local out
  out=$(timeout 20 "$peer" client 127.0.0.1 $port root.pem sni=localhost "${cargs[@]}" 2>&1 | tail -1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local got=${out%% *}
  if [ "$got" = "$want" ] && { [ -z "$check" ] || [[ "$out" == *"$check"* ]]; }; then
    report PASS "$name" "$out"
  else
    report FAIL "$name" "want $want${check:+ with $check}, got: ${out:-nothing (timeout?)}"
  fi
}

www=(-www)
for key in ec256 ec384 rsa2048 rsa4096 ed25519; do
  for suite in aes128 aes256 chacha20; do
    client_case "client: $key $suite" ok "suite=$suite" $(chain $key) "${www[@]}" -- suites=$suite get=/
  done
done
client_case "client: P-521 key" ok "suite=" $(chain ec521) -www -- get=/
client_case "client: Ed448 key, scheme not offered" refused "handshake_failure" $(chain ed448) -www -- get=/
client_case "client: RSASSA-PSS key, scheme not offered" refused "handshake_failure" $(chain rsapss) -www -- get=/
for group in X25519 P-256 P-384 P-521 X448; do
  client_case "client: server group $group" ok "suite=" $(chain ec256) -groups $group -www -- get=/
done
client_case "client: HRR to P-384" ok "suite=" $(chain ec256) -groups P-384 -www -- get=/ groups=x25519,p384
client_case "client: no common group" refused "handshake_failure" $(chain ec256) -groups ffdhe2048 -www -- get=/
client_case "client: finite-field group when asked for" ok "suite=" $(chain ec256) -groups ffdhe2048 -www -- get=/ groups=ffdhe2048
client_case "client: records of 512 octets" ok "bytes=1048" $(chain ec256) -max_send_frag 512 -WWW -- get=/big.bin
client_case "client: records padded to 512" ok "bytes=1048" $(chain ec256) -record_padding 512 -WWW -- get=/big.bin
client_case "client: a megabyte" ok "bytes=1048" $(chain ec256) -WWW -- get=/big.bin
client_case "client: no tickets" ok "suite=" $(chain ec256) -num_tickets 0 -www -- get=/
client_case "client: five tickets" ok "suite=" $(chain ec256) -num_tickets 5 -www -- get=/
client_case "client: KeyUpdate before the request" ok "suite=" $(chain ec256) -www -- get=/ update
client_case "client: ALPN agreed" ok "alpn=http/1.1" $(chain ec256) -alpn h2,http/1.1 -www -- get=/ alpn=foo,http/1.1
client_case "client: ALPN not agreed" refused "no_application_protocol" $(chain ec256) -alpn h2 -www -- get=/ alpn=foo
client_case "client: SNI picks the second chain" ok "suite=" $(chain rsa2048) -servername alt.test -cert2 alt.crt -key2 alt.key -www -- get=/ sni=alt.test
client_case "client: SNI keeps the first chain" ok "suite=" $(chain rsa2048) -servername alt.test -cert2 alt.crt -key2 alt.key -www -- get=/ sni=localhost
client_case "client: leaf issued by the root" ok "suite=" -cert alt.crt -key alt.key -www -- get=/
client_case "client: certificate asked for, none sent" ok "suite=" $(chain ec256) -verify 1 -www -- get=/
client_case "client: certificate required, none sent" refused "" $(chain ec256) -Verify 1 -www -- get=/
client_case "client: echo through -rev" ok "first=gnip" $(chain ec256) -rev -- send=ping
client_case "client: intermediate not sent" refused "unknown_ca" -cert ec256.crt -key ec256.key -www -- get=/
client_case "client: root not trusted" refused "unknown_ca" -cert strayleaf.crt -key strayleaf.key -cert_chain stray.pem -www -- get=/
client_case "client: leaf not signed by its named issuer" refused "bad_certificate" -cert strayleaf.crt -key strayleaf.key -cert_chain mid.pem -www -- get=/
client_case "client: wrong host" refused "bad_certificate" $(chain ec256) -www -- get=/ sni=wrong.test
client_case "client: expired leaf" refused "certificate_expired" $(chain expired) -www -- get=/
client_case "client: leaf not yet valid" refused "certificate_expired" $(chain premature) -www -- get=/
client_case "client: leaf for client auth only" refused "bad_certificate" $(chain clientonly) -www -- get=/
client_case "client: leaf that is a CA" refused "bad_certificate" $(chain leafca) -www -- get=/
client_case "client: 1.3 only against a TLS 1.2 server" refused "protocol_version" $(chain ec256) -www -tls1_2 -- get=/ versions=13

# TLS 1.2. Every key type with every suite, the curves, ALPN, and the sizes that split records.
for key in ec256 ec384 ed25519; do
  for code in c02b c02c cca9; do
    client_case "client 1.2: $key $code" ok "suite=$code" $(chain $key) -tls1_2 -www -- suites12=$code get=/
  done
done
for key in rsa2048 rsa4096; do
  for code in c02f c030 cca8; do
    client_case "client 1.2: $key $code" ok "suite=$code" $(chain $key) -tls1_2 -www -- suites12=$code get=/
  done
done
client_case "client 1.2: P-521 key" ok "version=1.2" $(chain ec521) -tls1_2 -www -- get=/
for group in X25519 P-256 P-384 P-521 X448; do
  client_case "client 1.2: server curve $group" ok "version=1.2" $(chain ec256) -tls1_2 -groups $group -www -- get=/
done
client_case "client 1.2: no common curve" refused "handshake_failure" $(chain ec256) -tls1_2 -groups ffdhe2048 -www -- get=/
client_case "client 1.2: a megabyte" ok "bytes=1048" $(chain ec256) -tls1_2 -WWW -- get=/big.bin
client_case "client 1.2: records of 512 octets" ok "bytes=1048" $(chain ec256) -tls1_2 -max_send_frag 512 -WWW -- get=/big.bin
client_case "client 1.2: ALPN agreed" ok "alpn=http/1.1" $(chain ec256) -tls1_2 -alpn h2,http/1.1 -www -- get=/ alpn=foo,http/1.1
client_case "client 1.2: ALPN not agreed" refused "no_application_protocol" $(chain ec256) -tls1_2 -alpn h2 -www -- get=/ alpn=foo
client_case "client 1.2: no extended master secret" ok "version=1.2" $(chain ec256) -tls1_2 -no_ems -www -- get=/
client_case "client 1.2: certificate asked for, none sent" ok "version=1.2" $(chain ec256) -tls1_2 -verify 1 -www -- get=/
client_case "client 1.2: certificate required, none sent" refused "" $(chain ec256) -tls1_2 -Verify 1 -www -- get=/
client_case "client 1.2: wrong host" refused "bad_certificate" $(chain ec256) -tls1_2 -www -- get=/ sni=wrong.test
client_case "client 1.2: expired leaf" refused "certificate_expired" $(chain expired) -tls1_2 -www -- get=/
client_case "client 1.2: echo through -rev" ok "first=gnip" $(chain ec256) -tls1_2 -rev -- send=ping

# moontls as the server: s_client sends lines, the server echoes them. A line `update` makes
# the server send a KeyUpdate, a line `K` makes s_client send one; `lines` overrides the input.
server_case() { # name want-pattern key server-args... -- s_client-args...
  local name=$1 want=$2 key=$3; shift 3
  local sargs=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
  shift
  cargs=("$@")
  port=$((port + 1))
  "$peer" server $port $key.pem $key.key "${sargs[@]}" > "p.$port.log" 2>&1 &
  local pid=$!
  wait_port $port || { report FAIL "$name" "peer did not start: $(head -c 200 p.$port.log)"; kill $pid 2>/dev/null; return; }
  # The lines go in once s_client reports the handshake over, done or failed: a
  # private key that takes seconds to sign must not see its echo cut short.
  local out log=c.$port.log
  : > "$log"
  (for _ in $(seq 200); do grep -qE 'Verify return code|error|alert' "$log" && break; sleep 0.1; done
    for l in ${lines:-ping update pong}; do printf '%s\n' "$l"; sleep 0.5; done; sleep 1) |
    timeout 40 openssl s_client -connect 127.0.0.1:$port -CAfile root.pem -verify_return_error \
      $([[ " ${cargs[*]} " == *" -noservername "* ]] || echo -servername localhost) "${cargs[@]}" > "$log" 2>&1
  out=$(cat "$log")
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  if [[ "$out" =~ $want ]]; then
    report PASS "$name" "$(grep -m1 -oE 'Ciphersuite: [A-Z0-9_]+|Negotiated TLS1.3 group: [A-Za-z0-9-]+' <<< "$out" | tr '\n' ' ')"
  else
    report FAIL "$name" "$(grep -m3 -iE 'error|alert|Verify return code|Cipher is' <<< "$out" | tr '\n' ' ' | head -c 300) | peer: $(tail -2 p.$port.log | tr '\n' ' ')"
  fi
}

echoed='ping.*pong'
for key in ec256 ec384 rsa2048 ed25519; do
  for cs in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    server_case "server: $key $cs" "$echoed" $key -- -ciphersuites $cs
  done
done
server_case "server: OpenSSL's default groups (ML-KEM first)" "$echoed" ec256 --
for group in X25519 P-256 P-384 P-521 X448; do
  server_case "server: client group $group" "$echoed" ec256 -- -groups $group
done
server_case "server: HRR from ffdhe2048 to P-256" "$echoed" ec256 -- -groups ffdhe2048:P-256
server_case "server: no common group" "alert|handshake failure|error" ec256 -- -groups ffdhe2048
server_case "server: finite-field group when asked for" "$echoed" ec256 groups=ffdhe2048 -- -groups ffdhe2048
server_case "server: RSA-PSS SHA-512 asked for" "$echoed" rsa2048 -- -sigalgs rsa_pss_rsae_sha512
server_case "server: only Ed25519 accepted, ECDSA key" "alert|error" ec256 -- -sigalgs ed25519
server_case "server: ALPN" "ALPN protocol: http/1.1" ec256 alpn=h2,http/1.1 -- -alpn http/1.1
server_case "server: records padded to 512" "$echoed" ec256 -- -record_padding 512
server_case "server: records of 512 octets" "$echoed" ec256 -- -max_send_frag 512
lines="ping K pong" server_case "server: a KeyUpdate from the client" "$echoed" ec256 --
server_case "server: middlebox compatibility off" "$echoed" ec256 -- -no_middlebox
server_case "server: session saved for resumption" "$echoed" ec256 -- -sess_out "$work/sess.pem"
server_case "server: RSA 4096" "$echoed" rsa4096 --
server_case "server: P-521 key" "$echoed" ec521 --
server_case "server: no SNI" "$echoed" ec256 -- -noservername
server_case "server: Ed25519 key, Ed25519 only" "$echoed" ed25519 -- -sigalgs ed25519
server_case "server: 1.3 only, client offers TLS 1.2 only" "alert protocol version|wrong version|unsupported protocol" ec256 versions=13 -- -tls1_2

# TLS 1.2: every key type with every suite, the curves, and a client that leaves extensions out.
# No KeyUpdate here, since 1.2 has none. supported_groups speaks for the certificate too, so P-256
# stays on the client's list after the curve under test.
lines="ping pong"
for key in ec256 ec384 ed25519; do
  for cs in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
    server_case "server 1.2: $key $cs" "$echoed" $key -- -tls1_2 -cipher $cs
  done
done
for key in rsa2048 rsa4096; do
  for cs in ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305; do
    server_case "server 1.2: $key $cs" "$echoed" $key -- -tls1_2 -cipher $cs
  done
done
for group in X25519 P-384 P-521 X448; do
  server_case "server 1.2: client curve $group" "$echoed" ec256 -- -tls1_2 -groups $group:P-256
done
server_case "server 1.2: client curve P-256" "$echoed" ec256 -- -tls1_2 -groups P-256
server_case "server 1.2: certificate's curve not on the client's list" "alert|error" ec256 -- -tls1_2 -groups X25519
server_case "server 1.2: RSA PKCS#1 signature" "$echoed" rsa2048 -- -tls1_2 -sigalgs rsa_pkcs1_sha256
server_case "server 1.2: RSA-PSS signature" "$echoed" rsa2048 -- -tls1_2 -sigalgs rsa_pss_rsae_sha256
server_case "server 1.2: ALPN" "ALPN protocol: http/1.1" ec256 alpn=h2,http/1.1 -- -tls1_2 -alpn http/1.1
server_case "server 1.2: no extended master secret" "$echoed" ec256 -- -tls1_2 -no_ems
server_case "server 1.2: only 3DES on offer" "alert|error" ec256 suites12=all -- -tls1_2 -cipher 'DES-CBC3-SHA:@SECLEVEL=0'
server_case "server 1.2: extended master secret agreed" "Extended master secret: yes" ec256 -- -tls1_2
lines="ping R" server_case "server 1.2: renegotiation is declined" "no renegotiation" ec256 -- -tls1_2

# Every suite in the table by its code and OpenSSL's name, both ways, and CBC both ways round: with
# encrypt_then_mac, which OpenSSL takes by default, and with the MAC first.
cbc() { case $1 in *GCM*|*CCM*|*CHACHA*) return 1;; esac; }
while read -r code name key; do
  [ -n "$code" ] || continue
  list="$name:@SECLEVEL=0"
  client_case "client 1.2: $name" ok "suite=$code" $(chain $key) -tls1_2 -cipher "$list" -www -- suites12=$code get=/
  server_case "server 1.2: $name" "Cipher is $name.*$echoed" $key suites12=$code -- -tls1_2 -cipher "$list"
  if cbc "$name"; then
    client_case "client 1.2: $name, MAC first" ok "suite=$code" $(chain $key) -tls1_2 -no_etm -cipher "$list" -www -- suites12=$code get=/
    server_case "server 1.2: $name, MAC first" "Cipher is $name.*$echoed" $key suites12=$code -- -tls1_2 -no_etm -cipher "$list"
  fi
done <<'TABLE'
cca9 ECDHE-ECDSA-CHACHA20-POLY1305 ec256
cca8 ECDHE-RSA-CHACHA20-POLY1305 rsa2048
c02b ECDHE-ECDSA-AES128-GCM-SHA256 ec256
c02f ECDHE-RSA-AES128-GCM-SHA256 rsa2048
c02c ECDHE-ECDSA-AES256-GCM-SHA384 ec256
c030 ECDHE-RSA-AES256-GCM-SHA384 rsa2048
c0ac ECDHE-ECDSA-AES128-CCM ec256
c0ad ECDHE-ECDSA-AES256-CCM ec256
c0ae ECDHE-ECDSA-AES128-CCM8 ec256
c0af ECDHE-ECDSA-AES256-CCM8 ec256
ccaa DHE-RSA-CHACHA20-POLY1305 rsa2048
9e DHE-RSA-AES128-GCM-SHA256 rsa2048
9f DHE-RSA-AES256-GCM-SHA384 rsa2048
c09e DHE-RSA-AES128-CCM rsa2048
c09f DHE-RSA-AES256-CCM rsa2048
c0a2 DHE-RSA-AES128-CCM8 rsa2048
c0a3 DHE-RSA-AES256-CCM8 rsa2048
c023 ECDHE-ECDSA-AES128-SHA256 ec256
c027 ECDHE-RSA-AES128-SHA256 rsa2048
c024 ECDHE-ECDSA-AES256-SHA384 ec256
c028 ECDHE-RSA-AES256-SHA384 rsa2048
c009 ECDHE-ECDSA-AES128-SHA ec256
c013 ECDHE-RSA-AES128-SHA rsa2048
c00a ECDHE-ECDSA-AES256-SHA ec256
c014 ECDHE-RSA-AES256-SHA rsa2048
67 DHE-RSA-AES128-SHA256 rsa2048
6b DHE-RSA-AES256-SHA256 rsa2048
33 DHE-RSA-AES128-SHA rsa2048
39 DHE-RSA-AES256-SHA rsa2048
9c AES128-GCM-SHA256 rsa2048
9d AES256-GCM-SHA384 rsa2048
c09c AES128-CCM rsa2048
c09d AES256-CCM rsa2048
c0a0 AES128-CCM8 rsa2048
c0a1 AES256-CCM8 rsa2048
3c AES128-SHA256 rsa2048
3d AES256-SHA256 rsa2048
2f AES128-SHA rsa2048
35 AES256-SHA rsa2048
TABLE
client_case "client 1.2: a megabyte under CBC, MAC first" ok "bytes=1048" $(chain rsa2048) -tls1_2 -no_etm -cipher 'AES128-SHA:@SECLEVEL=0' -WWW -- suites12=2f get=/big.bin
client_case "client 1.2: a megabyte under CBC" ok "bytes=1048" $(chain rsa2048) -tls1_2 -cipher 'ECDHE-RSA-AES256-SHA384:@SECLEVEL=0' -WWW -- suites12=c028 get=/big.bin
client_case "client 1.2: a megabyte under CCM8" ok "bytes=1048" $(chain ec256) -tls1_2 -cipher 'ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0' -WWW -- suites12=c0ae get=/big.bin
openssl dhparam -out dh1024.pem 1024 2>/dev/null
client_case "client 1.2: a 1024-bit DHE prime" refused "insufficient_security" $(chain rsa2048) -tls1_2 -dhparam dh1024.pem -cipher 'DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0' -www -- suites12=9e get=/
unset lines
server_case "server: only ECDSA P-384 accepted, P-256 key" "alert|error" ec256 -- -sigalgs ecdsa_secp384r1_sha384

# Go and rustls load neither; moontls refuses an RSASSA-PSS key at configuration.
port=$((port + 1))
out=$(timeout 10 "$peer" server $port rsapss.pem rsapss.key 2>&1 | head -1)
if [[ "$out" == "bad server configuration"* ]]; then
  report PASS "server: RSASSA-PSS key refused" "$out"
else
  report FAIL "server: RSASSA-PSS key refused" "got: $out"
fi

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
