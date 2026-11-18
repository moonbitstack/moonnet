name = "moonbitstack/moonnet"

version = "0.2.2"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonnet"

license = "Apache-2.0"

keywords = [
  "networking",
  "network",
  "socket",
  "udp",
  "tcp",
  "tls",
  "https",
  "http",
  "http1",
  "http2",
  "http3",
  "h2",
  "h3",
  "quic",
  "stream",
  "stream-reset",
  "reset-stream",
  "stop-sending",
  "websocket",
  "ws",
  "alpn",
  "connection",
  "connection-pool",
  "pool",
  "connection-reuse",
  "reuse",
  "keep-alive",
  "listener",
  "dialer",
  "client",
  "server",
  "proxy",
  "async",
  "rfc9110",
  "rfc9112",
  "rfc9113",
  "rfc9114",
  "rfc6455",
  "rfc7301",
  "rfc9000",
  "moonbit",
]

description = "Networking for MoonBit: connections, listeners and dialers over TCP, TLS and QUIC."

import {
  "moonbitstack/moontls@0.10.2",
  "moonbitstack/mooncred@0.8.1",
  "moonbitstack/mooncrypt@0.5.2",
  "moonbitstack/moonhttp@0.16.1",
  "moonbitstack/moonquic@0.4.1",
  "moonbitstack/moonbase@0.5.1",
  "moonbitstack/moonurl@0.3.1",
  "moonbitlang/async@0.22.5",
}

source = "src"
