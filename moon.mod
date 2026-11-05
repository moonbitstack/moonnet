name = "moonbitstack/moonnet"

version = "0.1.10"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonnet"

license = "Apache-2.0"

keywords = [
  "networking",
  "network",
  "socket",
  "tcp",
  "tls",
  "https",
  "connection",
  "listener",
  "dialer",
  "client",
  "server",
  "async",
  "http",
  "quic",
  "moonbit",
]

description = "Networking for MoonBit: connections, listeners and dialers over TCP, TLS and QUIC."

import {
  "moonbitstack/moontls@0.9.14",
  "moonbitstack/mooncred@0.6.9",
  "moonbitstack/mooncrypt@0.4.11",
  "moonbitlang/async@0.22.5",
}

source = "src"
