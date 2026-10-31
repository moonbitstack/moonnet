name = "moonbitstack/moonnet"

version = "0.1.5"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonnet"

license = "Apache-2.0"

keywords = [ "http", "tls", "quic", "client", "server", "moonbit" ]

description = "Networking for MoonBit: connections, listeners and dialers over TCP, TLS and QUIC."

import {
  "moonbitstack/moontls@0.9.4",
  "moonbitstack/mooncred@0.6.6",
  "moonbitstack/mooncrypt@0.4.5",
  "moonbitlang/async@0.22.5",
}

source = "src"
