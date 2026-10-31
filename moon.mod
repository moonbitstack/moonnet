name = "moonbitstack/moonnet"

version = "0.1.6"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonnet"

license = "Apache-2.0"

keywords = [ "http", "tls", "quic", "client", "server", "moonbit" ]

description = "Networking for MoonBit: connections, listeners and dialers over TCP, TLS and QUIC."

import {
  "moonbitstack/moontls@0.9.5",
  "moonbitstack/mooncred@0.6.7",
  "moonbitstack/mooncrypt@0.4.6",
  "moonbitlang/async@0.22.5",
}

source = "src"
