name = "moonbitstack/moonnet"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonnet"

license = "Apache-2.0"

keywords = [ "http", "tls", "quic", "client", "server", "moonbit" ]

description = "moonnet — the networking front door for MoonBit: one import that re-exports moonhttp, moontls and moonquic, and the connection layer that ties those formats to sockets."

import {
  "moonbitstack/moontls@0.9.2",
  "moonbitstack/mooncred@0.6.4",
  "moonbitstack/mooncrypt@0.4.2",
  "moonbitlang/async@0.22.5",
}
