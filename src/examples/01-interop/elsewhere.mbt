// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The sockets this client drives exist on the native and wasm backends, and wasm has no
/// command line: on js and wasm-gc there is nothing here to run.
fn main {
  println(
    "an interop client runs on the native backend; see the package manifest",
  )
}
