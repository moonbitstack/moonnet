// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A TLS echo server on the family's port and a client that talks to it, in one run:
///
///     moon run src/examples/tour --target native
///
/// The certificate is made on the spot and has no names in it, so the client pins it instead of
/// judging it against roots.
#coverage.skip
async fn main {
  let key = @ecdsa.PrivateKey::new(@env.rand(32).unwrap()[:])
  let cert = @x509.self_signed(
    key, b"\x01", "tour", "250101000000Z", "350101000000Z",
  )
  let server = @tls.Server::new([cert], Ec(key), alpn=["echo"])
  let pinned : @tls.Verify = Custom((chain, _) => {
    if chain[0] != cert {
      fail("not the certificate this tour made")
    }
  })
  let client = @tls.Client::new(
    @x509.Roots::new(),
    alpn=["echo"],
    verify=pinned,
  )
  @async.with_task_group(g => {
    let serving = g.spawn(() => {
      @tcp.serve(tls=server, (conn, peer) => {
        println("server: \{peer} speaks \{conn.alpn().unwrap_or("-")}")
        while conn.read_until("\n") is Some(line) {
          conn.write(line + "\n")
        }
      })
    })
    @async.sleep(100)
    let conn = @tcp.dial("127.0.0.1", port=@tcp.port, tls=client)
    defer conn.close()
    conn.write("hello over TLS 1.3\n")
    println("client: \{conn.read_until("\n").unwrap_or("-")}")
    conn.shutdown()
    serving.cancel()
  })
}
