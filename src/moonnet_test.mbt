// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The front door is what it promises: `serve`, `listen` and `dial` are the tcp ones, the
/// contract's types are the spec ones, and `connect` reads a URL into a connection without
/// the caller assembling TLS by hand.
async test "moonnet: one import serves and connects" {
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @moonnet.listen(port=0)
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        })
      })
      let port = listener.addr().port()
      let opened = @moonnet.connect("http://127.0.0.1:\{port}/a/b?c=1")
      assert_eq(opened.alpn, "")
      assert_eq(opened.target, "/a/b?c=1")
      opened.conn.write("through the front door\n")
      assert_eq(opened.conn.read_until("\n"), Some("through the front door"))
      opened.conn.close()
      server.cancel()
    })
  })
}

///|
async test "moonnet: a scheme the front door does not speak is refused" {
  let refused = try {
    let _ = @moonnet.connect("ftp://example.com/")
    false
  } catch {
    @spec.Unsupported(_) => true
    e => abort("a scheme this cannot open raised \{e}")
  }
  assert_true(refused)
}
