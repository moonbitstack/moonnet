// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn dialer(port : Int32) -> async (@pool.Key) -> @tcp.Conn {
  _key => @tcp.dial("127.0.0.1", port~)
}

///|
async test "pool: the connection is the same one, and the server opened it once" {
  let opened : Ref[Int32] = Ref(0)
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          opened.val = opened.val + 1
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        })
      })
      let port = listener.addr().port()
      let pool = @pool.Pool::new(dialer(port))
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let first = pool.get(key)
      first.write("a\n")
      assert_eq(first.read_until("\n"), Some("a"))
      pool.put(key, first)
      let again = pool.get(key)
      again.write("b\n")
      assert_eq(again.read_until("\n"), Some("b"))
      pool.put(key, again)
      assert_eq(opened.val, 1)
      assert_eq(pool.total(), 1)
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a peer that closed while idle is not handed out" {
  let opened : Ref[Int32] = Ref(0)
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      // This server answers one exchange and then hangs up, which is what a keep-alive
      // timeout looks like from the client's side.
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          opened.val = opened.val + 1
          let _ = conn.read_until("\n")
          conn.write("bye\n")
        })
      })
      let port = listener.addr().port()
      let pool = @pool.Pool::new(dialer(port))
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let first = pool.get(key)
      first.write("a\n")
      assert_eq(first.read_until("\n"), Some("bye"))
      pool.put(key, first)
      // The server is closing; the peek in `get` is what notices.
      @async.sleep(20)
      let again = pool.get(key)
      assert_eq(opened.val, 2)
      assert_eq(pool.total(), 1)
      again.close()
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: two keys never share a connection" {
  let opened : Ref[Int32] = Ref(0)
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          opened.val = opened.val + 1
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        })
      })
      let port = listener.addr().port()
      let pool = @pool.Pool::new(dialer(port))
      let plain = @pool.Key::new("127.0.0.1", port, alpn="")
      let h2 = @pool.Key::new("127.0.0.1", port, alpn="h2")
      let a = pool.get(plain)
      let b = pool.get(h2)
      a.write("a\n")
      b.write("b\n")
      assert_eq(a.read_until("\n"), Some("a"))
      assert_eq(b.read_until("\n"), Some("b"))
      pool.put(plain, a)
      pool.put(h2, b)
      assert_eq(opened.val, 2)
      assert_eq(pool.idle(plain), 1)
      assert_eq(pool.idle(h2), 1)
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a connection idle past its life is closed instead of reused" {
  let opened : Ref[Int32] = Ref(0)
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          opened.val = opened.val + 1
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        })
      })
      let port = listener.addr().port()
      let pool = @pool.Pool::new(dialer(port), config={
        ..@pool.defaults,
        idle: 5,
      })
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let first = pool.get(key)
      first.write("a\n")
      assert_eq(first.read_until("\n"), Some("a"))
      pool.put(key, first)
      @async.sleep(20)
      let again = pool.get(key)
      assert_eq(opened.val, 2)
      again.close()
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a full pool waits, and then says so" {
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        })
      })
      let port = listener.addr().port()
      let pool = @pool.Pool::new(dialer(port), config={
        ..@pool.defaults,
        max_total: 1,
        wait: 50,
      })
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let only = pool.get(key)
      let refused = try {
        let _ = pool.get(key)
        false
      } catch {
        @pool.Busy => true
        _ => abort("a full pool raised something other than Busy")
      }
      assert_true(refused)
      // Giving it back frees the slot, so the next caller gets it rather than waiting.
      pool.put(key, only)
      let again = pool.get(key)
      again.close()
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a key keeps no more than max_idle, and stops counting the rest" {
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        })
      })
      let port = listener.addr().port()
      let pool = @pool.Pool::new(dialer(port), config={
        ..@pool.defaults,
        max_idle: 2,
      })
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let held : Array[@tcp.Conn] = []
      for _ in 0..<4 {
        held.push(pool.get(key))
      }
      assert_eq(pool.total(), 4)
      for conn in held {
        pool.put(key, conn)
      }
      assert_eq(pool.idle(key), 2)
      assert_eq(pool.total(), 2)
      pool.close()
      server.cancel()
    })
  })
}
