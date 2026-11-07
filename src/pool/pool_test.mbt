// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A connection over a socket that carries one line per exchange: the request's target out,
/// one line back. These tests are about what the pool keeps and what it lets go of, so the
/// wire is the simplest thing that answers; the adapters have real traffic of their own.
struct Line {
  sock : @tcp.Conn
  mut next : Int32
  // The exchange in flight, and whether its one line has been handed out.
  mut stream : Int32
  mut owed : Bool
  mut finished : Bool
}

///|
fn Line::over(sock : @tcp.Conn) -> Line {
  { sock, next: 0, stream: 0, owed: false, finished: false, }
}

///|
impl @spec.Conn for Line with fn open(self, request) {
  guard !self.finished else { raise @spec.Refused::Closed }
  guard self.stream == 0 || !self.owed else {
    raise @spec.Refused::Unsupported("an exchange is still in flight")
  }
  self.sock.write(request.target + "\n")
  self.next += 1
  self.stream = self.next
  self.owed = true
  { id: self.stream, }
}

///|
impl @spec.Conn for Line with fn send(self, stream, bytes, end~) {
  let _ = (self, stream, bytes, end)
  raise @spec.Refused::Unsupported("a line carries no body")
}

///|
impl @spec.Conn for Line with fn response(self, stream) {
  guard stream.id == self.stream else {
    raise @spec.Refused::Unsupported("not the exchange in flight")
  }
  { status: 200, fields: [], }
}

///|
impl @spec.Conn for Line with fn read(self, stream) {
  guard self.owed && stream.id == self.stream else { return None }
  self.owed = false
  match self.sock.read_until("\n") {
    // What a peer sends that the protocol does not allow: refused, and the connection is
    // still idle as far as its own state goes.
    Some("bad") => raise @spec.Refused::Malformed("a line this cannot read")
    Some(line) => Some(@utf8.encode(line))
    None => {
      self.finished = true
      raise @spec.Refused::Closed
    }
  }
}

///|
impl @spec.Conn for Line with fn trailers(self, stream) {
  let _ = (self, stream)
  []
}

///|
impl @spec.Conn for Line with fn is_ready(self) {
  !self.owed && !self.finished
}

///|
impl @spec.Conn for Line with fn kind(self) {
  let _ = self
  "line"
}

///|
impl @spec.Conn for Line with fn close(self) {
  self.finished = true
  self.sock.close()
}

///|
/// One exchange over the contract, with the reply read as a line.
async fn exchange(conn : &@spec.Conn, text : String) -> String {
  let stream = conn.open(@spec.Request::new("GET", text))
  let _ = conn.response(stream)
  match conn.read(stream) {
    Some(line) => @utf8.decode_lossy(line[:])
    None => ""
  }
}

///|
/// A pool of line connections, one per key.
fn line_pool(config~ : @pool.Config = @pool.defaults) -> @pool.Pool {
  @pool.Pool::new(
    key => {
      let sock = @tcp.dial(key.host, port=key.port)
      @pool.Opened::new(sock, Line::over(sock))
    },
    config~,
  )
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
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let first = pool.get(key)
      assert_eq(exchange(first, "a"), "a")
      first.close()
      let again = pool.get(key)
      assert_eq(exchange(again, "b"), "b")
      again.close()
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
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let first = pool.get(key)
      assert_eq(exchange(first, "a"), "bye")
      first.close()
      // The server is closing; the peek in `get` is what notices.
      @async.sleep(20)
      let again = pool.get(key)
      // One exchange first: the server counts a connection in its handler, which may not have
      // run yet when the client side of the connect returns.
      assert_eq(exchange(again, "b"), "bye")
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
      let pool = line_pool()
      let plain = @pool.Key::new("127.0.0.1", port, alpn="")
      let h2 = @pool.Key::new("127.0.0.1", port, alpn="h2")
      let a = pool.get(plain)
      let b = pool.get(h2)
      assert_eq(exchange(a, "a"), "a")
      assert_eq(exchange(b, "b"), "b")
      a.close()
      b.close()
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
      let pool = line_pool(config={ ..@pool.defaults, idle: 5, })
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let first = pool.get(key)
      assert_eq(exchange(first, "a"), "a")
      first.close()
      @async.sleep(20)
      let again = pool.get(key)
      // The server counts a connection in its handler, so the exchange comes first.
      assert_eq(exchange(again, "b"), "b")
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
      let pool = line_pool(config={ ..@pool.defaults, max_total: 1, wait: 50, })
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
      only.close()
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
      let pool = line_pool(config={ ..@pool.defaults, max_idle: 2, })
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let held : Array[@pool.Handout] = []
      for _ in 0..<4 {
        held.push(pool.get(key))
      }
      assert_eq(pool.total(), 4)
      for conn in held {
        conn.close()
      }
      assert_eq(pool.idle(key), 2)
      assert_eq(pool.total(), 2)
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: closing is what returns a connection, and the pool counts it once" {
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
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let conn = pool.get(key)
      // Out on loan: against the total, and not idle.
      assert_eq(pool.idle(key), 0)
      assert_eq(pool.total(), 1)
      conn.close()
      assert_eq(pool.idle(key), 1)
      // A second close is not a second connection in the pool.
      conn.close()
      assert_eq(pool.idle(key), 1)
      assert_eq(pool.total(), 1)
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: an exchange that failed discards the connection" {
  let opened : Ref[Int32] = Ref(0)
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      // One reply is a line the connection refuses: that exchange fails while the
      // connection itself is still idle, which is the case a pool must not wave through.
      let server = g.spawn(() => {
        listener.serve((conn, _) => {
          opened.val = opened.val + 1
          while conn.read_until("\n") is Some(line) {
            conn.write(if line == "bad" { "bad\n" } else { line + "\n" })
          }
        })
      })
      let port = listener.addr().port()
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let conn = pool.get(key)
      let failed = try {
        let _ = exchange(conn, "bad")
        false
      } catch {
        @spec.Malformed(_) => true
        _ => false
      }
      assert_true(failed)
      // Nothing of that connection is worth keeping, though the connection under the loan
      // is idle by its own state: closing it frees the slot instead of returning it.
      conn.close()
      assert_eq(pool.idle(key), 0)
      assert_eq(pool.total(), 0)
      let again = pool.get(key)
      assert_eq(exchange(again, "b"), "b")
      assert_eq(opened.val, 2)
      again.close()
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a connection taken back mid-exchange is not handed out again" {
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
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let conn = pool.get(key)
      // The exchange is open and its reply unread: another caller must not be handed the
      // same connection with those octets still on it.
      let _ = conn.open(@spec.Request::new("GET", "a"))
      assert_false(conn.is_ready())
      conn.close()
      assert_eq(pool.idle(key), 0)
      assert_eq(pool.total(), 0)
      let again = pool.get(key)
      assert_eq(exchange(again, "b"), "b")
      assert_eq(opened.val, 2)
      again.close()
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a connection used after it went back says so" {
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
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let conn = pool.get(key)
      assert_eq(exchange(conn, "a"), "a")
      conn.close()
      let refused = try {
        let _ = exchange(conn, "b")
        false
      } catch {
        @spec.Closed => true
        _ => false
      }
      assert_true(refused)
      // The connection itself is in the pool and untouched by the late call.
      assert_eq(pool.idle(key), 1)
      pool.close()
      server.cancel()
    })
  })
}

///|
async test "pool: a connection out on loan when the pool closes is shut, not kept" {
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
      let pool = line_pool()
      let key = @pool.Key::new("127.0.0.1", port, alpn="")
      let conn = pool.get(key)
      assert_eq(exchange(conn, "a"), "a")
      pool.close()
      conn.close()
      assert_eq(pool.total(), 0)
      let refused = try {
        let _ = pool.get(key)
        false
      } catch {
        @pool.Closed => true
        _ => false
      }
      assert_true(refused)
      server.cancel()
    })
  })
}
