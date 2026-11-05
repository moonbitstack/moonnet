// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Run `body` against a server that answers each connection as `reply` does, on a port
/// the system chose. The listener is bound before `body` starts, so nothing races it, and
/// the whole run is bounded so a hang fails the test rather than the suite.
async fn with_server(
  reply : async (@tcp.Conn) -> Unit,
  body : async (Int32) -> Unit,
) -> Unit {
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => listener.serve((conn, _) => reply(conn)))
      body(listener.addr().port())
      server.cancel()
    })
  })
}

///|
/// The request head, as the peer sent it, with the blank line that ends it.
async fn head_of(conn : @tcp.Conn) -> String {
  match conn.read_until("\r\n\r\n") {
    Some(head) => head + "\r\n\r\n"
    None => abort("the peer stopped before the head was complete")
  }
}

///|
fn hex(size : StringView) -> Int32 {
  let mut n = 0
  for c in size {
    let digit = if c >= '0' && c <= '9' {
      c.to_int() - '0'.to_int()
    } else if c >= 'a' && c <= 'f' {
      c.to_int() - 'a'.to_int() + 10
    } else {
      abort("a chunk size that is not hexadecimal")
    }
    n = n * 16 + digit
  }
  n
}

///|
async test "h1: a head and a body of declared length" {
  let answer = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 11\r\n\r\nhello world"
  with_server(
    conn => {
      for _ in 0..<2 {
        let _ = head_of(conn)
        conn.write(answer)
      }
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let stream = conn.open(@spec.Request::new("GET", "/"))
      let response = conn.response(stream)
      assert_eq(response.status, 200)
      assert_eq(response.field("Content-Type"), Some("text/plain"))
      assert_eq(@spec.read_to_end(conn, stream), b"hello world")
      let (again, body) = @spec.call(conn, @spec.Request::new("GET", "/"))
      assert_eq((again.status, body), (200, b"hello world"))
      conn.close()
    },
  )
}

///|
async test "h1: a chunked body, with the trailers after the last chunk" {
  let answer = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" +
    "5\r\nhello\r\n6\r\n world\r\n0\r\nx-sum: 42\r\n\r\n"
  with_server(
    conn => {
      let _ = head_of(conn)
      conn.write(answer)
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let stream = conn.open(@spec.Request::new("GET", "/"))
      let response = conn.response(stream)
      assert_eq(response.field("transfer-encoding"), Some("chunked"))
      assert_eq(@spec.read_to_end(conn, stream), b"hello world")
      assert_eq(@spec.find(conn.trailers(stream), "x-sum"), Some("42"))
      conn.close()
    },
  )
}

///|
async test "h1: a body that runs to the close ends where the peer stops" {
  with_server(
    conn => {
      let _ = head_of(conn)
      conn.write("HTTP/1.1 200 OK\r\n\r\nall of it")
      conn.shutdown()
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let stream = conn.open(@spec.Request::new("GET", "/"))
      let _ = conn.response(stream)
      assert_eq(@spec.read_to_end(conn, stream), b"all of it")
      // The connection went with the body, so another exchange on it is refused rather
      // than written into a socket nobody reads.
      assert_false(conn.is_ready())
      let refused = try {
        let _ = conn.open(@spec.Request::new("GET", "/"))
        false
      } catch {
        @spec.Closed => true
        e => abort("a closed connection raised \{e}")
      }
      assert_true(refused)
      conn.close()
    },
  )
}

///|
async test "h1: a body shorter than its length is a truncation, not a short reply" {
  with_server(
    conn => {
      let _ = head_of(conn)
      conn.write("HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort")
      conn.shutdown()
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let stream = conn.open(@spec.Request::new("GET", "/"))
      let _ = conn.response(stream)
      let refused = try {
        let _ = @spec.read_to_end(conn, stream)
        false
      } catch {
        @spec.Closed => true
        e => abort("a truncated body raised \{e}")
      }
      assert_true(refused)
      conn.close()
    },
  )
}

///|
async test "h1: two exchanges on one connection, the second reusing it" {
  let seen : Array[String] = []
  let reply = async fn(conn : @tcp.Conn) {
    for _ in 0..<2 {
      seen.push(head_of(conn))
      conn.write("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
    }
  }
  with_server(reply, port => {
    let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
    for _ in 0..<2 {
      assert_true(conn.is_ready())
      let stream = conn.open(@spec.Request::new("GET", "/x"))
      let _ = conn.response(stream)
      assert_eq(@spec.read_to_end(conn, stream), b"ok")
    }
    assert_eq(seen.length(), 2)
    assert_true(conn.is_ready())
    conn.close()
  })
}

///|
async test "h1: a request body that is streamed goes out chunked as it is written" {
  let seen : Ref[Bytes] = Ref(b"")
  with_server(
    conn => {
      let head = head_of(conn)
      assert_true(head.contains("transfer-encoding: chunked"))
      let mut body = b""
      while true {
        guard conn.read_until("\r\n") is Some(line) else {
          abort("the body stopped early")
        }
        body = body + @utf8.encode(line) + b"\r\n"
        let size = hex(line)
        if size == 0 {
          // The trailer section ends at a blank line.
          let _ = conn.read_until("\r\n")
          body = body + b"\r\n"
          break
        }
        body = body + conn.read_exactly(size) + b"\r\n"
        // Each chunk's octets are followed by the break that ends its line.
        guard conn.read_until("\r\n") is Some("") else {
          abort("a chunk not terminated by a break")
        }
      }
      seen.val = body
      conn.write("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let stream = conn.open(
        @spec.Request::new("POST", "/upload", body=@spec.Body::Streaming),
      )
      conn.send(stream, b"abc", end=false)
      conn.send(stream, b"de", end=false)
      conn.send(stream, b"", end=true)
      let _ = conn.response(stream)
      assert_eq(@spec.read_to_end(conn, stream), b"")
      conn.close()
    },
  )
  assert_eq(seen.val, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
}

///|
async test "h1: an informational head is passed over for the final one" {
  with_server(
    conn => {
      let _ = head_of(conn)
      conn.write("HTTP/1.1 100 Continue\r\n\r\n")
      conn.write("HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n")
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let stream = conn.open(
        @spec.Request::new("POST", "/", body=@spec.Body::Bytes(b"x")),
      )
      assert_eq(conn.response(stream).status, 201)
      conn.close()
    },
  )
}

///|
async test "h1: a second exchange while one is in flight is refused" {
  with_server(
    conn => {
      let _ = head_of(conn)
      conn.write("HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nx")
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "127.0.0.1:\{port}")
      let _ = conn.open(@spec.Request::new("GET", "/"))
      assert_false(conn.is_ready())
      let refused = try {
        let _ = conn.open(@spec.Request::new("GET", "/"))
        false
      } catch {
        @spec.Unsupported(_) => true
        e => abort("a second exchange raised \{e}")
      }
      assert_true(refused)
      conn.close()
    },
  )
}

///|
async test "h1: the Host field is the authority, once" {
  let seen : Ref[String] = Ref("")
  with_server(
    conn => {
      seen.val = head_of(conn)
      conn.write("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
    },
    port => {
      let conn = @h1.client(@tcp.dial("127.0.0.1", port~), "example.test:8080")
      let stream = conn.open(
        @spec.Request::new("GET", "/", fields=[
          @spec.Field::new("Host", "elsewhere.test"),
        ]),
      )
      let _ = conn.response(stream)
      conn.close()
    },
  )
  let head = seen.val
  assert_true(head.contains("host: example.test:8080"))
  assert_false(head.contains("elsewhere.test"))
}
