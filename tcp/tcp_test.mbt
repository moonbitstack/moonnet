///|
fn server_config(alpn? : Array[String]) -> @tls.Server raise {
  @tls.Server::new(@x509.pems(cert), @x509.PrivateKey::pem(key), alpn?)
}

///|
fn client_config(
  roots~ : String = root,
  alpn? : Array[String],
) -> @tls.Client raise {
  @tls.Client::new(@x509.Roots::new(certs=@x509.pems(roots)[:]), alpn?)
}

///|
/// Echo each line back until the peer ends its stream.
async fn echo(conn : @tcp.Conn, _ : @socket.Addr) -> Unit {
  while conn.read_until("\n") is Some(line) {
    conn.write(line + "\n")
  }
}

///|
/// Run `body` against a server on `port`, then stop the server. The whole run is bounded, so a
/// hang fails the test instead of the suite.
async fn with_server(
  port : Int32,
  handler : async (@tcp.Conn, @socket.Addr) -> Unit,
  body : async () -> Unit,
  tls? : @tls.Server,
) -> Unit {
  @async.with_timeout(10000, () => {
    @async.with_task_group(g => {
      let server = g.spawn(() => @tcp.serve(handler, port~, tls?))
      @async.sleep(100)
      body()
      server.cancel()
    })
  })
}

///|
async test "tcp: a line goes out and comes back in the clear" {
  with_server(12101, echo, () => {
    let conn = @tcp.dial("127.0.0.1", port=12101)
    defer conn.close()
    conn.write("hello\n")
    assert_eq(conn.read_until("\n"), Some("hello"))
    assert_false(conn.is_tls())
    assert_eq(conn.alpn(), None)
  })
}

///|
async test "tcp: under TLS the same, with ALPN, SNI and the chain" {
  let seen : Ref[(String?, String?)] = Ref((None, None))
  let handler = async fn(conn : @tcp.Conn, peer : @socket.Addr) {
    seen.val = (conn.alpn(), conn.server_name())
    echo(conn, peer)
  }
  let tls = server_config(alpn=["h2", "http/1.1"])
  with_server(12102, handler, tls~, () => {
    let conn = @tcp.dial(
      "localhost",
      port=12102,
      tls=client_config(alpn=["http/1.1"]),
    )
    defer conn.close()
    conn.write("over tls\n")
    assert_eq(conn.read_until("\n"), Some("over tls"))
    assert_true(conn.is_tls())
    assert_eq(conn.alpn(), Some("http/1.1"))
    assert_eq(conn.peer().length(), 1)
    conn.shutdown()
  })
  assert_eq(seen.val, (Some("http/1.1"), Some("localhost")))
}

///|
async test "tcp: a large write crosses many records and arrives whole" {
  let big = Bytes::make(100000, b'z')
  let handler = async fn(conn : @tcp.Conn, _ : @socket.Addr) {
    conn.write(conn.read_exactly(100000))
  }
  with_server(12103, handler, tls=server_config(), () => {
    let conn = @tcp.dial("localhost", port=12103, tls=client_config())
    defer conn.close()
    conn.write(big)
    assert_eq(conn.read_exactly(100000), big)
  })
}

///|
async test "tcp: a sniff for a preface does not consume it, and does not wait on a short message" {
  let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  let verdicts : Array[(Bool, String)] = []
  let handler = async fn(conn : @tcp.Conn, _ : @socket.Addr) {
    let h2 = conn.starts_with(preface[:])
    let first = conn.read_until("\n").unwrap_or("")
    verdicts.push((h2, first))
    conn.write("ok\n")
  }
  with_server(12104, handler, () => {
    for message in ["PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "GET /\n"] {
      let conn = @tcp.dial("127.0.0.1", port=12104)
      defer conn.close()
      conn.write(message)
      assert_eq(conn.read_until("\n"), Some("ok"))
    }
  })
  assert_eq(verdicts, [(true, "PRI * HTTP/2.0\r"), (false, "GET /")])
}

///|
async test "tcp: two tasks writing at once put whole messages on the wire" {
  let handler = async fn(conn : @tcp.Conn, _ : @socket.Addr) {
    @async.with_task_group(g => {
      for name in ["a", "b"] {
        g.spawn_bg(() => {
          for i in 0..<40 {
            conn.write("\{name}\{i}:" + "x".repeat(40000) + "\n")
          }
        })
      }
    })
  }
  with_server(12105, handler, tls=server_config(), () => {
    let conn = @tcp.dial("localhost", port=12105, tls=client_config())
    defer conn.close()
    let counts = Map::from_array([("a", 0), ("b", 0)])
    for _ in 0..<80 {
      guard conn.read_until("\n") is Some(line) else {
        fail("stream ended early")
      }
      guard line.split_once(":") is Some((tag, body)) else { fail("torn line") }
      assert_eq(body, "x".repeat(40000))
      let name = tag[:1].to_owned()
      assert_eq(tag[1:].to_owned(), counts[name].to_string())
      counts[name] = counts[name] + 1
    }
  })
}

///|
async test "tcp: a client that does not trust the chain refuses the connection" {
  let reached = Ref(false)
  let handler = async fn(conn : @tcp.Conn, _ : @socket.Addr) {
    reached.val = true
    conn.shutdown()
  }
  with_server(12106, handler, tls=server_config(), () => {
    let refused = try
      @tcp.dial("localhost", port=12106, tls=client_config(roots=other_root))
    catch {
      _ => true
    } noraise {
      conn => {
        conn.close()
        false
      }
    }
    assert_true(refused)
  })
  assert_false(reached.val)
}
