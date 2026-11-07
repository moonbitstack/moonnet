// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The accept a server owes for `key`: base64 of SHA-1 over the key and the magic of
/// RFC 6455 §1.3. Computed here rather than shared with the adapter, so that the test does
/// not check the client against its own arithmetic.
fn accept(key : String) -> String {
  let magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  @base64.encode(@sha1.hash(@utf8.encode(key + magic)[:]))
}

///|
/// A server that upgrades the connection and echoes every message back, answering a ping
/// with a pong and a close with a close, as §5.5 asks.
async fn echo_server(
  conn : @tcp.Conn,
  pongs : Array[Bool],
  wrong_accept~ : Bool = false,
) -> Unit {
  guard conn.read_until("\r\n\r\n") is Some(head) else { return }
  let request = try {
    let (request, _) = @http1.request(@utf8.encode(head + "\r\n\r\n")[:])
    request
  } catch {
    _ => return
  }
  let key = match request.field("sec-websocket-key") {
    Some(key) => @utf8.decode_lossy(key[:])
    None => return
  }
  let accept = if wrong_accept {
    "AAAAAAAAAAAAAAAAAAAAAAAAAAA="
  } else {
    accept(key)
  }
  conn.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "upgrade: websocket\r\nconnection: Upgrade\r\n" +
    "sec-websocket-accept: \{accept}\r\n\r\n",
  )
  let reader = @frame.Reader::new()
  let mut held = b""
  let mut running = true
  while running {
    guard conn.read_some() is Some(bytes) else { break }
    held = if held.length() == 0 { bytes } else { held + bytes }
    let mut more = true
    while more {
      let parsed = @frame.decode(held[:], client=true) catch { _ => None }
      match parsed {
        None => more = false
        Some((frame, used)) => {
          held = held[used:].to_owned()
          let step = reader.feed(frame) catch {
            _ => {
              running = false
              break
            }
          }
          match step.reply {
            Some(reply) => {
              pongs.push(reply.opcode is @frame.Opcode::Pong)
              conn.write(reply.encode())
            }
            None => ()
          }
          match step.message {
            Some(@frame.Message::Text(text)) =>
              conn.write(
                @frame.Frame::{
                  fin: true,
                  opcode: @frame.Opcode::Text,
                  payload: @utf8.encode(text),
                }.encode(),
              )
            Some(@frame.Message::Binary(bytes)) =>
              conn.write(
                @frame.Frame::{
                  fin: true,
                  opcode: @frame.Opcode::Binary,
                  payload: bytes,
                }.encode(),
              )
            Some(@frame.Message::Close(status~, reason~)) => {
              conn.write(
                @frame.Frame::{
                  fin: true,
                  opcode: @frame.Opcode::Close,
                  payload: @frame.close(
                    status,
                    reason=@utf8.decode_lossy(reason[:]),
                  ),
                }.encode(),
              )
              running = false
            }
            None => ()
          }
        }
      }
    }
  }
}

///|
async fn with_ws(
  server : async (@tcp.Conn) -> Unit,
  body : async (Int32) -> Unit,
) -> Unit {
  @async.with_timeout(60000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let running = g.spawn(() => listener.serve((conn, _) => server(conn)))
      body(listener.addr().port())
      running.cancel()
    })
  })
}

///|
async test "ws: a text message goes out and comes back" {
  let pongs : Array[Bool] = []
  with_ws(conn => echo_server(conn, pongs), port => {
    let conn = @ws.client(
      @tcp.dial("127.0.0.1", port~),
      host="127.0.0.1:\{port}",
    )
    let stream = conn.open(@spec.Request::new("GET", "/chat"))
    let response = conn.response(stream)
    assert_eq(response.status, 101)
    assert_true(response.field("upgrade") is Some(_))
    conn.send_text("hello")
    assert_eq(conn.next(), Some(@frame.Message::Text("hello")))
    assert_eq(conn.kind(), "ws")
    conn.close()
  })
}

///|
async test "ws: the accept key the server answers with is checked" {
  let pongs : Array[Bool] = []
  with_ws(conn => echo_server(conn, pongs, wrong_accept=true), port => {
    let conn = @ws.client(
      @tcp.dial("127.0.0.1", port~),
      host="127.0.0.1:\{port}",
    )
    let refused = try {
      let _ = conn.open(@spec.Request::new("GET", "/chat"))
      false
    } catch {
      @spec.Malformed(_) => true
      e => abort("a handshake with a wrong accept raised \{e}")
    }
    assert_true(refused)
    conn.close()
  })
}

///|
async test "ws: a binary message through the contract's send" {
  let pongs : Array[Bool] = []
  with_ws(conn => echo_server(conn, pongs), port => {
    let conn = @ws.client(
      @tcp.dial("127.0.0.1", port~),
      host="127.0.0.1:\{port}",
    )
    let stream = conn.open(@spec.Request::new("GET", "/binary"))
    let _ = conn.response(stream)
    conn.send(stream, b"\x00\x01\xfe\xff", end=false)
    assert_eq(conn.read(stream), Some(b"\x00\x01\xfe\xff"))
    conn.close()
  })
}

///|
async fn opened_with_accept(conn : @tcp.Conn) -> Bool {
  guard conn.read_until("\r\n\r\n") is Some(head) else { return false }
  let request = try {
    let (request, _) = @http1.request(@utf8.encode(head + "\r\n\r\n")[:])
    request
  } catch {
    _ => return false
  }
  guard request.field("sec-websocket-key") is Some(key) else { return false }
  let accept = accept(@utf8.decode_lossy(key[:]))
  conn.write(
    "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n" +
    "sec-websocket-accept: \{accept}\r\n\r\n",
  )
  true
}

///|
async test "ws: a ping is answered before any message reaches the caller" {
  let pongs : Ref[Int32] = Ref(0)
  let server = async fn(conn : @tcp.Conn) {
    guard opened_with_accept(conn) else { return }
    conn.write(
      @frame.Frame::{
        fin: true,
        opcode: @frame.Opcode::Ping,
        payload: b"are you there",
      }.encode(),
    )
    // The message behind the ping: what the read returns once it has answered.
    conn.write(
      @frame.Frame::{
        fin: true,
        opcode: @frame.Opcode::Text,
        payload: b"after",
      }.encode(),
    )
    let mut held = b""
    while conn.read_some() is Some(bytes) {
      held = held + bytes
      let mut more = true
      while more {
        let parsed = @frame.decode(held[:], client=true) catch { _ => None }
        match parsed {
          None => more = false
          Some((frame, used)) => {
            held = held[used:].to_owned()
            if frame.opcode is @frame.Opcode::Pong {
              pongs.val = pongs.val + 1
            }
          }
        }
      }
    }
  }
  with_ws(server, port => {
    let conn = @ws.client(@tcp.dial("127.0.0.1", port~), host="127.0.0.1")
    let stream = conn.open(@spec.Request::new("GET", "/chat"))
    let _ = conn.response(stream)
    // The ping is answered on the way to the message behind it, and never reaches the
    // caller: what comes back is the text.
    assert_eq(conn.next(), Some(@frame.Message::Text("after")))
    conn.close()
  })
  assert_true(pongs.val >= 1)
}

///|
async test "ws: a close from the peer ends the read and keeps its code" {
  let server = async fn(conn : @tcp.Conn) {
    guard opened_with_accept(conn) else { return }
    conn.write(
      @frame.Frame::{
        fin: true,
        opcode: @frame.Opcode::Close,
        payload: @frame.close(1001, reason="going away"),
      }.encode(),
    )
    let _ = conn.read_some()
  }
  with_ws(server, port => {
    let conn = @ws.client(@tcp.dial("127.0.0.1", port~), host="127.0.0.1")
    let stream = conn.open(@spec.Request::new("GET", "/chat"))
    let _ = conn.response(stream)
    assert_eq(conn.read(stream), None)
    assert_eq(conn.close_code(), 1001)
    assert_eq(conn.close_reason(), "going away")
    assert_false(conn.is_ready())
    conn.close()
  })
}

///|
async test "ws: a message that is not valid UTF-8 closes with 1007" {
  let sent : Ref[Int32] = Ref(0)
  let server = async fn(conn : @tcp.Conn) {
    guard opened_with_accept(conn) else { return }
    conn.write(
      @frame.Frame::{
        fin: true,
        opcode: @frame.Opcode::Text,
        payload: b"\xff\xfe",
      }.encode(),
    )
    // The reply this test is about is one close frame, so its code is read off the octets
    // rather than through the codec: a masked frame, key at 2, code at 6, big-endian.
    let mut held = b""
    while conn.read_some() is Some(bytes) {
      held = held + bytes
      if held.length() >= 8 && (held[0].to_int() & 0xff) == 0x88 {
        let hi = (held[6].to_int() ^ held[2].to_int()) & 0xff
        let lo = (held[7].to_int() ^ held[3].to_int()) & 0xff
        sent.val = hi * 256 + lo
        break
      }
    }
    let _ = conn.read_some()
  }
  with_ws(server, port => {
    let conn = @ws.client(@tcp.dial("127.0.0.1", port~), host="127.0.0.1")
    let stream = conn.open(@spec.Request::new("GET", "/chat"))
    let _ = conn.response(stream)
    let refused = Ok(conn.next()) catch { e => Err(e) }
    match refused {
      Err(@spec.Refused::Malformed(why)) => assert_true(why.contains("UTF-8"))
      _ => abort("a text message that is not UTF-8 was not refused")
    }
    // The server reads the close on its own task; give it the turn it needs before the verdict.
    @async.sleep(100)
    assert_eq(sent.val, 1007)
    conn.close()
  })
}

///|
/// A WebSocket session from the pool carries its messages, and the pool drops it on the way
/// back: a session's one exchange is the upgrade, so there is nothing to hand on.
async test "ws: a session from the pool carries its message and is not handed out again" {
  let pongs : Array[Bool] = []
  let opened : Ref[Int32] = Ref(0)
  with_ws(
    conn => {
      opened.val = opened.val + 1
      echo_server(conn, pongs)
    },
    port => {
      let pool = @pool.Pool::new(key => {
        let sock = @tcp.dial(key.host, port=key.port)
        @pool.Opened::new(sock, @ws.client(sock, host="127.0.0.1:\{port}"))
      })
      let key = @pool.Key::new("127.0.0.1", port, alpn="http/1.1")
      let session = pool.get(key)
      assert_eq(session.kind(), "ws")
      let stream = session.open(@spec.Request::new("GET", "/chat"))
      assert_eq(session.response(stream).status, 101)
      session.send(stream, @utf8.encode("hello"), end=false)
      assert_eq(session.read(stream), Some(@utf8.encode("hello")))
      session.close()
      assert_eq(pool.idle(key), 0)
      assert_eq(pool.total(), 0)
      // A second caller is not given the finished session: it gets one of its own.
      let next = pool.get(key)
      let stream = next.open(@spec.Request::new("GET", "/chat"))
      assert_eq(next.response(stream).status, 101)
      assert_eq(opened.val, 2)
      next.close()
      pool.close()
    },
  )
}
