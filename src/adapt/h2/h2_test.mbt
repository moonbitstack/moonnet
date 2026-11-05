// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Take every event the codec has ready, discarding them: a server here answers in one
/// piece, so what it reads mid-exchange is only the flow-control bookkeeping.
fn settle(h2 : @http2.Conn) -> Unit {
  let mut reading = true
  while reading {
    let next = Ok(h2.next()) catch { _ => Err(()) }
    match next {
      Ok(@http2.Event::NeedData) => reading = false
      Ok(@http2.Event::Closed) => reading = false
      _ => ()
    }
  }
}

///|
/// Put `body` on `stream` as DATA, as much as the window allows at a time, waiting for the
/// peer's WINDOW_UPDATE when it does not: a body larger than the window is the case that
/// tells a flow-controlled sender from one that only works under 64 KiB.
async fn push(
  h2 : @http2.Conn,
  conn : @tcp.Conn,
  stream : Int32,
  body : Bytes,
) -> Unit {
  let mut off = 0
  while off < body.length() {
    let room = h2.window(stream)
    if room <= 0 {
      guard conn.read_some() is Some(bytes) else { return }
      h2.receive(bytes)
      settle(h2)
      continue
    }
    let take = if body.length() - off < room {
      body.length() - off
    } else {
      room
    }
    h2.data(stream, body[off:off + take], end=false)
    off += take
    let out = h2.take()
    if out.length() > 0 {
      conn.write(out)
    }
  }
  h2.end(stream)
  let out = h2.take()
  if out.length() > 0 {
    conn.write(out)
  }
}

///|
/// A server that answers every request with `status` and `body`, speaking HTTP/2 over the
/// connection it was given. The codec is the one `moonhttp` is conformance-tested on; what
/// these tests are about is the client adapter on the other end.
async fn answer_with(
  conn : @tcp.Conn,
  status~ : Int32 = 200,
  body~ : Bytes = b"ok",
  seen~ : Array[String] = [],
) -> Unit {
  let h2 = @http2.Conn::new(@http2.Role::Server)
  let hello = h2.take()
  if hello.length() > 0 {
    conn.write(hello)
  }
  while conn.read_some() is Some(bytes) {
    h2.receive(bytes)
    let mut reading = true
    while reading {
      let next = Ok(h2.next()) catch { _ => Err(()) }
      match next {
        Ok(@http2.Event::Request(stream~, fields~)) => {
          seen.push(
            fields
            .map(h => {
              let (name, value) = h.ascii()
              "\{name}: \{value}"
            })
            .join("|"),
          )
          h2.headers(
            stream,
            [@header.Header::of(":status", status.to_string())],
            end=false,
          )
          push(h2, conn, stream, body)
        }
        Ok(@http2.Event::NeedData) => reading = false
        Ok(@http2.Event::Closed) => reading = false
        _ => ()
      }
    }
    let out = h2.take()
    if out.length() > 0 {
      conn.write(out)
    }
  }
}

///|
/// Run `body` against a server that answers as `answer` does, on a port the system chose.
async fn with_h2(
  answer : async (@tcp.Conn) -> Unit,
  body : async (Int32) -> Unit,
) -> Unit {
  @async.with_timeout(120000, () => {
    @async.with_task_group(g => {
      let listener = @tcp.listen(port=0)
      let server = g.spawn(() => listener.serve((conn, _) => answer(conn)))
      body(listener.addr().port())
      server.cancel()
    })
  })
}

///|
async test "h2: a head and a body over the prior-knowledge preface" {
  with_h2(conn => answer_with(conn, body=b"hello over h2"), port => {
    let conn = @h2.client(
      @tcp.dial("127.0.0.1", port~),
      scheme="http",
      authority="127.0.0.1",
    )
    assert_eq(conn.kind(), "h2")
    let stream = conn.open(@spec.Request::new("GET", "/"))
    let response = conn.response(stream)
    assert_eq(response.status, 200)
    assert_eq(@spec.read_to_end(conn, stream), b"hello over h2")
    assert_eq(conn.trailers(stream), [])
    conn.close()
  })
}

///|
async test "h2: the same code that runs on h1 runs here" {
  with_h2(conn => answer_with(conn, status=201, body=b"created"), port => {
    let conn = @h2.client(
      @tcp.dial("127.0.0.1", port~),
      scheme="http",
      authority="127.0.0.1",
    )
    let (response, body) = @spec.call(
      conn,
      @spec.Request::new(
        "POST",
        "/things",
        fields=[@spec.Field::new("content-type", "text/plain")],
        body=@spec.Body::Bytes(b"payload"),
      ),
    )
    assert_eq((response.status, body), (201, b"created"))
    conn.close()
  })
}

///|
async test "h2: the request the peer reads carries the pseudo-fields, and one authority" {
  let seen : Array[String] = []
  let answer = async fn(conn : @tcp.Conn) { answer_with(conn, seen~) }
  with_h2(answer, port => {
    let conn = @h2.client(
      @tcp.dial("127.0.0.1", port~),
      scheme="http",
      authority="example.test",
    )
    let stream = conn.open(
      @spec.Request::new("GET", "/path?q=1", fields=[
        @spec.Field::new("Host", "elsewhere.test"),
      ]),
    )
    let _ = conn.response(stream)
    let _ = @spec.read_to_end(conn, stream)
    conn.close()
  })
  let head = seen[0]
  assert_true(head.contains(":method: GET"))
  assert_true(head.contains(":scheme: http"))
  assert_true(head.contains(":authority: example.test"))
  assert_true(head.contains(":path: /path?q=1"))
  assert_false(head.contains("elsewhere.test"))
}

///|
async test "h2: a body larger than the flow-control window arrives whole" {
  let size = 300 * 1024
  let body = Bytes::makei(size, i => (i % 251).to_byte())
  with_h2(conn => answer_with(conn, body~), port => {
    let conn = @h2.client(
      @tcp.dial("127.0.0.1", port~),
      scheme="http",
      authority="127.0.0.1",
    )
    let stream = conn.open(@spec.Request::new("GET", "/big"))
    let _ = conn.response(stream)
    // Read the body as it arrives, so the adapter hands the window back rather than
    // stalling after the first 64 KiB.
    let mut total = 0
    let got = @buffer.Buffer::Buffer(size_hint=size)
    while conn.read(stream) is Some(piece) {
      total += piece.length()
      got.write_bytes(piece)
    }
    assert_eq(total, size)
    assert_true(got.to_bytes() == body)
    conn.close()
  })
}

///|
async test "h2: a request body streamed in pieces reaches the peer" {
  let seen : Ref[String] = Ref("")
  let answer = async fn(conn : @tcp.Conn) {
    let h2 = @http2.Conn::new(@http2.Role::Server)
    let hello = h2.take()
    if hello.length() > 0 {
      conn.write(hello)
    }
    let held = @buffer.Buffer::Buffer(size_hint=64)
    let opened : Ref[Int32] = Ref(0)
    while conn.read_some() is Some(bytes) {
      h2.receive(bytes)
      let mut reading = true
      while reading {
        let next = Ok(h2.next()) catch { _ => Err(()) }
        match next {
          Ok(@http2.Event::Request(stream~, ..)) => {
            opened.val = stream
            h2.headers(
              stream,
              [@header.Header::of(":status", "200")],
              end=false,
            )
          }
          Ok(@http2.Event::Data(data~, ..)) => held.write_bytes(data)
          Ok(@http2.Event::End(..)) => {
            let body = held.to_bytes()
            seen.val = @utf8.decode_lossy(body[:])
            h2.data(opened.val, body, end=true)
            reading = false
          }
          Ok(@http2.Event::NeedData) => reading = false
          Ok(@http2.Event::Closed) => reading = false
          _ => ()
        }
      }
      let out = h2.take()
      if out.length() > 0 {
        conn.write(out)
      }
    }
  }
  with_h2(answer, port => {
    let conn = @h2.client(
      @tcp.dial("127.0.0.1", port~),
      scheme="http",
      authority="127.0.0.1",
    )
    let stream = conn.open(
      @spec.Request::new("POST", "/echo", body=@spec.Body::Streaming),
    )
    conn.send(stream, b"one,", end=false)
    conn.send(stream, b"two,", end=false)
    conn.send(stream, b"three", end=true)
    let _ = conn.response(stream)
    assert_eq(@spec.read_to_end(conn, stream), b"one,two,three")
    conn.close()
  })
  assert_eq(seen.val, "one,two,three")
}

///|
async test "h2: a reply with no body ends with its head" {
  with_h2(conn => answer_with(conn, status=204, body=b""), port => {
    let conn = @h2.client(
      @tcp.dial("127.0.0.1", port~),
      scheme="http",
      authority="127.0.0.1",
    )
    let stream = conn.open(@spec.Request::new("DELETE", "/things/1"))
    assert_eq(conn.response(stream).status, 204)
    assert_eq(conn.read(stream), None)
    assert_true(conn.is_ready())
    conn.close()
  })
}
