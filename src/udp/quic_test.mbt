// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC connection at both ends: the client is this package's, and the server is the state
// machine the same dependency carries, driven on a datagram socket of its own. What the tests
// check is what the peer saw — the frames it was sent and the events they raised — rather than
// what this side believes it sent.

///|
fn server_config(alpn? : Array[String]) -> @tls.Server raise {
  @tls.Server::new(@x509.pems(cert), @x509.PrivateKey::pem(key), alpn?)
}

///|
fn client_config(alpn? : Array[String]) -> @tls.Client raise {
  @tls.Client::new(@x509.Roots::new(certs=@x509.pems(root)[:]), alpn?)
}

///|
fn entropy(n : Int32) -> Bytes {
  guard @env.rand(n) is Some(bytes) else { abort("no system entropy") }
  bytes
}

///|
/// What the server's connection reports: how each stream ended, and the octets that arrived.
struct Server {
  mut live : Bool
  resets : Array[(UInt64, UInt64)]
  stops : Array[(UInt64, UInt64)]
  data : Map[UInt64, Bytes]
  mut close : UInt64?
  mut session : @conn.Session[@socket.Addr]?
}

///|
fn Server::new() -> Server {
  {
    live: false,
    resets: [],
    stops: [],
    data: Map([]),
    close: None,
    session: None,
  }
}

///|
/// The server's own half of `stream`: abandon it with `code`.
fn Server::reset(self : Server, stream : UInt64, code : UInt64) -> Bool {
  match self.session {
    Some(session) => {
      session.reset(stream, code)
      true
    }
    None => false
  }
}

///|
/// Ask the client to stop sending on `stream`, with `code`.
fn Server::stop(self : Server, stream : UInt64, code : UInt64) -> Bool {
  match self.session {
    Some(session) => {
      session.stop(stream, code)
      true
    }
    None => false
  }
}

///|
/// Put `bytes` on `stream` from the server's side.
fn Server::write(self : Server, stream : UInt64, bytes : Bytes) -> Bool {
  match self.session {
    Some(session) => {
      session.queue_stream(stream, bytes)
      true
    }
    None => false
  }
}

///|
/// The octets the server has read on `stream` so far, emptied by the call.
fn Server::take(self : Server, stream : UInt64) -> Bytes {
  let held = self.data.get(stream).unwrap_or(b"")
  self.data[stream] = b""
  held
}

///|
/// One turn of the server: put what the endpoint has ready on the wire, note what its one
/// connection reports, and take one datagram in. The receive blocks, because a datagram lost to
/// a timeout leaves the handshake to a retransmission that a test should not have to wait for;
/// `stop` is set by the caller and followed by one datagram of its own, which is what brings
/// the task back out of the wait.
async fn serve(socket : @udp.Socket, seen : Server, stop : Ref[Bool]) -> Unit {
  let endpoint : @conn.Endpoint[@socket.Addr] = @conn.Endpoint::server(
    @conn.Config::default(),
    server_config(alpn=["moonnet-test"]) catch {
      _ => abort("the fixture certificate was refused")
    },
    rand=n => entropy(n),
  )
  while !stop.val {
    let at = @udp.now()
    while true {
      let next = endpoint.poll_out(at) catch { _ => None }
      match next {
        Some((datagram, to)) => socket.send(to, datagram) catch { _ => () }
        None => break
      }
    }
    for session in endpoint.take_busy() {
      seen.session = Some(session)
      for event in session.take_events() {
        match event {
          @conn.Event::Connected => seen.live = true
          @conn.Event::Readable(id) =>
            seen.data[id] = seen.data.get(id).unwrap_or(b"") + session.read(id)
          @conn.Event::Reset(id, code) => seen.resets.push((id, code))
          @conn.Event::Stopped(id, code) => seen.stops.push((id, code))
          // A CONNECTION_CLOSE, carrying the code it was sent with.
          @conn.Event::Closed(code) => seen.close = Some(code)
          _ => ()
        }
      }
    }
    let arrived = socket.recv() catch { _ => None }
    match arrived {
      Some((bytes, from)) => endpoint.recv(bytes, from, at) catch { _ => () }
      None => ()
    }
    endpoint.tick(at)
  }
}

///|
/// A client against a server beside it. The server is a task on the group, so every wait the
/// body takes is a turn the server gets too; the group is torn down after the body.
async fn with_quic(body : async (Int32, Server) -> Unit) -> Unit {
  @async.with_timeout(120000, () => {
    @async.with_task_group(g => {
      let socket = @udp.bind(host="127.0.0.1", port=0)
      let seen = Server::new()
      let stop : Ref[Bool] = Ref(false)
      let server = g.spawn(() => serve(socket, seen, stop))
      body(socket.addr().port(), seen) catch {
        e => abort("the client raised \{e}")
      }
      // The server is parked in a receive: one datagram of this side's own, then the flag it
      // reads on the way round, and the task is done rather than cancelled where it waits.
      stop.val = true
      socket.send(socket.addr(), b"\x00") catch {
        _ => ()
      }
      server.wait()
      socket.close()
    })
  })
}

///|
/// The client end, shaking hands with the server on `port`.
async fn connect(port : Int32) -> @udp.Quic {
  @udp.dial(
    "127.0.0.1",
    port~,
    tls=client_config(alpn=["moonnet-test"]) catch {
      _ => abort("the fixture certificate was refused")
    },
  )
}

///|
/// Turn the connection until `done` holds, and answer whether it does. Every turn yields to the
/// server, so what the peer owes arrives without the test counting datagrams.
async fn until(
  quic : @udp.Quic,
  done : () -> Bool,
  rounds~ : Int32 = 300,
) -> Bool {
  let mut left = rounds
  while left > 0 {
    if done() {
      return true
    }
    ignore(quic.step(timeout=20) catch { _ => false })
    left -= 1
  }
  done()
}

///|
async test "quic: a stream this side abandons reaches the peer as RESET_STREAM" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"hello")
    assert_true(until(quic, () => seen.take(0UL) == b"hello"))
    quic.reset(stream, code=42UL)
    assert_true(until(quic, () => seen.resets.length() > 0))
    // The code the peer was given. The final size is checked on its side: a stream reset at
    // fewer octets than it was sent is a FINAL_SIZE_ERROR there, which arrives here as a
    // close rather than as a reset.
    assert_eq(seen.resets, [(0UL, 42UL)])
    assert_eq(seen.close, None)
    quic.close()
  })
}

///|
async test "quic: asking the peer to stop reaches it as STOP_SENDING" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"one")
    // §19.5: a STOP_SENDING for a stream the peer has not seen is a STREAM_STATE_ERROR, and
    // control frames leave ahead of stream data, so the stream is in use before it is asked
    // to stop.
    assert_true(until(quic, () => seen.take(0UL) == b"one"))
    quic.stop(stream, code=7UL)
    assert_true(until(quic, () => seen.stops.length() > 0))
    assert_eq(seen.stops, [(0UL, 7UL)])
    assert_eq(seen.close, None)
    quic.close()
  })
}

///|
async test "quic: a reset from the peer ends the read with its code" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"request")
    assert_true(until(quic, () => seen.live))
    // The peer abandons its own half of the exchange. A stream it has said nothing on yet has
    // no record in its send loop, so it puts a byte there first; abandoning then drops that
    // byte and the code arrives with nothing before it.
    assert_true(seen.write(stream, b"x"))
    assert_true(seen.reset(stream, 99UL))
    assert_true(until(quic, () => quic.refused(stream) is Some(_)))
    assert_eq(quic.refused(stream), Some(@udp.QuicRefused::Reset(99UL)))
    assert_true(quic.ended(stream))
    let raised = try {
      ignore(quic.take(stream))
      None
    } catch {
      e => Some(e)
    }
    assert_eq(raised, Some(@udp.QuicRefused::Reset(99UL)))
    quic.close()
  })
}

///|
async test "quic: a stop from the peer refuses the write, and a reset goes back" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"first")
    assert_true(until(quic, () => seen.take(0UL) == b"first"))
    assert_true(seen.stop(stream, 55UL))
    assert_true(
      until(quic, () => {
        quic.refused(stream) is Some(@udp.QuicRefused::Stopped(55UL))
      }),
    )
    let raised = try {
      quic.write(stream, b"more")
      None
    } catch {
      e => Some(e)
    }
    assert_eq(raised, Some(@udp.QuicRefused::Stopped(55UL)))
    // §3.5: the answer to a STOP_SENDING is a RESET_STREAM carrying the same code, which the
    // peer sees as this side's half of the stream being reset.
    assert_true(until(quic, () => seen.resets.length() > 0))
    assert_eq(seen.resets, [(0UL, 55UL)])
    quic.close()
  })
}

///|
async test "quic: what arrived before a reset is readable, then the reset is raised" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"request")
    assert_true(until(quic, () => seen.live))
    assert_true(seen.write(stream, b"part of a reply"))
    // The octets come first and the reset behind them: a read hands over what did arrive and
    // raises only once there is nothing left to give (RFC 9000 §3.2).
    let got : Ref[Bytes] = Ref(b"")
    let collected = until(quic, () => {
      let more = quic.take(stream) catch { _ => b"" }
      got.val = got.val + more
      more.length() > 0
    })
    assert_true(collected)
    assert_eq(got.val, b"part of a reply")
    assert_true(seen.reset(stream, 1UL))
    assert_true(until(quic, () => quic.refused(stream) is Some(_)))
    assert_eq(seen.close, None)
    assert_eq(quic.refused(stream), Some(@udp.QuicRefused::Reset(1UL)))
    quic.close()
  })
}

///|
async test "quic: a stream this side abandoned takes no more writing" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"hello")
    quic.reset(stream, code=0UL)
    let raised = try {
      quic.write(stream, b"after")
      None
    } catch {
      e => Some(e)
    }
    assert_eq(raised, Some(@udp.QuicRefused::Reset(0UL)))
    // Abandoning twice sends one frame, not two, and the first code is the one the peer gets.
    quic.reset(stream, code=1UL)
    assert_true(until(quic, () => seen.resets.length() > 0))
    assert_eq(seen.resets, [(0UL, 0UL)])
    quic.close()
  })
}

///|
async test "quic: what the peer says of one stream says nothing of another" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let kept = quic.open_bi()
    let stopped = quic.open_bi()
    quic.write(kept, b"first")
    quic.write(stopped, b"second")
    assert_true(until(quic, () => seen.take(kept) == b"first"))
    assert_true(until(quic, () => seen.take(stopped) == b"second"))
    // The second stream is the one stopped, so a code kept anywhere but under its own number
    // lands on the first one and is what these assertions see.
    assert_true(seen.stop(stopped, 55UL))
    // The server is parked in a blocking receive, and the client has no ACK left to send: a
    // datagram from this side is what gives the server the turn it needs to put the frame on the
    // wire. Without one the wait below can outlast the frame and look like a lost message.
    quic.write(kept, b"third")
    assert_true(
      until(quic, () => {
        quic.refused(stopped) is Some(@udp.QuicRefused::Stopped(55UL))
      }),
    )
    assert_eq(quic.refused(kept), None)
    assert_true(until(quic, () => seen.take(kept) == b"third"))
    // A stop is about sending, so reading the stopped stream says nothing rather than raising.
    assert_eq(quic.take(stopped), b"")
    assert_eq(quic.refused(stopped), Some(@udp.QuicRefused::Stopped(55UL)))
    let raised = try {
      quic.write(stopped, b"more")
      None
    } catch {
      e => Some(e)
    }
    assert_eq(raised, Some(@udp.QuicRefused::Stopped(55UL)))
    quic.close()
  })
}

///|
async test "quic: a stream this side has only written on is not over" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"request", fin=true)
    assert_true(until(quic, () => seen.take(stream) == b"request"))
    // The codec has no record of a stream nothing has arrived on and calls it ended; a finish
    // on this side's half says nothing about the peer's.
    assert_false(quic.ended(stream))
    assert_eq(quic.refused(stream), None)
    assert_true(seen.write(stream, b"reply"))
    let got : Ref[Bytes] = Ref(b"")
    assert_true(
      until(quic, () => {
        got.val = got.val + (quic.take(stream) catch { _ => b"" })
        got.val.length() > 0
      }),
    )
    assert_eq(got.val, b"reply")
    assert_false(quic.ended(stream))
    quic.close()
  })
}

///|
async test "quic: a closed connection refuses every frame" {
  with_quic((port, seen) => {
    let quic = connect(port)
    let stream = quic.open_bi()
    quic.write(stream, b"hello")
    quic.close()
    let wrote = try {
      quic.write(stream, b"late")
      None
    } catch {
      e => Some(e)
    }
    assert_eq(wrote, Some(@udp.QuicRefused::Closed))
    let reset = try {
      quic.reset(stream)
      None
    } catch {
      e => Some(e)
    }
    assert_eq(reset, Some(@udp.QuicRefused::Closed))
    let stopped = try {
      quic.stop(stream)
      None
    } catch {
      e => Some(e)
    }
    assert_eq(stopped, Some(@udp.QuicRefused::Closed))
    // A turn of a closed connection sends nothing and reports nothing rather than raising.
    assert_false(quic.step(timeout=1) catch { _ => true })
    ignore(seen)
  })
}
