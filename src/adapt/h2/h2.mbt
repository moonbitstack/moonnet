// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An HTTP/2 client connection: many exchanges over one connection, each on its own
/// stream, framed as RFC 9113 says.
pub struct Conn {
  sock : @tcp.Conn
  h2 : @http2.Conn
  // What the `:authority` of every request says, and what the chain was checked against.
  authority : String
  scheme : String
  // Events read from the peer and not yet handed out, oldest first.
  events : Array[@http2.Event]
  // The fields that came after a body, by stream.
  tails : Map[Int32, Array[@spec.Field]]
  mut dead : Bool
}

///|
fn Conn::new(sock : @tcp.Conn, scheme : String, authority : String) -> Conn {
  {
    sock,
    h2: @http2.Conn::new(@http2.Role::Client),
    authority,
    scheme,
    events: [],
    tails: Map([]),
    dead: false,
  }
}

///|
/// A client over a connection that already carries the HTTP/2 preface of the client side.
pub async fn client(
  sock : @tcp.Conn,
  scheme~ : String = "https",
  authority~ : String,
) -> Conn {
  let conn = Conn::new(sock, scheme, authority)
  conn.flush()
  conn
}

///|
/// Connect to `host:port` and speak HTTP/2 over it, which is ALPN `h2` under TLS and the
/// preface alone in the clear (RFC 9113 §3.3, prior knowledge). A TLS connection that
/// settled on anything else is refused, since speaking HTTP/2 to a server that did not
/// agree is what the ALPN is there to prevent.
pub async fn connect(
  host : String,
  port~ : Int32,
  tls? : @tls.Client,
  now? : Int64,
  authority? : String,
) -> Conn {
  let sock = @tcp.dial(host, port~, tls?, now?)
  match sock.alpn() {
    Some("h2") => ()
    Some(name) => {
      sock.close()
      raise @spec.Refused::Unsupported("the server chose \{name}, not h2")
    }
    None => ()
  }
  let conn = Conn::new(
    sock,
    if tls is Some(_) {
      "https"
    } else {
      "http"
    },
    authority.unwrap_or(authority_of(host, port)),
  )
  conn.flush()
  conn
}

///|
fn authority_of(host : String, port : Int32) -> String {
  if port == 80 || port == 443 {
    host
  } else if host.contains(":") && !host.has_prefix("[") {
    "[\{host}]:\{port}"
  } else {
    "\{host}:\{port}"
  }
}

///|
/// Put what the connection has queued on the wire.
async fn Conn::flush(self : Conn) -> Unit {
  let out = self.h2.take()
  if out.length() > 0 {
    self.sock.write(out)
  }
}

///|
/// Take every event the codec has ready into the queue, up to the next `NeedData`.
fn Conn::drain(self : Conn) -> Unit raise @spec.Refused {
  while true {
    let next = Ok(self.h2.next()) catch {
      @http2.Refused::Incomplete => Err("an incomplete frame")
      @http2.Refused::FrameSizeError(why) => Err("frame size: \{why}")
      @http2.Refused::ProtocolError(why) => Err("protocol: \{why}")
      @http2.Refused::Connection(code~, why) =>
        Err("connection \{code}: \{why}")
      @http2.Refused::Order(why) => Err("out of order: \{why}")
    }
    match next {
      Err(why) => {
        self.dead = true
        raise @spec.Refused::Malformed(why)
      }
      Ok(@http2.Event::NeedData) => break
      Ok(@http2.Event::Closed) => {
        self.dead = true
        self.events.push(@http2.Event::Closed)
        break
      }
      Ok(event) => self.events.push(event)
    }
  }
}

///|
/// Read once from the socket and feed the codec; `false` at the end of the peer's stream.
async fn Conn::pump(self : Conn) -> Bool {
  guard self.sock.read_some() is Some(bytes) else {
    self.dead = true
    return false
  }
  self.h2.receive(bytes) catch {
    @http2.Refused::Incomplete =>
      raise @spec.Refused::Malformed("an incomplete frame")
    @http2.Refused::FrameSizeError(why) =>
      raise @spec.Refused::Malformed("frame size: \{why}")
    @http2.Refused::ProtocolError(why) =>
      raise @spec.Refused::Malformed("protocol: \{why}")
    @http2.Refused::Connection(code~, why) =>
      raise @spec.Refused::Malformed("connection \{code}: \{why}")
    @http2.Refused::Order(why) =>
      raise @spec.Refused::Malformed("out of order: \{why}")
  }
  self.drain()
  self.flush()
  true
}

///|
/// The first event in the queue that `want` accepts, taken out of it.
fn Conn::shift(self : Conn, want : (@http2.Event) -> Bool) -> @http2.Event? {
  for i, event in self.events {
    if want(event) {
      let _ = self.events.remove(i)
      return Some(event)
    }
  }
  None
}

///|
fn fields(head : Array[@header.Header]) -> Array[@spec.Field] {
  head.map(h => {
    let (name, value) = h.ascii()
    @spec.Field::new(name, value)
  })
}

///|
fn digit(code : UInt16) -> Int32 {
  let n = code.to_int()
  if n >= 48 && n <= 57 {
    n - 48
  } else {
    -1
  }
}

///|
/// The `:status` of a reply, which HTTP/2 carries as three digits (RFC 9113 §8.3.2).
fn status_of(head : Array[@header.Header]) -> Int32 raise @spec.Refused {
  guard @spec.find(fields(head), ":status") is Some(text) && text.length() == 3 else {
    raise @spec.Refused::Malformed("a reply without a three-digit :status")
  }
  let hundreds = digit(text[0])
  let tens = digit(text[1])
  let ones = digit(text[2])
  if hundreds < 0 || tens < 0 || ones < 0 {
    raise @spec.Refused::Malformed("a :status that is not a number")
  }
  hundreds * 100 + tens * 10 + ones
}

///|
/// The pseudo-fields of RFC 9113 §8.3, then the caller's own, with the ones the framing
/// owns dropped so that a request cannot name a second authority.
fn request_fields(
  request : @spec.Request,
  scheme : String,
  authority : String,
) -> Array[@header.Header] {
  let all : Array[@header.Header] = [
    @header.Header::of(":method", request.verb),
    @header.Header::of(":scheme", scheme),
    @header.Header::of(":authority", authority),
    @header.Header::of(":path", request.target),
  ]
  for field in request.fields {
    let key = field.key()
    if !key.has_prefix(":") && key != "host" && key != "connection" {
      all.push(@header.Header::of(key, field.value))
    }
  }
  all
}

///|
pub impl @spec.Conn for Conn with fn open(self, request) {
  if self.dead {
    raise @spec.Refused::Closed
  }
  let stream = self.h2.next_stream()
  let end = request.body is @spec.Body::Empty
  self.h2.headers(
    stream,
    request_fields(request, self.scheme, self.authority),
    end~,
  ) catch {
    e => raise beyond(e)
  }
  self.flush()
  let opened : @spec.Stream = { id: stream, }
  match request.body {
    @spec.Body::Bytes(bytes) =>
      if bytes.length() > 0 {
        self.body(opened, bytes)
      }
    _ => ()
  }
  opened
}

///|
/// A refusal from the codec, as the contract states it: a frame the peer should not have
/// sent is malformed traffic, and anything the codec will not do is unsupported here.
fn beyond(e : @http2.Refused) -> @spec.Refused {
  match e {
    @http2.Refused::Incomplete =>
      @spec.Refused::Malformed("an incomplete frame")
    @http2.Refused::FrameSizeError(why) =>
      @spec.Refused::Malformed("frame size: \{why}")
    @http2.Refused::ProtocolError(why) =>
      @spec.Refused::Malformed("protocol: \{why}")
    @http2.Refused::Connection(code~, why) =>
      @spec.Refused::Malformed("connection \{code}: \{why}")
    @http2.Refused::Order(why) => @spec.Refused::Unsupported(why)
  }
}

///|
/// Send `bytes` as DATA on `stream`, as much as the flow-control window allows at a time,
/// and wait for the peer to widen it when it does not (RFC 9113 §6.9).
async fn Conn::body(self : Conn, stream : @spec.Stream, bytes : Bytes) -> Unit {
  let mut off = 0
  while off < bytes.length() {
    let room = self.h2.window(stream.id)
    if room <= 0 {
      guard self.pump() else { raise @spec.Refused::Closed }
      continue
    }
    let take = if bytes.length() - off < room {
      bytes.length() - off
    } else {
      room
    }
    self.h2.data(stream.id, bytes[off:off + take], end=false) catch {
      e => raise beyond(e)
    }
    off += take
    self.flush()
  }
}

///|
pub impl @spec.Conn for Conn with fn send(self, stream, bytes, end~) {
  if self.dead {
    raise @spec.Refused::Closed
  }
  if bytes.length() > 0 {
    self.body(stream, bytes)
  }
  if end {
    self.h2.end(stream.id) catch {
      e => raise beyond(e)
    }
    self.flush()
  }
}

///|
pub impl @spec.Conn for Conn with fn response(self, at) {
  let want = at.id
  let mut reply : @spec.Response? = None
  while reply is None {
    let event = self.shift(event => {
      match event {
        @http2.Event::Response(stream~, ..) => stream == want
        @http2.Event::Reset(stream~, ..) => stream == want
        @http2.Event::Closed => true
        _ => false
      }
    })
    match event {
      Some(@http2.Event::Response(fields=head, ..)) =>
        reply = Some({ status: status_of(head), fields: fields(head), })
      Some(@http2.Event::Reset(code~, ..)) =>
        raise @spec.Refused::Broken("the peer reset the stream: \{code}")
      Some(@http2.Event::Closed) => raise @spec.Refused::Closed
      _ => if !self.pump() { raise @spec.Refused::Closed }
    }
  }
  match reply {
    Some(response) => response
    None => raise @spec.Refused::Closed
  }
}

///|
pub impl @spec.Conn for Conn with fn read(self, at) {
  let want = at.id
  if self.dead {
    return None
  }
  while true {
    let event = self.shift(event => {
      match event {
        @http2.Event::Data(stream~, ..) => stream == want
        @http2.Event::End(stream~) => stream == want
        @http2.Event::Trailers(stream~, ..) => stream == want
        @http2.Event::Reset(stream~, ..) => stream == want
        @http2.Event::Closed => true
        _ => false
      }
    })
    match event {
      Some(@http2.Event::Data(data~, ..)) => {
        // Hand the octets back to the peer's window, or it stops sending after one.
        self.h2.acknowledge(want, data.length()) catch {
          e => raise beyond(e)
        }
        self.flush()
        if data.length() > 0 {
          return Some(data)
        }
      }
      Some(@http2.Event::Trailers(fields=head, ..)) =>
        self.tails[want] = fields(head)
      Some(@http2.Event::End(..)) => return None
      Some(@http2.Event::Reset(code~, ..)) =>
        raise @spec.Refused::Broken("the peer reset the stream: \{code}")
      Some(@http2.Event::Closed) => raise @spec.Refused::Closed
      _ => if !self.pump() { return None }
    }
  }
  None
}

///|
pub impl @spec.Conn for Conn with fn trailers(self, at) {
  match self.tails.get(at.id) {
    Some(head) => head
    None => []
  }
}

///|
pub impl @spec.Conn for Conn with fn is_ready(self) {
  !self.dead
}

///|
pub impl @spec.Conn for Conn with fn kind(self) {
  let _ = self
  "h2"
}

///|
pub impl @spec.Conn for Conn with fn close(self) {
  if !self.dead {
    self.h2.goaway() catch {
      _ => ()
    }
    self.flush() catch {
      _ => ()
    }
  }
  self.sock.shutdown() catch {
    _ => ()
  }
  self.sock.close()
  self.dead = true
}

///|
pub extend Conn with @spec.Conn::{
  open,
  send,
  response,
  read,
  trailers,
  is_ready,
  kind,
  close,
}
