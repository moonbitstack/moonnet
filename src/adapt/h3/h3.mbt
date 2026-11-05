// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An HTTP/3 client connection: one QUIC connection, a control stream carrying this side's
/// settings, and a bidirectional stream for every exchange (RFC 9114 §6).
pub struct Conn {
  quic : @udp.Quic
  scheme : String
  authority : String
  // The QPACK block of a reply is decoded with the static table only: this side offers a
  // dynamic table of no entries, so the peer may not refer to one (RFC 9204 §3.2.1).
  mut next_id : Int32
  // Where each exchange's stream is, and what has arrived on it but not been framed.
  streams : Map[Int32, UInt64]
  // Octets that arrived on an exchange's stream and are not framed yet, and the body octets
  // of the reply, which wait for a reader.
  held : Map[Int32, Bytes]
  body : Map[Int32, Bytes]
  heads : Map[Int32, @spec.Response]
  tails : Map[Int32, Array[@spec.Field]]
  ended : Map[Int32, Bool]
  mut dead : Bool
  // When the peer last said anything, and how long a silence is worth waiting through.
  mut quiet : Int64
  deadline : Int64
}

///|
/// Connect to `host:port` over QUIC and state this side's HTTP/3 settings. `tls` offers `h3`;
/// a handshake that settles on anything else is refused.
pub async fn connect(
  host : String,
  port~ : Int32,
  tls~ : @tls.Client,
  authority? : String,
) -> Conn {
  let quic = @udp.dial(host, port~, tls~)
  match quic.alpn() {
    Some("h3") => ()
    Some(name) => {
      quic.close()
      raise @spec.Refused::Unsupported("the server chose \{name}, not h3")
    }
    None => ()
  }
  let conn : Conn = {
    quic,
    scheme: "https",
    authority: authority.unwrap_or(authority_of(host, port)),
    next_id: 1,
    streams: Map([]),
    held: Map([]),
    body: Map([]),
    heads: Map([]),
    tails: Map([]),
    ended: Map([]),
    dead: false,
    quiet: @udp.now(),
    deadline: 30000L,
  }
  conn.settings()
  conn
}

///|
fn authority_of(host : String, port : Int32) -> String {
  if port == 443 {
    host
  } else if host.contains(":") && !host.has_prefix("[") {
    "[\{host}]:\{port}"
  } else {
    "\{host}:\{port}"
  }
}

///|
/// The control stream of RFC 9114 §6.2.1: this side's settings, with the dynamic table shut
/// so that no reply can refer to an entry this side does not have.
fn Conn::settings(self : Conn) -> Unit {
  let settings = @http3.Settings::new(0UL, 16384UL, 0UL)
  let stream = self.quic.open_uni()
  self.quic.write(stream, @http3.control(settings.pairs()), fin=false)
}

///|
/// One turn of the connection: send what is queued, take what arrived, and split the octets
/// of every exchange into frames.
async fn Conn::step(self : Conn) -> Unit {
  if self.dead {
    return
  }
  let arrived = self.quic.step(timeout=10) catch {
    _ => {
      self.dead = true
      false
    }
  }
  if arrived {
    self.quiet = @udp.now()
  } else if @udp.now() - self.quiet > self.deadline {
    // A peer that has said nothing for the whole deadline is not going to: without this a
    // client whose server never answers waits for ever.
    self.dead = true
  }
  for at, stream in self.streams {
    let arrived = self.quic.take(stream)
    if arrived.length() > 0 {
      let held = self.held.get(at).unwrap_or(b"")
      self.held[at] = if held.length() == 0 { arrived } else { held + arrived }
    }
  }
}

///|
fn fields(head : Array[@header.Header]) -> Array[@spec.Field] {
  head.map(h => {
    let (name, value) = h.ascii()
    @spec.Field::new(name, value)
  })
}

///|
fn status_of(head : Array[@header.Header]) -> Int32 raise @spec.Refused {
  guard @spec.find(fields(head), ":status") is Some(text) && text.length() == 3 else {
    raise @spec.Refused::Malformed("a reply without a three-digit :status")
  }
  let mut status = 0
  for i = 0; i < 3; i = i + 1 {
    let n = text[i].to_int() - 48
    if n < 0 || n > 9 {
      raise @spec.Refused::Malformed("a :status that is not a number")
    }
    status = status * 10 + n
  }
  status
}

///|
/// The pseudo-fields of RFC 9114 §4.3.1, then the caller's own. The framing owns the
/// authority, so a caller cannot name a second one.
fn request_head(
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
  let stream = self.quic.open_bi()
  let id = self.next_id
  self.next_id += 1
  self.streams[id] = stream
  let head = request_head(request, self.scheme, self.authority)
  match request.body {
    @spec.Body::Bytes(bytes) =>
      self.quic.write(stream, @http3.message(head, bytes), fin=true)
    @spec.Body::Empty =>
      self.quic.write(stream, @http3.message(head, b""), fin=true)
    @spec.Body::Streaming =>
      self.quic.write(stream, @http3.message(head, b""), fin=false)
  }
  let opened : @spec.Stream = { id, }
  opened
}

///|
pub impl @spec.Conn for Conn with fn send(self, at, bytes, end~) {
  guard self.streams.get(at.id) is Some(stream) else {
    raise @spec.Refused::Unsupported("not the exchange in flight")
  }
  if bytes.length() > 0 {
    self.quic.write(
      stream,
      @http3.Frame::encode(@http3.Frame::Data(bytes)),
      fin=false,
    )
  }
  if end {
    self.quic.write(stream, b"", fin=true)
  }
}

///|
/// The frames of `at` that the octets held for it hold whole, taken off the front.
fn Conn::frames(
  self : Conn,
  at : Int32,
) -> Array[@http3.Frame] raise @spec.Refused {
  let held = self.held.get(at).unwrap_or(b"")
  let frames : Array[@http3.Frame] = []
  let mut off = 0
  while off < held.length() {
    let parsed = @http3.decode(held[off:]) catch {
      @http3.Refused::Malformed(why) => raise @spec.Refused::Malformed(why)
    }
    guard parsed is Some((frame, used)) else { break }
    frames.push(frame)
    off += used
  }
  if off > 0 {
    self.held[at] = held[off:].to_owned()
  }
  frames
}

///|
pub impl @spec.Conn for Conn with fn response(self, at) {
  while true {
    if self.dead {
      raise @spec.Refused::Closed
    }
    for frame in self.frames(at.id) {
      match frame {
        @http3.Frame::Headers(block) => {
          let head = @qpack.decode(block) catch {
            @qpack.Refused::Malformed(why) =>
              raise @spec.Refused::Malformed(why)
            @qpack.Refused::Index(..) =>
              raise @spec.Refused::Malformed(
                "a QPACK index this table does not have",
              )
            @qpack.Refused::Exceeded(..) =>
              raise @spec.Refused::Malformed(
                "a QPACK block over the table this side has",
              )
          }
          if !self.heads.contains(at.id) {
            self.heads[at.id] = {
              status: status_of(head),
              fields: fields(head),
            }
          } else {
            // A second HEADERS is the trailers, which travel with the end of the stream.
            self.tails[at.id] = fields(head)
          }
        }
        @http3.Frame::Data(bytes) => self.bodies(at.id, bytes)
        @http3.Frame::GoAway(_) => raise @spec.Refused::Closed
        _ => ()
      }
    }
    if self.heads.contains(at.id) {
      break
    }
    // The head is looked for before "the stream ended" is believed, since a reply that
    // arrives whole ends the stream in the same flight as its head.
    if self.quic.ended(self.streams.get(at.id).unwrap_or(0UL)) {
      raise @spec.Refused::Closed
    }
    self.step()
  }
  match self.heads.get(at.id) {
    Some(head) => head
    None => raise @spec.Refused::Closed
  }
}

///|
/// Hold the octets of a DATA frame until a reader asks for them.
fn Conn::bodies(self : Conn, at : Int32, bytes : Bytes) -> Unit {
  self.body[at] = self.body.get(at).unwrap_or(b"") + bytes
}

///|
pub impl @spec.Conn for Conn with fn read(self, at) {
  while true {
    if !self.ended.get(at.id).unwrap_or(false) {
      for frame in self.frames(at.id) {
        match frame {
          @http3.Frame::Data(bytes) => self.bodies(at.id, bytes)
          @http3.Frame::Headers(block) => {
            let head = @qpack.decode(block) catch {
              @qpack.Refused::Malformed(why) =>
                raise @spec.Refused::Malformed(why)
              @qpack.Refused::Index(..) =>
                raise @spec.Refused::Malformed(
                  "a QPACK index this table does not have",
                )
              @qpack.Refused::Exceeded(..) =>
                raise @spec.Refused::Malformed(
                  "a QPACK block over the table this side has",
                )
            }
            self.tails[at.id] = fields(head)
          }
          _ => ()
        }
      }
      let ready = self.body.get(at.id).unwrap_or(b"")
      if ready.length() > 0 {
        self.body[at.id] = b""
        return Some(ready)
      }

      if self.quic.ended(self.streams.get(at.id).unwrap_or(0UL)) {
        self.ended[at.id] = true
      }
    }
    if self.ended.get(at.id).unwrap_or(false) {
      let ready = self.body.get(at.id).unwrap_or(b"")
      self.body[at.id] = b""
      return if ready.length() > 0 { Some(ready) } else { None }
    }
    if self.dead {
      raise @spec.Refused::Closed
    }
    self.step()
  }
  abort("unreachable: a body that neither yields nor ends")
}

///|
pub impl @spec.Conn for Conn with fn trailers(self, at) {
  self.tails.get(at.id).unwrap_or([])
}

///|
pub impl @spec.Conn for Conn with fn is_ready(self) {
  !self.dead
}

///|
pub impl @spec.Conn for Conn with fn kind(self) {
  let _ = self
  "h3"
}

///|
pub impl @spec.Conn for Conn with fn close(self) {
  self.dead = true
  self.quic.close()
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
