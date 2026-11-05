// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An HTTP/1.1 client connection: one exchange at a time, its head and body framed as
/// RFC 9112 says, over the tcp connection underneath.
pub struct Conn {
  sock : @tcp.Conn
  // What the Host field says. One authority per connection, because a connection that
  // serves two is a proxy, and this is not one.
  authority : String
  // Octets read from the socket and not yet framed into a message, from `at` on.
  mut held : Bytes
  mut at : Int32
  mut next_id : Int32
  // The exchange in flight, or the one that just ended.
  mut stream : Int32
  mut verb : String
  mut phase : Phase
  // How the reply's body is framed, once its head has been read.
  mut framing : @http1.Body
  // Octets of a body with a declared length that have yet to arrive.
  mut left : Int32
  mut streaming : Bool
  mut sent_end : Bool
  // Whether the connection may carry another exchange: what keep-alive asks of both ends.
  mut alive : Bool
  mut after : Array[@spec.Field]
}

///|
/// Where an exchange stands.
pub enum Phase {
  Idle
  // The request is out, and the reply's head has not been read.
  Reading
  // The head is read, and its body is being read.
  Body
  // The peer said it will not take another exchange, or the socket failed.
  Finished
}

///|
pub fn Conn::new(sock : @tcp.Conn, authority : String) -> Conn {
  {
    sock,
    authority,
    held: b"",
    at: 0,
    next_id: 1,
    stream: 0,
    verb: "GET",
    phase: Idle,
    framing: @http1.Body::Empty,
    left: 0,
    streaming: false,
    sent_end: false,
    alive: true,
    after: [],
  }
}

///|
/// A client over a connection that is already open to `authority`, the `host[:port]` the
/// Host field carries.
pub fn client(sock : @tcp.Conn, authority : String) -> Conn {
  Conn::new(sock, authority)
}

///|
/// Connect to `host:port` and speak HTTP/1.1 over it, under TLS when `tls` is given. The
/// host names the server for SNI and for checking its certificate; the ALPN the TLS
/// config offers decides what the connection settles on, and this refuses anything but
/// HTTP/1.1.
pub async fn connect(
  host : String,
  port~ : Int32,
  tls? : @tls.Client,
  now? : Int64,
) -> Conn {
  let sock = @tcp.dial(host, port~, tls?, now?)
  match sock.alpn() {
    Some(name) if name != "http/1.1" && name != "http/1.0" => {
      sock.close()
      raise @spec.Refused::Unsupported("the server chose \{name}, not HTTP/1.1")
    }
    _ => ()
  }
  Conn::new(sock, authority(host, port))
}

///|
/// What the Host field says: the port is left out when it is the one the scheme implies,
/// since a Host with a redundant port is a different origin to some servers.
fn authority(host : String, port : Int32) -> String {
  if port == 80 || port == 443 {
    host
  } else if host.contains(":") && !host.has_prefix("[") {
    "[\{host}]:\{port}"
  } else {
    "\{host}:\{port}"
  }
}

///|
/// What is held and not yet framed.
fn Conn::view(self : Conn) -> BytesView {
  self.held[self.at:]
}

///|
fn Conn::available(self : Conn) -> Int32 {
  self.held.length() - self.at
}

///|
/// Read more from the socket onto what is held; `false` at the end of the peer's stream.
async fn Conn::fill(self : Conn) -> Bool {
  guard self.sock.read_some() is Some(more) else { return false }
  let buffer = @buffer.Buffer::Buffer(
    size_hint=self.available() + more.length(),
  )
  buffer.write_bytesview(self.view())
  buffer.write_bytes(more)
  self.held = buffer.to_bytes()
  self.at = 0
  true
}

///|
/// The reply's head, read from what is held, or `None` while it is not all there.
fn Conn::parse_head(self : Conn) -> @http1.Response? raise @spec.Refused {
  let parsed = Some(@http1.response(self.view(), verb=self.verb)) catch {
    @http1.Partial => None
    @http1.Malformed(why) => raise @spec.Refused::Malformed(why)
    @http1.Smuggled(why) => raise @spec.Refused::Malformed("smuggled: \{why}")
    @http1.Order(why) => raise @spec.Refused::Malformed("out of order: \{why}")
    @http1.Version(why) => raise @spec.Refused::Unsupported("version: \{why}")
    @http1.Coding(why) => raise @spec.Refused::Unsupported("coding: \{why}")
    @http1.Exceeded(limit~, got~) =>
      raise @spec.Refused::Malformed("a head over \{limit} octets: \{got}")
  }
  match parsed {
    Some((response, used)) => {
      self.at += used
      Some(response)
    }
    None => None
  }
}

///|
/// One piece of a chunked body, or `None` while it is not all there.
fn Conn::parse_chunk(self : Conn) -> @http1.Chunk? raise @spec.Refused {
  let parsed = Some(@http1.chunked(self.view())) catch {
    @http1.Partial => None
    @http1.Malformed(why) => raise @spec.Refused::Malformed(why)
    @http1.Smuggled(why) => raise @spec.Refused::Malformed("smuggled: \{why}")
    @http1.Order(why) => raise @spec.Refused::Malformed("out of order: \{why}")
    @http1.Version(why) => raise @spec.Refused::Unsupported("version: \{why}")
    @http1.Coding(why) => raise @spec.Refused::Unsupported("coding: \{why}")
    @http1.Exceeded(limit~, got~) =>
      raise @spec.Refused::Malformed("a chunk over \{limit} octets: \{got}")
  }
  match parsed {
    Some(chunk) => {
      let used = match chunk {
        @http1.Piece(_, used) => used
        @http1.Done(_, used) => used
      }
      self.at += used
      Some(chunk)
    }
    None => None
  }
}

///|
/// The end of an exchange: the next one may start, unless keep-alive is off.
fn Conn::settle(self : Conn) -> Unit {
  self.phase = if self.alive { Idle } else { Finished }
}

///|
/// A connection that cannot go on: the peer broke the protocol or the socket failed.
fn Conn::break_off(self : Conn) -> Unit {
  self.alive = false
  self.phase = Finished
}

///|
/// HTTP fields as the contract shows them.
fn fields(head : Array[@header.Header]) -> Array[@spec.Field] {
  head.map(h => {
    let (name, value) = h.ascii()
    @spec.Field::new(name, value)
  })
}

///|
/// HTTP/1.1 has no field names of its own beyond what the request and the framing need;
/// a caller's Host is dropped in favour of the authority the connection was opened to.
fn request_fields(fields : Array[@spec.Field]) -> Array[@header.Header] {
  let all : Array[@header.Header] = []
  for field in fields {
    if field.key() != "host" {
      all.push(@header.Header::of(field.name, field.value))
    }
  }
  all
}

///|
pub impl @spec.Conn for Conn with fn open(self, request) {
  if self.phase is Reading || self.phase is Body {
    raise @spec.Refused::Unsupported(
      "an exchange is still in flight on this connection",
    )
  }
  guard self.phase is Idle else { raise @spec.Refused::Closed }
  let (framing, body) = match request.body {
    @spec.Body::Empty => (@http1.Body::Empty, b"")
    @spec.Body::Bytes(bytes) => (@http1.Body::Sized(bytes.length()), bytes)
    @spec.Body::Streaming => (@http1.Body::Chunked, b"")
  }
  let head = @http1.Request::of(
    request.verb,
    request.target,
    fields=request_fields(request.fields),
    body=framing,
    host=self.authority,
    keep_alive=self.alive,
  )
  self.sock.write(head.encode())
  if body.length() > 0 {
    self.sock.write(body)
  }
  self.verb = request.verb
  self.streaming = request.body is @spec.Body::Streaming
  self.sent_end = !self.streaming
  self.stream = self.next_id
  self.next_id += 1
  self.phase = Reading
  { id: self.stream, }
}

///|
pub impl @spec.Conn for Conn with fn send(self, stream, bytes, end~) {
  guard self.stream == stream.id &&
    self.streaming &&
    !self.sent_end &&
    self.phase is Reading else {
    raise @spec.Refused::Unsupported("not the body of the exchange in flight")
  }
  if bytes.length() > 0 {
    self.sock.write(@http1.chunk(bytes))
  }
  if end {
    self.sock.write(@http1.last_chunk())
    self.sent_end = true
  }
}

///|
/// The reply's head: the first one that is not informational, since a 1xx is not the
/// reply and the final head comes after it (RFC 9110 §15.2).
async fn Conn::head(self : Conn) -> @http1.Response {
  while true {
    let mut parsed = self.parse_head()
    while parsed is None {
      guard self.fill() else { raise @spec.Refused::Closed }
      parsed = self.parse_head()
    }
    guard parsed is Some(response) else { abort("a head that vanished") }
    if response.status < 100 || response.status >= 200 {
      return response
    }
  }
  abort("unreachable: a head that is neither informational nor final")
}

///|
pub impl @spec.Conn for Conn with fn response(self, stream) {
  guard self.stream == stream.id else {
    raise @spec.Refused::Unsupported("not the exchange in flight")
  }
  let response = self.head()
  self.framing = response.body
  self.left = match response.body {
    @http1.Body::Sized(n) => n
    _ => 0
  }
  // A body framed by the close of the connection ends the connection with it.
  self.alive = self.alive &&
    response.keep_alive &&
    !(response.body is @http1.Body::Closed)
  self.phase = Body
  if response.body is @http1.Body::Empty {
    self.settle()
  }
  { status: response.status, fields: fields(response.fields), }
}

///|
/// A body with a declared length: exactly that many octets, and a peer that closes
/// before them truncated the message.
async fn Conn::read_sized(self : Conn) -> Bytes? {
  if self.left <= 0 {
    self.settle()
    return None
  }
  while self.available() == 0 {
    guard self.fill() else {
      self.break_off()
      raise @spec.Refused::Closed
    }
  }
  let n = @cmp.minimum(self.left, self.available())
  let run = self.held[self.at:self.at + n].to_owned()
  self.at += n
  self.left -= n
  if self.left == 0 {
    self.settle()
  }
  Some(run)
}

///|
/// A body in chunks (RFC 9112 §7.1): each piece is a run of octets, and the last one is
/// followed by the trailers.
async fn Conn::read_chunked(self : Conn) -> Bytes? {
  while true {
    match self.parse_chunk() {
      None =>
        if !self.fill() {
          self.break_off()
          raise @spec.Refused::Closed
        }
      Some(@http1.Piece(body, _)) => if body.length() > 0 { return Some(body) }
      Some(@http1.Done(trailers, _)) => {
        self.after = fields(trailers)
        self.settle()
        return None
      }
    }
  }
  abort("unreachable: a chunked body that neither ends nor yields")
}

///|
/// A body that runs to the end of the connection: the reply is complete when the peer
/// closes, which is how a response without a length is framed (RFC 9112 §6.3).
async fn Conn::read_to_close(self : Conn) -> Bytes? {
  while true {
    if self.available() > 0 {
      let run = self.view().to_owned()
      self.at = self.held.length()
      return Some(run)
    }
    guard self.fill() else {
      self.settle()
      return None
    }
  }
  abort("unreachable: a body that does not end")
}

///|
pub impl @spec.Conn for Conn with fn read(self, stream) {
  guard self.stream == stream.id else {
    raise @spec.Refused::Unsupported("not the exchange in flight")
  }
  guard self.phase is Body else { return None }
  match self.framing {
    @http1.Body::Empty => None
    @http1.Body::Sized(_) => self.read_sized()
    @http1.Body::Chunked => self.read_chunked()
    @http1.Body::Closed => self.read_to_close()
  }
}

///|
pub impl @spec.Conn for Conn with fn trailers(self, stream) {
  let _ = stream
  self.after
}

///|
pub impl @spec.Conn for Conn with fn is_ready(self) {
  self.phase is Idle
}

///|
pub impl @spec.Conn for Conn with fn kind(self) {
  let _ = self
  "http/1.1"
}

///|
pub impl @spec.Conn for Conn with fn close(self) {
  self.sock.shutdown() catch {
    _ => ()
  }
  self.sock.close()
  self.phase = Finished
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
