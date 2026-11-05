// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The magic the accept key is derived with (RFC 6455 §1.3): the client's key, this, and
/// SHA-1 in between.
let magic : String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

///|
/// A WebSocket session over a connection. The exchange is the upgrade: `open` sends the
/// handshake, `response` is the 101, and from then on `read` yields whole messages and
/// `send` writes them.
pub struct Conn {
  sock : @tcp.Conn
  scheme : String
  // What the Host field says, and what SNI named.
  host : String
  // The path the upgrade asks for, from the request's target.
  mut target : String
  // The key this side offered, which the accept is checked against.
  key : String
  stream : Int32
  // Frame octets read and not yet decoded.
  mut held : Bytes
  reader : @frame.Reader
  mut opened : Bool
  mut closed : Bool
  mut code : Int32
  mut why : String
  // The 101, once the handshake has been answered.
  mut head : @spec.Response?
}

///|
/// Connect to `url` (`ws://` or `wss://`) and answer the contract with a session over it.
/// The upgrade itself happens on `open`, so the request's target and fields are the ones
/// that reach the server.
pub async fn connect(
  url : StringView,
  tls? : @tls.Client,
  now? : Int64,
) -> Conn {
  let parsed = @url.Url::decode(url) catch {
    _ => raise @spec.Refused::Unsupported("a URL this cannot read")
  }
  let secure = match parsed.scheme {
    Some("wss") => true
    Some("ws") => false
    Some(other) =>
      raise @spec.Refused::Unsupported("a scheme this cannot open: \{other}")
    None => raise @spec.Refused::Unsupported("a URL with no scheme")
  }
  guard parsed.host is Some(host) else {
    raise @spec.Refused::Unsupported("a URL with no host")
  }
  let port = parsed.port.unwrap_or(if secure { 443 } else { 80 })
  let sock = @tcp.dial(host, port~, tls?, now?)
  Conn::new(
    sock,
    if secure {
      "wss"
    } else {
      "ws"
    },
    if port == 80 || port == 443 {
      host
    } else {
      authority(host, port)
    },
  )
}

///|
fn authority(host : String, port : Int32) -> String {
  if host.contains(":") && !host.has_prefix("[") {
    "[\{host}]:\{port}"
  } else {
    "\{host}:\{port}"
  }
}

///|
/// A session over a connection that is already open to the server.
pub fn client(
  sock : @tcp.Conn,
  host~ : String,
  scheme~ : String = "ws",
) -> Conn {
  Conn::new(sock, scheme, host)
}

///|
fn Conn::new(sock : @tcp.Conn, scheme : String, host : String) -> Conn {
  {
    sock,
    scheme,
    host,
    target: "/",
    key: key_of(
      @env.rand(16).unwrap_or(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      ),
    ),
    stream: 1,
    held: b"",
    reader: @frame.Reader::new(),
    opened: false,
    closed: false,
    code: 0,
    why: "",
    head: None,
  }
}

///|
/// The `Sec-WebSocket-Key` of RFC 6455 §4.1: sixteen octets at random, in base64.
fn key_of(random : Bytes) -> String {
  @base64.encode(random)
}

///|
/// What the server must answer with: base64 of SHA-1 over the key and the magic.
fn accept_of(key : String) -> String {
  @base64.encode(@sha1.hash(@utf8.encode(key + magic)[:]))
}

///|
/// The close code and reason the peer gave, once the session has closed; 0 before.
pub fn Conn::close_code(self : Conn) -> Int32 {
  self.code
}

///|
/// The reason the peer gave with its close, empty when it gave none.
pub fn Conn::close_reason(self : Conn) -> String {
  self.why
}

///|
/// Whether the session has closed, from either side.
pub fn Conn::is_closed(self : Conn) -> Bool {
  self.closed
}

///|
/// Put one frame on the wire. A client's frames are masked (RFC 6455 §5.3), each with its
/// own key, which is why the mask is drawn here rather than kept in the connection.
async fn Conn::frame(
  self : Conn,
  opcode : @frame.Opcode,
  payload : Bytes,
) -> Unit raise @spec.Refused {
  let mask = @env.rand(4).unwrap_or(b"\x00\x00\x00\x00")
  let encoded = @frame.Frame::{ fin: true, opcode, payload, }.encode(mask~)
  self.put(encoded)
}

///|
/// A text message, which is what a caller with text wants: the contract's `send` writes
/// octets, and octets alone do not say whether they are text.
pub async fn Conn::send_text(
  self : Conn,
  text : String,
) -> Unit raise @spec.Refused {
  self.frame(@frame.Opcode::Text, @utf8.encode(text))
}

///|
/// A binary message.
pub async fn Conn::send_binary(
  self : Conn,
  bytes : Bytes,
) -> Unit raise @spec.Refused {
  self.frame(@frame.Opcode::Binary, bytes)
}

///|
/// The next message as the protocol states it, text kept as text; `None` once the session
/// has closed. A ping is answered before this returns, as §5.5.2 requires.
pub async fn Conn::next(self : Conn) -> @frame.Message? raise @spec.Refused {
  while true {
    if self.decoded() is Some(message) {
      return Some(message)
    }
    guard self.pump() else {
      self.closed = true
      return None
    }
  }
  None
}

///|
/// Answer a ping, echo a close, and hand back a message that completes one.
async fn Conn::decoded(self : Conn) -> @frame.Message? raise @spec.Refused {
  while self.held.length() > 0 {
    guard self.parse() is Some((frame, used)) else { return None }
    self.drop(used)
    let fed = Ok(self.reader.feed(frame)) catch { e => Err(e) }
    let step = match fed {
      Ok(step) => step
      Err(e) => {
        let (code, why) = refused(e)
        self.fail(code, why)
        raise @spec.Refused::Malformed(why)
      }
    }
    match step.reply {
      Some(reply) => self.out(reply)
      None => ()
    }
    match step.message {
      Some(@frame.Message::Close(status~, reason~)) => {
        self.code = status
        self.why = @utf8.decode_lossy(reason[:])
        self.closed = true
        return Some(@frame.Message::Close(status~, reason~))
      }
      Some(message) => return Some(message)
      None => ()
    }
  }
  None
}

///|
/// Put a frame the session owes the peer on the wire, unmasked only where it is the echo
/// of a close the peer already sent.
async fn Conn::out(
  self : Conn,
  frame : @frame.Frame,
) -> Unit raise @spec.Refused {
  let mask = @env.rand(4).unwrap_or(b"\x00\x00\x00\x00")
  self.put(frame.encode(mask~))
}

///|
/// The code a refusal from the codec asks the session to close with (RFC 6455 §7.4.1): 1002 for
/// a frame the protocol does not allow, 1007 for a payload that is not what its type says, and
/// 1009 for one over the size this side takes.
fn refused(e : Error) -> (Int32, String) {
  match e {
    @frame.Refused::Protocol(why) => (1002, why)
    @frame.Refused::Payload(why) => (1007, why)
    @frame.Refused::Exceeded(limit~, got~) =>
      (1009, "a message over \{limit} octets: \{got}")
    _ => (1002, "refused")
  }
}

///|
/// End the session with a code the peer can act on, which is what the protocol asks of a client
/// that has read something it will not accept. The failure is reported to the caller as well;
/// this is the peer's half of it.
async fn Conn::fail(
  self : Conn,
  code : Int32,
  why : String,
) -> Unit raise @spec.Refused {
  if self.closed {
    return
  }
  self.closed = true
  self.code = code
  self.why = why
  // Not caught: a session whose peer has gone cannot be told why, and the caller is about to
  // hear about the failure either way.
  self.frame(@frame.Opcode::Close, @frame.close(code, reason=why))
}

///|
/// The frame at the front of what is held, or `None` while it is not all there.
async fn Conn::parse(self : Conn) -> (@frame.Frame, Int32)? raise @spec.Refused {
  let decoded = Ok(@frame.decode(self.held[:], client=false)) catch {
    e => Err(e)
  }
  match decoded {
    Ok(frame) => frame
    Err(e) => {
      let (code, why) = refused(e)
      self.fail(code, why)
      raise @spec.Refused::Malformed(why)
    }
  }
}

///|
/// Give up `used` octets from the front of what is held.
fn Conn::drop(self : Conn, used : Int32) -> Unit {
  self.held = self.held[used:].to_owned()
}

///|
/// Put octets on the wire, a socket that fails stated as the contract states it.
async fn Conn::put(self : Conn, bytes : Bytes) -> Unit raise @spec.Refused {
  self.sock.write(bytes) catch {
    e => raise @spec.Refused::Broken("the socket failed: \{e}")
  }
}

///|
/// Read once from the socket onto what is held; `false` at the end of the peer's stream.
async fn Conn::pump(self : Conn) -> Bool raise @spec.Refused {
  let got = Ok(self.sock.read_some()) catch { e => Err(e) }
  match got {
    Ok(Some(bytes)) => {
      self.held = if self.held.length() == 0 {
        bytes
      } else {
        self.held + bytes
      }
      true
    }
    Ok(None) => false
    Err(e) => raise @spec.Refused::Broken("the socket failed: \{e}")
  }
}

///|
/// The reply head, read up to the blank line that ends it, as HTTP/1.1 states it. Anything
/// the peer sent after it is a frame and stays on the connection.
async fn Conn::head(self : Conn) -> @spec.Response {
  guard self.sock.read_until("\r\n\r\n") is Some(text) else {
    raise @spec.Refused::Closed
  }
  let response = try {
    let (head, _) = @http1.response(@utf8.encode(text + "\r\n\r\n")[:])
    head
  } catch {
    @http1.Partial =>
      raise @spec.Refused::Malformed("a head that stopped at the blank line")
    @http1.Malformed(why) => raise @spec.Refused::Malformed(why)
    @http1.Smuggled(why) => raise @spec.Refused::Malformed("smuggled: \{why}")
    @http1.Order(why) => raise @spec.Refused::Malformed("out of order: \{why}")
    @http1.Version(why) => raise @spec.Refused::Unsupported("version: \{why}")
    @http1.Coding(why) => raise @spec.Refused::Unsupported("coding: \{why}")
    @http1.Exceeded(limit~, got~) =>
      raise @spec.Refused::Malformed("a head over \{limit} octets: \{got}")
  }
  {
    status: response.status,
    fields: response.fields.map(h => {
      let (name, value) = h.ascii()
      @spec.Field::new(name, value)
    }),
  }
}

///|
/// The handshake of RFC 6455 §4.1: what the client sends, and the fields the caller adds.
fn Conn::handshake(self : Conn, request : @spec.Request) -> Bytes {
  let fields : Array[@header.Header] = [
    @header.Header::of("Host", self.host),
    @header.Header::of("Upgrade", "websocket"),
    @header.Header::of("Connection", "Upgrade"),
    @header.Header::of("Sec-WebSocket-Key", self.key),
    @header.Header::of("Sec-WebSocket-Version", "13"),
  ]
  for field in request.fields {
    let key = field.key()
    if key != "host" &&
      key != "upgrade" &&
      key != "connection" &&
      key != "sec-websocket-key" &&
      key != "sec-websocket-version" {
      fields.push(@header.Header::of(field.name, field.value))
    }
  }
  @http1.Request::of(
    "GET",
    self.target,
    fields~,
    version="HTTP/1.1",
    keep_alive=true,
  ).encode()
}

///|
pub impl @spec.Conn for Conn with fn open(self, request) {
  if self.opened {
    raise @spec.Refused::Unsupported("the session is open already")
  }
  self.target = if request.target == "" { "/" } else { request.target }
  self.put(self.handshake(request))
  // The reply is a head and nothing else; anything after it is a frame.
  let head = self.head()
  if head.status != 101 {
    raise @spec.Refused::Unsupported(
      "the server answered \{head.status}, not 101",
    )
  }
  let accept = @spec.find(head.fields, "sec-websocket-accept").unwrap_or("")
  if accept != accept_of(self.key) {
    raise @spec.Refused::Malformed(
      "a Sec-WebSocket-Accept that does not match the key",
    )
  }
  self.opened = true
  self.head = Some(head)
  match request.body {
    @spec.Body::Bytes(bytes) =>
      if bytes.length() > 0 {
        self.frame(@frame.Opcode::Binary, bytes)
      }
    _ => ()
  }
  { id: self.stream, }
}

///|
pub impl @spec.Conn for Conn with fn send(self, stream, bytes, end~) {
  if !self.opened || self.closed || stream.id != self.stream {
    raise @spec.Refused::Closed
  }
  if bytes.length() > 0 {
    self.frame(@frame.Opcode::Binary, bytes)
  }
  if end {
    self.frame(@frame.Opcode::Close, @frame.close(1000))
    self.closed = true
  }
}

///|
pub impl @spec.Conn for Conn with fn response(self, at) {
  let _ = at
  match self.head {
    Some(head) => head
    None => raise @spec.Refused::Closed
  }
}

///|
pub impl @spec.Conn for Conn with fn read(self, at) {
  let _ = at
  guard self.opened else { return None }
  if self.closed {
    return None
  }
  match self.next() {
    Some(@frame.Message::Text(text)) => Some(@utf8.encode(text))
    Some(@frame.Message::Binary(bytes)) => Some(bytes)
    Some(@frame.Message::Close(..)) => None
    None => None
  }
}

///|
pub impl @spec.Conn for Conn with fn trailers(self, at) {
  let _ = (self, at)
  []
}

///|
pub impl @spec.Conn for Conn with fn is_ready(self) {
  !self.opened || !self.closed
}

///|
pub impl @spec.Conn for Conn with fn kind(self) {
  let _ = self
  "ws"
}

///|
pub impl @spec.Conn for Conn with fn close(self) {
  if self.opened && !self.closed {
    self.frame(@frame.Opcode::Close, @frame.close(1000)) catch {
      _ => ()
    }
  }
  self.closed = true
  self.sock.shutdown() catch {
    _ => ()
  }
  self.sock.close()
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
