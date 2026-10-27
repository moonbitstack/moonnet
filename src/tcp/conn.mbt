// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One TCP connection, in the clear or under TLS 1.3. It reads and writes through `@io.Reader` and
/// `@io.Writer` either way, so a protocol driver serves both with the same code.
///
/// One task may read while another writes. Writes are serialised, so two tasks writing at once
/// put whole messages on the wire, one after the other, and TLS records stay in sequence.
struct Conn {
  sock : @socket.Tcp
  tls : @tls.Conn?
  buf : @io.ReaderBuffer
  lock : @async.Mutex
  mut ahead : Bytes
  mut at : Int32
}

///|
/// How much is read from the socket at once: a whole TLS record, 2^14 octets and the 256 of
/// expansion RFC 8446 §5.2 allows. The async default reads a kibibyte at a time.
let chunk : Int32 = 16384 + 256

///|
fn Conn::new(sock : @socket.Tcp, tls : @tls.Conn?) -> Conn {
  {
    sock,
    tls,
    buf: @io.ReaderBuffer::new(),
    lock: @async.Mutex(),
    ahead: b"",
    at: 0,
  }
}

///|
/// A connection in the clear.
pub fn Conn::plain(sock : @socket.Tcp) -> Conn {
  Conn::new(sock, None)
}

///|
/// The server side of a TLS connection, returned once the handshake is done. A handshake the
/// client fails raises the alert, after it has been sent.
pub async fn Conn::server(
  sock : @socket.Tcp,
  config : @tls.Server,
  rand? : (Int32) -> Bytes,
) -> Conn {
  let tls = @tls.Conn::server(config, rand=rand.unwrap_or(entropy))
  Conn::new(sock, Some(tls))..handshake()
}

///|
/// The client side of a TLS connection to `host`, returned once the handshake is done and the
/// server's chain has been judged under `config`. `now`, in seconds since the epoch, is the time
/// the chain is judged at; the system clock when not given.
pub async fn Conn::client(
  sock : @socket.Tcp,
  config : @tls.Client,
  host : String,
  rand? : (Int32) -> Bytes,
  now? : Int64,
) -> Conn {
  let tls = @tls.Conn::client(
    config,
    host,
    rand=rand.unwrap_or(entropy),
    now=now.unwrap_or_else(clock),
  )
  Conn::new(sock, Some(tls))..handshake()
}

///|
/// What a connection will not do.
pub(all) suberror Refused {
  /// `secure` on a connection that is TLS already.
  Secured
} derive(Eq, Debug)

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
/// Run the server side of a TLS handshake on a connection that is still in the clear, starting
/// from what a sniff has already read ahead, and return the TLS connection once it is done. This
/// is how one port serves TLS and the clear: look with `opens_tls`, then secure the ones that do.
///
/// A connection that is already TLS raises `Refused::Secured`.
pub async fn Conn::secure(
  self : Conn,
  config : @tls.Server,
  rand? : (Int32) -> Bytes,
) -> Conn {
  guard self.tls is None else { raise Secured }
  let tls = @tls.Conn::server(config, rand=rand.unwrap_or(entropy))
  let ahead = self.ahead[self.at:]
  if ahead.length() > 0 {
    tls.receive(ahead)
  }
  Conn::new(self.sock, Some(tls))..handshake()
}

///|
/// Whether the peer's stream opens with a TLS handshake record (RFC 8446 §5.1, content type 22),
/// without consuming it. No HTTP/1.1 method or HTTP/2 preface starts with that octet.
pub async fn Conn::opens_tls(self : Conn) -> Bool {
  self.starts_with(b"\x16"[:])
}

///|
fn entropy(n : Int32) -> Bytes {
  guard @env.rand(n) is Some(bytes) else { abort("no system entropy") }
  bytes
}

///|
fn clock() -> Int64 {
  (@env.now() / 1000).reinterpret_as_int64()
}

///|
async fn Conn::handshake(self : Conn) -> Unit {
  guard self.tls is Some(tls) else { return }
  self.flush()
  while !tls.is_connected() {
    guard self.sock.read_some(max_len=chunk) is Some(data) else {
      raise @io.ReaderClosed
    }
    self.receive(tls, data)
  }
}

///|
/// Feed ciphertext in and send whatever it calls for: handshake messages, a key update in reply,
/// the alert that ends the connection.
async fn Conn::receive(self : Conn, tls : @tls.Conn, data : Bytes) -> Unit {
  errdefer (self.flush() catch { _ => () })
  tls.receive(data[:])
  self.flush()
}

///|
async fn Conn::flush(self : Conn) -> Unit {
  guard self.tls is Some(tls) else { return }
  self.lock.acquire()
  defer self.lock.release()
  let out = tls.take()
  if out.length() > 0 {
    self.sock.write(out)
  }
}

///|
/// The next run of the peer's plaintext; None at the end of its stream.
async fn Conn::next(self : Conn) -> Bytes? {
  guard self.tls is Some(tls) else { return self.sock.read_some(max_len=chunk) }
  let mut plain = tls.read()
  while plain.length() == 0 && !tls.is_closed() {
    guard self.sock.read_some(max_len=chunk) is Some(data) else { break }
    self.receive(tls, data)
    plain = tls.read()
  }
  if plain.length() > 0 {
    Some(plain)
  } else {
    None
  }
}

///|
/// Read more of the peer's stream onto what is already ahead. False at the end of it.
async fn Conn::fill(self : Conn) -> Bool {
  guard self.next() is Some(bytes) else { return false }
  self.ahead = if self.at == self.ahead.length() {
    bytes
  } else {
    self.ahead[self.at:].to_owned() + bytes
  }
  self.at = 0
  true
}

///|
/// Whether the peer's stream opens with `prefix`, without consuming it. Reads only as far as the
/// first byte that differs, so a message shorter than `prefix` that is not it is not waited on —
/// which is what telling an HTTP/2 preface from an HTTP/1.1 request needs.
///
/// Ask before reading anything else: what a read has already taken is not looked at again.
pub async fn Conn::starts_with(self : Conn, prefix : BytesView) -> Bool {
  while self.agrees(prefix) && self.ahead.length() - self.at < prefix.length() {
    guard self.fill() else { return false }
  }
  self.agrees(prefix)
}

///|
/// Whether what is ahead and `prefix` agree as far as both go.
fn Conn::agrees(self : Conn, prefix : BytesView) -> Bool {
  let have = self.ahead[self.at:]
  let n = @cmp.minimum(have.length(), prefix.length())
  have[:n] == prefix[:n]
}

///|
pub impl @io.Reader for Conn with fn _get_internal_buffer(self) {
  self.buf
}

///|
pub impl @io.Reader for Conn with fn _direct_read(self, dst, offset~, max_len~) {
  if self.at == self.ahead.length() && !self.fill() {
    return 0
  }
  let n = @cmp.minimum(max_len, self.ahead.length() - self.at)
  dst.blit_from_bytes(offset, self.ahead, self.at, n)
  self.at += n
  n
}

///|
#deprecated
pub extend Conn with @io.Reader::{_direct_read, _get_internal_buffer}

///|
pub extend Conn with @io.Reader::{
  read,
  read_some,
  drop,
  read_all,
  read_until,
  read_exactly,
}

///|
pub impl @io.Writer for Conn with fn write_once(self, src, offset~, len~) {
  match self.tls {
    None => {
      self.lock.acquire()
      defer self.lock.release()
      self.sock.write(src[offset:offset + len])
    }
    Some(tls) => {
      tls.write(src[offset:offset + len])
      self.flush()
    }
  }
  len
}

///|
pub extend Conn with @io.Writer::{write_once, write, write_reader}

///|
/// End the stream: under TLS a close_notify (RFC 8446 §6.1), so the peer can tell the end from a
/// truncation. The peer may still send; read on until the end of its stream. In the clear there
/// is nothing to send.
pub async fn Conn::shutdown(self : Conn) -> Unit {
  guard self.tls is Some(tls) else { return }
  tls.close()
  self.flush()
}

///|
/// Close the socket. Call `shutdown` first for a clean end under TLS.
pub fn Conn::close(self : Conn) -> Unit {
  self.sock.close()
}

///|
/// Whether the connection runs under TLS.
pub fn Conn::is_tls(self : Conn) -> Bool {
  self.tls is Some(_)
}

///|
/// The TLS connection underneath, for what the accessors here do not say: the suite, the key
/// update, the refusal reason. None in the clear.
pub fn Conn::tls(self : Conn) -> @tls.Conn? {
  self.tls
}

///|
/// The application protocol ALPN settled on (RFC 7301). None in the clear.
pub fn Conn::alpn(self : Conn) -> String? {
  self.tls.bind(t => t.alpn())
}

///|
/// The host name the client asked for (RFC 6066 §3). None in the clear.
pub fn Conn::server_name(self : Conn) -> String? {
  self.tls.bind(t => t.server_name())
}

///|
/// The certificate chain the peer presented, DER, leaf first. Empty in the clear.
pub fn Conn::peer(self : Conn) -> Array[Bytes] {
  match self.tls {
    Some(t) => t.peer()
    None => []
  }
}
