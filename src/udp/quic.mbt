// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A QUIC connection driven by one task: the client half of what `moonquic` states and this
/// package puts on a datagram socket. Reading is a poll, because a connection that also
/// carries control and QPACK streams cannot hand every arrival to one caller.
pub struct Quic {
  socket : Socket
  to : @socket.Addr
  client : @conn.Client
  mut bi : UInt64
  mut uni : UInt64
  mut dead : Bool
  // Streams the peer has sent something on. The codec reports an unknown stream as ended,
  // because it has no record of one, so a stream this side only wrote on is not ended yet.
  seen : Map[UInt64, Bool]
  // Octets handed to `write` on each stream. The send loop keeps its own record of a stream it
  // has carried data for; a stream opened and never written on has none, and still has to be
  // reset with a final size rather than not at all.
  sent : Map[UInt64, UInt64]
  // How the peer ended each stream abruptly: the code of a reset it sent, or of the stop it
  // asked for. A stream the peer ended with a FIN is not in here.
  errors : Map[UInt64, QuicRefused]
  // Streams this side has abandoned as a sender, with the code it sent.
  abandoned : Map[UInt64, UInt64]
}

///|
/// The clock a QUIC connection counts in: microseconds since the epoch, which is the unit the
/// recovery, idle and closing-period timers are measured in (RFC 9002 §6). Reading it in
/// milliseconds leaves every timer a thousand times too long, so a lost packet is never sent
/// again.
pub fn now() -> Int64 {
  (@env.now() * 1000).reinterpret_as_int64()
}

///|
/// The clock a certificate is judged at: seconds since the epoch.
fn wall() -> Int64 {
  (@env.now() / 1000).reinterpret_as_int64()
}

///|
fn entropy(n : Int32) -> Bytes {
  guard @env.rand(n) is Some(bytes) else { abort("no system entropy") }
  bytes
}

///|
/// Connect to `host:port` and shake hands. The connection is returned once the handshake is
/// confirmed; `tls` offers `h3` or whatever ALPN the peer is expected to choose.
pub async fn dial(
  host : String,
  port~ : Int32,
  tls~ : @tls.Client,
  idle~ : UInt64 = 30000UL,
) -> Quic raise QuicRefused {
  let to = @socket.Addr::resolve(host, port~) catch {
    e => raise QuicRefused::Broken("\{e}")
  }
  // The socket has to be of the same family as the peer, or the kernel refuses the datagram.
  let socket = bind(host=if to.is_ipv6() { "::" } else { "0.0.0.0" }, port=0) catch {
    e => raise QuicRefused::Broken("\{e}")
  }
  let scid = entropy(8)
  let dcid = entropy(8)
  let params = @conn.Limits::new(
    idle_timeout=idle,
    data=8_000_000UL,
    stream_data_bidi_local=4_000_000UL,
    stream_data_bidi_remote=4_000_000UL,
    stream_data_uni=1_000_000UL,
    streams_bidi=128UL,
    streams_uni=16UL,
  ).params()
  params.push({ kind: @conn.Kind::InitialScid, value: scid, })
  let client = @conn.Client::new(
    tls,
    host,
    @conn.encode(params[:]),
    entropy,
    dcid,
    scid,
    wall(),
  ) catch {
    e => raise QuicRefused::Broken("\{e}")
  }
  let link : Quic = {
    socket,
    to,
    client,
    bi: 0UL,
    uni: 2UL,
    dead: false,
    seen: Map([]),
    sent: Map([]),
    errors: Map([]),
    abandoned: Map([]),
  }
  let mut rounds = 0
  while !link.client.is_connected() {
    if rounds > 600 {
      link.socket.close()
      raise QuicRefused::Timeout
    }
    let _ = link.step(timeout=20)
    rounds += 1
  }
  link
}

///|
/// What a QUIC connection will not do.
#derive(Eq, Debug)
pub(all) suberror QuicRefused {
  /// The handshake did not complete in the time this waited.
  Timeout
  /// The socket or the connection under it failed.
  Broken(String)
  /// The connection is over.
  Closed
  /// The stream was abandoned with this application code: the peer sent RESET_STREAM when
  /// this side was reading it, or this side sent one itself (RFC 9000 §19.4).
  Reset(UInt64)
  /// The peer sent STOP_SENDING with this code, which says it will read no more of the
  /// stream; sending on it is over (RFC 9000 §19.5).
  Stopped(UInt64)
}

///|
pub extend QuicRefused with Eq::{equal, not_equal}

///|
pub extend QuicRefused with Debug::{to_repr}

///|
/// Send what the connection has queued and take one datagram in, which is one turn of a
/// handshake or of an exchange. False when nothing arrived within `timeout`.
pub async fn Quic::step(
  self : Quic,
  timeout~ : Int32 = 20,
) -> Bool raise QuicRefused {
  if self.dead {
    return false
  }
  for datagram in self.client.poll_out(now()) {
    self.socket.send(self.to, datagram) catch {
      e => raise QuicRefused::Broken("\{e}")
    }
  }
  let arrived = self.socket.recv(timeout~) catch {
    e => raise QuicRefused::Broken("\{e}")
  }
  guard arrived is Some((bytes, _)) else { return false }
  self.client.recv(bytes, now()) catch {
    e => {
      self.dead = true
      raise QuicRefused::Broken("\{e}")
    }
  }
  for event in self.client.take_events() {
    match event {
      @conn.Event::Readable(id) => self.seen[id] = true
      @conn.Event::Reset(id, code) => self.errors[id] = QuicRefused::Reset(code)
      // §3.5: a STOP_SENDING leaves the sender no choice but to abandon the stream, with the
      // code the peer gave it.
      @conn.Event::Stopped(id, code) => {
        self.errors[id] = QuicRefused::Stopped(code)
        ignore(self.abandon(id, code))
      }
      @conn.Event::Closed(_) => self.dead = true
      _ => ()
    }
  }
  true
}

///|
/// Put `bytes` on `stream`, and end it when `fin`. Raises `Stopped` when the peer has asked
/// this side to stop sending on the stream, and `Reset` when this side abandoned it.
pub fn Quic::write(
  self : Quic,
  stream : UInt64,
  bytes : Bytes,
  fin~ : Bool = false,
) -> Unit raise QuicRefused {
  if self.dead {
    raise QuicRefused::Closed
  }
  if self.errors.get(stream) is Some(QuicRefused::Stopped(code)) {
    raise QuicRefused::Stopped(code)
  }
  if self.abandoned.get(stream) is Some(code) {
    raise QuicRefused::Reset(code)
  }
  self.client.write(stream, bytes, fin~)
  if bytes.length() > 0 {
    let at = self.sent.get(stream).unwrap_or(0UL)
    self.sent[stream] = at + bytes.length().to_uint64()
  }
}

///|
/// The octets that arrived on `stream` since the last call; empty when none have. What arrived
/// before a reset is still handed over first: RFC 9000 §3.2 keeps the octets received up to the
/// final size readable, and it is the end that is an error. An empty read raises `Reset` once
/// the peer has abandoned the stream.
pub fn Quic::take(self : Quic, stream : UInt64) -> Bytes raise QuicRefused {
  let data = self.client.read(stream)
  if data.length() > 0 {
    self.seen[stream] = true
    return data
  }
  if self.errors.get(stream) is Some(QuicRefused::Reset(code)) {
    raise QuicRefused::Reset(code)
  }
  data
}

///|
/// How the peer ended `stream` abruptly, if it did: `Reset` for a stream this side was reading,
/// `Stopped` for one it was writing. `None` while the stream is live, and after a clean FIN —
/// which is what `ended` reports.
pub fn Quic::refused(self : Quic, stream : UInt64) -> QuicRefused? {
  self.errors.get(stream)
}

///|
/// Whether the peer has ended `stream`, with every octet of it read. A stream the peer reset is
/// over too, however much of it arrived.
pub fn Quic::ended(self : Quic, stream : UInt64) -> Bool {
  if self.errors.get(stream) is Some(QuicRefused::Reset(_)) {
    return true
  }
  self.seen.get(stream).unwrap_or(false) && self.client.finished(stream)
}

///|
/// Abandon `stream` as a sender: send RESET_STREAM carrying `code`, and drop what the send loop
/// still holds for it (RFC 9000 §3.5, §19.4). Zero, the default, is NO_ERROR (§20.1). Writing
/// on the stream afterwards raises `Reset`. A stream this side only reads may be reset too: it
/// closes this side's sending half, which is what a reply abandoned half way needs.
pub fn Quic::reset(
  self : Quic,
  stream : UInt64,
  code~ : UInt64 = 0UL,
) -> Unit raise QuicRefused {
  if self.dead {
    raise QuicRefused::Closed
  }
  if self.abandoned.contains(stream) {
    return
  }
  if !self.abandon(stream, code) {
    raise QuicRefused::Closed
  }
  self.abandoned[stream] = code
}

///|
/// Ask the peer to stop sending on `stream`, with STOP_SENDING carrying `code` (RFC 9000
/// §19.5): the octets already on their way are dropped when they arrive, and `take` raises
/// `Reset` if the peer answers with one. Zero, the default, is NO_ERROR (§20.1).
pub fn Quic::stop(
  self : Quic,
  stream : UInt64,
  code~ : UInt64 = 0UL,
) -> Unit raise QuicRefused {
  if self.dead {
    raise QuicRefused::Closed
  }
  let frame : @frame.Frame = @frame.Frame::StopSending(
    id=stream,
    error_code=code,
  )
  if !self.client.send_on(0UL, [frame], now()) {
    raise QuicRefused::Closed
  }
}

///|
/// Queue a RESET_STREAM for `stream` and cancel what is queued on it, answering whether the
/// connection could take the frame. The send loop queues the frame itself while it still holds
/// the stream; a stream whose data has all been acknowledged has been released there, and then
/// the frame is queued here with the final size this side wrote.
fn Quic::abandon(self : Quic, stream : UInt64, code : UInt64) -> Bool {
  if self.client.buffered(stream) > 0UL {
    self.client.sender.abandon(stream, code)
    return true
  }
  let end = self.sent.get(stream).unwrap_or(0UL)
  let frame : @frame.Frame = @frame.Frame::ResetStream(
    id=stream,
    error_code=code,
    final_size=end,
  )
  self.client.send_on(0UL, [frame], now())
}

///|
/// The next bidirectional stream this side opens: 0, 4, 8, … as RFC 9000 §2.1 numbers them.
pub fn Quic::open_bi(self : Quic) -> UInt64 {
  let id = self.bi
  self.bi += 4UL
  id
}

///|
/// The next unidirectional stream, from 2 upwards.
pub fn Quic::open_uni(self : Quic) -> UInt64 {
  let id = self.uni
  self.uni += 4UL
  id
}

///|
/// The ALPN the handshake settled on.
pub fn Quic::alpn(self : Quic) -> String? {
  self.client.alpn()
}

///|
/// Close the socket the connection runs on.
pub fn Quic::close(self : Quic) -> Unit {
  self.dead = true
  self.socket.close()
}
