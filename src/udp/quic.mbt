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
) -> Quic {
  let to = @socket.Addr::resolve(host, port~) catch {
    e => raise QuicRefused::Broken("\{e}")
  }
  // The socket has to be of the same family as the peer, or the kernel refuses the datagram.
  let socket = bind(host=if to.is_ipv6() { "::" } else { "0.0.0.0" }, port=0)
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
      @conn.Event::Closed(_) => self.dead = true
      _ => ()
    }
  }
  true
}

///|
/// Put `bytes` on `stream`, and end it when `fin`.
pub fn Quic::write(
  self : Quic,
  stream : UInt64,
  bytes : Bytes,
  fin~ : Bool = false,
) -> Unit {
  self.client.write(stream, bytes, fin~)
}

///|
/// The octets that arrived on `stream` since the last call; empty when none have.
pub fn Quic::take(self : Quic, stream : UInt64) -> Bytes {
  let data = self.client.read(stream)
  if data.length() > 0 {
    self.seen[stream] = true
  }
  data
}

///|
/// Whether the peer has ended `stream`, with every octet of it read.
pub fn Quic::ended(self : Quic, stream : UInt64) -> Bool {
  self.seen.get(stream).unwrap_or(false) && self.client.finished(stream)
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
