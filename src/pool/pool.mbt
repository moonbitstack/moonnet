// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What makes two connections interchangeable: the host, the port, and the protocol ALPN
/// settled on. A connection kept under one key is never handed out for another.
#derive(Eq, Debug)
pub(all) struct Key {
  host : String
  port : Int32
  alpn : String
}

///|
pub fn Key::new(host : String, port : Int32, alpn~ : String) -> Key {
  { host, port, alpn, }
}

///|
pub extend Key with Eq::{equal, not_equal}

///|
pub extend Key with Debug::{to_repr}

///|
/// What a reused connection is asked before it is handed out again.
#derive(Eq, Debug)
pub(all) enum Liveness {
  /// Nothing: a connection that served an exchange is taken on trust until the next one
  /// fails, which is what most clients do.
  None_
  /// A read that does not wait. A peer that has closed is dropped; one that has said
  /// something while idle keeps what it said for the next exchange.
  Peek
}

///|
pub extend Liveness with Eq::{equal, not_equal}

///|
pub extend Liveness with Debug::{to_repr}

///|
/// How a pool behaves. Every one of these is a number a caller will want to change, so all
/// of them are here rather than in the code.
#derive(Eq, Debug)
pub(all) struct Config {
  /// How long a connection may sit idle before it is closed instead of reused, in
  /// milliseconds.
  idle : Int32
  /// How many idle connections one key may keep.
  max_idle : Int32
  /// How many connections the pool may hold open at once, in use or idle.
  max_total : Int32
  /// Whether a reused connection is checked first.
  liveness : Liveness
  /// How long a caller waits for a slot when the pool is full, in milliseconds.
  wait : Int32
}

///|
pub extend Config with Eq::{equal, not_equal}

///|
pub extend Config with Debug::{to_repr}

///|
/// The presets: an idle connection lives half a minute, a key keeps eight, the pool holds
/// sixty-four, a reused one is peeked at, and a caller waits five seconds for a slot. These
/// are the values curl and Go's transport settle near; what matters more is that all five
/// are named and can be changed.
pub let defaults : Config = {
  idle: 30000,
  max_idle: 8,
  max_total: 64,
  liveness: Liveness::Peek,
  wait: 5000,
}

///|
/// What a pool will not do.
#derive(Eq, Debug)
pub(all) suberror Refused {
  /// The pool is full and no slot came free in time.
  Busy
  /// The pool was closed.
  Closed
  /// Opening a connection failed.
  Failed(String)
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
/// A socket and the connection that presents it as the contract. The two stay bound for as
/// long as both live: a protocol's connection carries state a fresh one over the same socket
/// would not have — HTTP/2 sends its preface once, and a WebSocket session is one upgrade
/// and then messages.
pub struct Opened {
  raw : @tcp.Conn
  conn : &@spec.Conn
}

///|
/// A pair for a socket the caller has just dialled, with `conn` the adapter over it.
pub fn Opened::new(raw : @tcp.Conn, conn : &@spec.Conn) -> Opened {
  { raw, conn, }
}

///|
/// A connection kept in the pool, and the moment it stops being worth reusing.
struct Idle {
  raw : @tcp.Conn
  conn : &@spec.Conn
  until : Int64
}

///|
/// The connections kept for another exchange, handed out as the contract. A caller takes one
/// with `get` and gives it back by closing it; a connection that is never closed is not
/// counted as idle and stays against `max_total`.
pub struct Pool {
  // What the pool opens for a key it has nothing idle for.
  open : async (Key) -> Opened
  config : Config
  // Idle connections by key, the most recently used last.
  mut idle : Map[String, Array[Idle]]
  mut total : Int32
  // Wakes a caller waiting for a slot.
  changed : @cond_var.Cond
  mut closed : Bool
}

///|
/// A pool that opens a connection with `open` when it has none to hand out.
pub fn Pool::new(
  open : async (Key) -> Opened,
  config~ : Config = defaults,
) -> Pool {
  {
    open,
    config,
    idle: Map([]),
    total: 0,
    changed: @cond_var.Cond(),
    closed: false,
  }
}

///|
/// The key as the one string the map is indexed by.
fn Key::text(self : Key) -> String {
  "\{self.host}:\{self.port}/\{self.alpn}"
}

///|
fn now() -> Int64 {
  @env.now().reinterpret_as_int64()
}

///|
/// Take a connection for `key`: one that is idle, unexpired and still open, or a new one.
/// What comes back is the contract, and closing it is what returns it to the pool rather
/// than shutting the socket. Raises `Busy` when the pool is full and nothing came free
/// within `wait`.
pub async fn Pool::get(self : Pool, key : Key) -> Handout raise Refused {
  let text = key.text()
  while true {
    if self.closed {
      raise Closed
    }
    if self.take_idle(text) is Some(entry) {
      if entry.until < now() {
        entry.raw.close()
        self.total -= 1
        continue
      }
      if self.config.liveness is Liveness::Peek {
        // The check may read what the peer sent; the read is kept on the socket, so the
        // exchange that follows starts from those octets rather than after them.
        let alive = entry.raw.is_alive(wait=1) catch { _ => false }
        if !alive {
          entry.raw.close()
          self.total -= 1
          continue
        }
      }
      return Handout::new(self, key, entry.raw, entry.conn)
    }
    if self.total < self.config.max_total {
      self.total += 1
      let opened = (self.open)(key) catch {
        e => {
          self.total -= 1
          self.changed.broadcast()
          raise Failed("\{e}")
        }
      }
      return Handout::new(self, key, opened.raw, opened.conn)
    }
    let woke = @async.with_timeout_opt(self.config.wait, () => {
      self.changed.wait()
    }) catch {
      _ => None
    }
    if woke is None {
      raise Busy
    }
  }
  raise Busy
}

///|
/// Where a handed-out connection stands. A connection is reused only from `InUse`; an
/// exchange that failed, or one that was cut short, leaves it `Broken` and the socket is
/// shut rather than handed on.
enum Standing {
  InUse
  Broken
  Returned
}

///|
/// A connection handed out by a pool: the contract's eight methods, and a `close` that puts
/// the connection back for the next caller instead of shutting the socket.
pub struct Handout {
  pool : Pool
  key : Key
  raw : @tcp.Conn
  conn : &@spec.Conn
  mut standing : Standing
}

///|
fn Handout::new(
  pool : Pool,
  key : Key,
  raw : @tcp.Conn,
  conn : &@spec.Conn,
) -> Handout {
  { pool, key, raw, conn, standing: InUse, }
}

///|
/// The connection this was handed out with, or a refusal if it has already gone back.
fn Handout::live(self : Handout) -> &@spec.Conn raise @spec.Refused {
  guard self.standing is InUse else { raise @spec.Refused::Closed }
  self.conn
}

///|
/// A failure anywhere in an exchange leaves the connection in a state only the peer knows:
/// the octets of a half-read body are still on the socket, so it is dropped rather than
/// handed to the next caller.
pub impl @spec.Conn for Handout with fn open(self, request) {
  let conn = self.live()
  errdefer {
    self.standing = Broken
  }
  conn.open(request)
}

///|
pub impl @spec.Conn for Handout with fn send(self, stream, bytes, end~) {
  let conn = self.live()
  errdefer {
    self.standing = Broken
  }
  conn.send(stream, bytes, end~)
}

///|
pub impl @spec.Conn for Handout with fn response(self, stream) {
  let conn = self.live()
  errdefer {
    self.standing = Broken
  }
  conn.response(stream)
}

///|
pub impl @spec.Conn for Handout with fn read(self, stream) {
  let conn = self.live()
  errdefer {
    self.standing = Broken
  }
  conn.read(stream)
}

///|
pub impl @spec.Conn for Handout with fn trailers(self, stream) {
  let conn = self.live() catch { _ => return [] }
  conn.trailers(stream)
}

///|
pub impl @spec.Conn for Handout with fn is_ready(self) {
  guard self.standing is InUse else { return false }
  self.conn.is_ready()
}

///|
pub impl @spec.Conn for Handout with fn kind(self) {
  self.conn.kind()
}

///|
/// The end of the loan: a connection that served its exchange goes back to the pool, and one
/// whose exchange failed, or that cannot take another, is shut. Closing twice does nothing
/// the second time.
pub impl @spec.Conn for Handout with fn close(self) {
  match self.standing {
    Returned => ()
    Broken | InUse => {
      let reusable = self.standing is InUse && self.conn.is_ready()
      self.standing = Returned
      if reusable {
        self.pool.recycle(self.key, self.raw, self.conn)
      } else {
        self.conn.close() catch {
          _ => ()
        }
        self.pool.discard()
      }
    }
  }
}

///|
pub extend Handout with @spec.Conn::{
  open,
  send,
  response,
  read,
  trailers,
  is_ready,
  kind,
  close,
}

///|
/// Keep a connection for the next caller. A pool that is closed, or that already keeps
/// `max_idle` for this key, closes it instead; either way it stops counting against
/// `max_total`.
fn Pool::recycle(
  self : Pool,
  key : Key,
  raw : @tcp.Conn,
  conn : &@spec.Conn,
) -> Unit {
  if self.closed {
    raw.close()
    self.total -= 1
    self.changed.broadcast()
    return
  }
  let text = key.text()
  let kept = match self.idle.get(text) {
    Some(kept) => kept
    None => {
      let fresh : Array[Idle] = []
      self.idle[text] = fresh
      fresh
    }
  }
  kept.push({ raw, conn, until: now() + self.config.idle.to_int64(), })
  while kept.length() > self.config.max_idle {
    let oldest = kept.remove(0)
    oldest.raw.close()
    self.total -= 1
  }
  self.changed.broadcast()
}

///|
/// Let go of a connection the pool will not keep: it has been shut, and the slot it held
/// goes to whoever is waiting.
fn Pool::discard(self : Pool) -> Unit {
  self.total -= 1
  self.changed.broadcast()
}

///|
fn Pool::take_idle(self : Pool, text : String) -> Idle? {
  match self.idle.get(text) {
    Some(kept) =>
      if kept.length() == 0 {
        None
      } else {
        Some(kept.remove(kept.length() - 1))
      }
    None => None
  }
}

///|
/// How many connections are idle under `key`.
pub fn Pool::idle(self : Pool, key : Key) -> Int32 {
  match self.idle.get(key.text()) {
    Some(kept) => kept.length()
    None => 0
  }
}

///|
/// How many connections the pool holds open, in use or idle.
pub fn Pool::total(self : Pool) -> Int32 {
  self.total
}

///|
/// Close every idle connection and refuse further use. A connection out on loan is closed
/// when its holder gives it back.
pub fn Pool::close(self : Pool) -> Unit {
  self.closed = true
  for _, kept in self.idle {
    for entry in kept {
      entry.raw.close()
      self.total -= 1
    }
  }
  self.idle = Map([])
  self.changed.broadcast()
}
