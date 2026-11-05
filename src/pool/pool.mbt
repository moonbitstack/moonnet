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
/// A connection in the pool and the moment it stops being worth reusing.
pub struct Idle {
  conn : @tcp.Conn
  until : Int64
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
/// The connections kept for another exchange. A caller takes one with `get` and gives it
/// back with `put`, or closes it and takes another next time; a connection that is not given
/// back is not counted as idle and stays against `max_total`.
pub struct Pool {
  dial : async (Key) -> @tcp.Conn
  config : Config
  // Idle connections by key, the most recently used last.
  mut idle : Map[String, Array[Idle]]
  mut total : Int32
  // Wakes a caller waiting for a slot.
  changed : @cond_var.Cond
  mut closed : Bool
}

///|
/// A pool that opens a connection with `dial` when it has none to hand out.
pub fn Pool::new(
  dial : async (Key) -> @tcp.Conn,
  config~ : Config = defaults,
) -> Pool {
  {
    dial,
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
/// Raises `Busy` when the pool is full and nothing came free within `wait`.
pub async fn Pool::get(self : Pool, key : Key) -> @tcp.Conn raise Refused {
  let text = key.text()
  while true {
    if self.closed {
      raise Closed
    }
    if self.take_idle(text) is Some(entry) {
      if entry.until < now() {
        entry.conn.close()
        self.total -= 1
        continue
      }
      if self.config.liveness is Liveness::Peek {
        // The check may read what the peer sent; the read is kept, so the next exchange
        // starts from those octets rather than after them.
        let alive = entry.conn.is_alive(wait=1) catch { _ => false }
        if !alive {
          entry.conn.close()
          self.total -= 1
          continue
        }
      }
      return entry.conn
    }
    if self.total < self.config.max_total {
      self.total += 1
      let opened = (self.dial)(key) catch {
        e => {
          self.total -= 1
          self.changed.broadcast()
          raise Failed("\{e}")
        }
      }
      return opened
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
/// Put a connection back for the next exchange. A pool that is closed, or that already keeps
/// `max_idle` for this key, closes it instead; either way it stops counting against
/// `max_total`.
pub fn Pool::put(self : Pool, key : Key, conn : @tcp.Conn) -> Unit {
  if self.closed {
    conn.close()
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
  kept.push({ conn, until: now() + self.config.idle.to_int64(), })
  while kept.length() > self.config.max_idle {
    let oldest = kept.remove(0)
    oldest.conn.close()
    self.total -= 1
  }
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
/// Close every idle connection and refuse further use.
pub fn Pool::close(self : Pool) -> Unit {
  self.closed = true
  for _, kept in self.idle {
    for entry in kept {
      entry.conn.close()
    }
  }
  self.idle = Map([])
  self.total = 0
  self.changed.broadcast()
}
