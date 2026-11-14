---
name: moonnet
description: Put HTTP/1.1, HTTP/2, HTTP/3 or WebSocket on a socket, carry QUIC streams, and hand those connections out from a pool as one contract. Use when a MoonBit program needs to open a connection, send a request, read a reply, upgrade to WebSocket, abandon a stream, or reuse connections instead of dialling again.
---

# moonnet

## Install

```
moon add moonbitstack/moonnet
```

Import the front door for the connection and the contract, and one adapter for the protocol you
speak:

```
import {
  "moonbitstack/moonnet",
  "moonbitstack/moonnet/adapt/h2",
  "moonbitstack/moonnet/spec",
}
```

## One request, whichever protocol carries it

Every adapter answers the same eight methods. `@spec.call` sends a request and reads the whole
reply, which is what most calls want.

```moonbit native
async fn status(host : String, tls : @tls.Client) -> String {
  let conn = @h2.connect(host, port=443, tls=tls)
  let (response, body) = @spec.call(conn, @spec.Request::new("GET", "/status"))
  conn.close()
  "\{response.status} \{body.length()}"
}
```

Swap `@h2.connect` for `@h1.connect`, `@h3.connect` or `@ws.connect` and the rest stands.
`@h3.connect` needs a TLS client with `alpn=["h3"]`; `@ws.connect` takes a `ws://` or `wss://` URL
and its exchange is the upgrade.

A body that is not at hand when the head goes out is streamed:

```moonbit native
async fn upload(conn : &@spec.Conn, parts : Array[Bytes]) -> @spec.Response {
  let stream = conn.open(
    @spec.Request::new("PUT", "/blob", body=@spec.Body::Streaming),
  )
  let mut left = parts.length()
  for part in parts {
    left -= 1
    conn.send(stream, part, end=left == 0)
  }
  conn.response(stream)
}
```

## Reuse the connection

A pool hands out the contract, not the socket: what `get` returns answers the same eight methods,
so the code that sends the request does not know whether an adapter or the pool supplied it.
Closing is what returns the connection. A connection whose exchange failed, that cannot take a
second exchange, or that sat idle too long is shut instead, and the slot goes to the next caller.

```moonbit native
async fn pooled(tls : @tls.Client) -> Unit {
  let pool = @pool.Pool::new(
    key => {
      let sock = @tcp.dial(key.host, port=key.port, tls=tls)
      @pool.Opened::new(sock, @h2.client(sock, scheme="https", authority=key.host))
    },
    config={ ..@pool.defaults, max_idle: 4 },
  )
  let key = @pool.Key::new("example.com", 443, alpn="h2")
  let conn = pool.get(key)
  let (response, body) = @spec.call(conn, @spec.Request::new("GET", "/"))
  println("\{response.status} \{body.length()}")
  conn.close()
  pool.close()
}
```

`Opened` pairs a socket with the adapter over it, and the pool keeps the two together: HTTP/2
sends its preface once, and a WebSocket session is one upgrade, so a fresh adapter over the same
socket would not be the same connection. `pool.get` raises `@pool.Busy` when the pool is at
`max_total` and nothing came free within `wait`, and `@pool.Closed` after `pool.close`.

## WebSocket

```moonbit native
async fn hello(url : String, tls : @tls.Client) -> Unit {
  let ws = @ws.connect(url, tls=tls)
  let stream = ws.open(@spec.Request::new("GET", "/chat"))
  println(ws.response(stream).status)
  ws.send(stream, @utf8.encode("hello"), end=false)
  match ws.read(stream) {
    Some(reply) => println(@utf8.decode_lossy(reply[:]))
    None => println("the session ended")
  }
  ws.close()
}
```

`send` writes a binary message and `send_text` writes text. A ping from the server is answered
for you and never reaches the caller, and `next` gives the messages as frames when the close code
and reason matter.

## Give a QUIC stream up, or be told to

A stream is abandoned in either direction, and the peer is told why: `reset` sends RESET_STREAM
with an application code, `stop` sends STOP_SENDING. Both go out as control frames, so they are
sent again if the packet carrying them is lost.

```moonbit native
async fn cancel(quic : @udp.Quic) -> Unit raise @udp.QuicRefused {
  let stream = quic.open_bi()
  quic.write(stream, @utf8.encode("a request nobody wants"), fin=false)
  // What is still queued on the stream goes, and the peer is told why.
  quic.reset(stream, code=0x10c)
}
```

The other end learns the same way: `take` raises `Reset(code)` once the octets that did arrive
have been handed over, `write` raises `Stopped(code)` when the peer has asked this side to stop
sending, and `refused(stream)` reports either without raising, for code that polls.

```moonbit native
async fn drain(quic : @udp.Quic, stream : UInt64) -> Int32 {
  let mut read = 0
  while true {
    let more = quic.take(stream) catch {
      @udp.QuicRefused::Reset(code) => {
        println("the peer gave up the stream with \{code}")
        return read
      }
      _ => return read
    }
    if more.length() == 0 {
      if quic.ended(stream) {
        return read
      }
    }
    read += more.length()
  }
  read
}
```

A STOP_SENDING is answered with a RESET_STREAM carrying the same code (RFC 9000 §3.5), so
nothing else is owed once `write` has raised `Stopped`. A STOP_SENDING for a stream the peer has
never seen — one this side opened and stopped before any octet went out — is a
STREAM_STATE_ERROR at the peer, so ask for a stop on a stream that is in use.

## What catches people out

- One task reads a connection and one task writes it. Two readers or two writers on the same
  handle abort the process in the async runtime; a pool hands a connection to one caller at a
  time for that reason.
- A connection from a pool belongs to the caller until `close`, and a connection never closed
  stays against `max_total`. Using one after it went back raises `@spec.Refused::Closed` rather
  than writing to a socket someone else now holds.
- HTTP/1.1 carries one exchange at a time, so `is_ready()` is false until the reply has been
  read to its end. HTTP/2 and HTTP/3 return true. Do not open a second exchange on HTTP/1.1
  because a check passed on another adapter.
- `read` returns `None` at the end of a body; keep calling it until then, or use
  `@spec.read_to_end(conn, stream, limit=...)` so a hostile peer cannot make you hold an
  unbounded body.
- `@udp.dial` tries IPv6 first and IPv4 `attempt_delay` (250 ms) later, keeping whichever
  handshake completes first; with addresses already in hand, `@udp.dial_addrs` tries them in
  the order given.
- The sockets exist on the native and wasm backends. On js and wasm-gc the packages that drive
  them are empty, so a program that dials is native or wasm.
- The default port is 12000 for a server this library starts, and 443/80 for `connect(url)`.
