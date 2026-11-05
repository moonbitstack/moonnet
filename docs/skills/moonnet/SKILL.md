---
name: moonnet
description: Put HTTP/1.1, HTTP/2, HTTP/3 or WebSocket on a socket, and keep those connections in a pool. Use when a MoonBit program needs to open a connection, send a request, read a reply, upgrade to WebSocket, or reuse connections instead of dialling again.
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

```moonbit
async fn status(url : String, tls : @tls.Client) -> String {
  let conn = @h2.connect("example.com", port=443, tls=tls)
  let (response, body) = @spec.call(conn, @spec.Request::new("GET", "/status"))
  conn.close()
  "\{response.status} \{body.length()}"
}
```

Swap `@h2.connect` for `@h1.connect`, `@h3.connect` or `@ws.connect` and the rest stands.
`@h3.connect` needs a TLS client with `alpn=["h3"]`; `@ws.connect` takes a `ws://` or `wss://` URL
and its exchange is the upgrade.

A body that is not at hand when the head goes out is streamed:

```moonbit
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

A pool key is the host, the port and the ALPN the connection settled on, so a connection opened
for `h2` is never handed back as a clear HTTP/1.1 one. The preset is a record; change one field
and the rest stay.

```moonbit
async fn pooled(tls_for : (@pool.Key) -> @tls.Client) -> Unit {
  let pool = @pool.Pool::new(
    key => @tcp.dial(key.host, port=key.port, tls=tls_for(key)),
    config={ ..@pool.defaults, max_idle: 4 },
  )
  let key = @pool.Key::new("example.com", 443, alpn="h2")
  let conn = pool.get(key)
  // ... one connection's worth of work ...
  pool.put(key, conn)
  pool.close()
}
```

`pool.get` raises `@pool.Busy` when the pool is at `max_total` and nothing came free within
`wait`, and `@pool.Closed` after `pool.close`.

## WebSocket

```moonbit
async fn echo(url : String, tls : @tls.Client) -> Unit {
  let ws = @ws.connect(url, tls=tls)
  let stream = ws.open(@spec.Request::new("GET", "/chat"))
  let _ = ws.response(stream)
  ws.send_text("hello")
  match ws.next() {
    Some(@frame.Message::Text(reply)) => println(reply)
    Some(@frame.Message::Close(status~, ..)) => println("closed \{status}")
    _ => ()
  }
}
```

`send` writes a binary message and `send_text` writes text; a reply arrives as a
`@frame.Message`, not as octets. A ping from the server is answered for you and never reaches
`next`.

## What catches people out

- One task reads a connection and one task writes it. Two readers or two writers on the same
  handle abort the process in the async runtime; a pool hands a connection to one caller at a
  time for that reason.
- HTTP/1.1 carries one exchange at a time, so `is_ready()` is false until the reply has been
  read to its end. HTTP/2, HTTP/3 and WebSocket return true. Do not open a second exchange on
  HTTP/1.1 because a check passed on another adapter.
- `read` returns `None` at the end of a body; keep calling it until then, or use
  `@spec.read_to_end(conn, stream, limit=...)` so a hostile peer cannot make you hold an
  unbounded body.
- The sockets exist on the native and wasm backends. On js and wasm-gc the packages that drive
  them are empty, so a program that dials is native or wasm.
- The default port is 12000 for a server this library starts, and 443/80 for `connect(url)`.
