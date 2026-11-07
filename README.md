# moonnet

[Site](https://moonbitstack.github.io/moonnet/) · [Guide](https://moonbitstack.github.io/moonnet/guide.html) · [API](https://moonbitstack.github.io/moonnet/api.html) · [mooncakes](https://mooncakes.io/docs/moonbitstack/moonnet)

The connection layer: one contract for a request and a reply, whatever carries it, and the
sockets underneath.

The wire formats are pure state machines — bytes in, events out — and touch no socket. This is
what puts them on one: TCP and UDP, TLS over TCP, QUIC over UDP, and an adapter for each
protocol that turns it into the same `open` / `send` / `response` / `read`.

```moonbit native
// One request, whichever of the four carries it.
let client = @tls.Client::new(@roots.mozilla(), alpn=["h2"])
let conn = @h2.connect("example.com", port=443, tls=client)
let (response, body) = @spec.call(conn, @spec.Request::new("GET", "/"))
println("\{response.status} \{body.length()}")
conn.close()
```

## Install

```bash
moon add moonbitstack/moonnet
```

## The contract

Everything above this library is written against `moonnet/spec`, and nothing in it names a
protocol:

| Declaration | Shape |
|:--|:--|
| `Field` | `{ name, value }`, one field of a head |
| `Body` | `Empty`, `Bytes(Bytes)`, `Streaming` |
| `Request` | `{ verb, target, fields, body }` |
| `Response` | `{ status : Int32, fields }` — the head; the body is read through the connection |
| `Stream` | one exchange, numbered by the connection rather than by the protocol under it |
| `Refused` | `Malformed`, `Unsupported`, `Closed`, `Broken` |

<!-- nocheck -->
```moonbit native
pub(open) trait Conn {
  async fn open(self : Self, request : Request) -> Stream
  async fn send(self : Self, stream : Stream, bytes : Bytes, end~ : Bool) -> Unit
  async fn response(self : Self, stream : Stream) -> Response
  async fn read(self : Self, stream : Stream) -> Bytes?
  fn trailers(self : Self, stream : Stream) -> Array[Field]
  fn is_ready(self : Self) -> Bool
  fn kind(self : Self) -> String
  async fn close(self : Self) -> Unit
}
```

The trait is open: a new protocol is an implementation of it, and nothing above changes.
`call` and `read_to_end` are the two helpers over it, for the common shape of "send this,
read all of that".

```moonbit native
async fn fetch(conn : &@spec.Conn, path : String) -> Bytes {
  let stream = conn.open(@spec.Request::new("GET", path))
  let response = conn.response(stream)
  assert_eq(response.status, 200)
  @spec.read_to_end(conn, stream)
}
```

The same `fetch` runs on every adapter below and on every connection a pool hands out.
`is_ready` is what a connection says about starting another exchange on it: HTTP/1.1 is False
while one is in flight, HTTP/2 and HTTP/3 are True, and a WebSocket session is False once its
upgrade has gone out, since the upgrade is its one exchange.

## Adapters

| Package | Protocol | Public entry points |
|:--|:--|:--|
| `adapt/h1` | HTTP/1.1, RFC 9112 | `client(tcp_conn, authority)`, `connect(host, port~, tls?)` |
| `adapt/h2` | HTTP/2, RFC 9113 | `client(tcp_conn, scheme~, authority~)`, `connect(host, port~, tls?)` |
| `adapt/h3` | HTTP/3, RFC 9114 | `connect(host, port~, tls~)` |
| `adapt/ws` | WebSocket, RFC 6455 | `client(tcp_conn, host~)`, `connect(url, tls?)` |

HTTP/1.1 frames a body three ways: a declared length, chunks with trailers, and a body that
runs to the close. A reply shorter than its length is a truncation and raises rather than
returning a short body; an informational head is passed over for the final one; the `Host`
field is the authority the connection was opened to, not whatever the caller passed.

HTTP/2 sends its preface and settings when the connection opens, puts every exchange on its
own stream, and honours flow control both ways: a body goes out as the window allows and
waits to be widened, and the octets read are handed back so that a reply larger than one
window arrives instead of stalling at 64 KiB.

HTTP/3 states its settings on a control stream — with the QPACK dynamic table shut, so no
reply can refer to an entry this side does not have — and puts each exchange on a
bidirectional stream. A peer that says nothing for thirty seconds is given up on rather than
waited for.

WebSocket makes the upgrade its exchange: `open` sends the handshake and `response` is the
101 with its accept checked against the key. After that `read` yields whole messages and a
ping is answered on the way without reaching the caller. `send` writes a binary message,
since the contract's octets do not say whether they are text; `send_text` is the one that
writes text, and `close_code` / `close_reason` report how a session ended.

```moonbit native
// A session, and the reply to what the client said.
async fn hello(url : String, tls : @tls.Client) -> Unit {
  let ws = @ws.connect(url, tls=tls)
  let stream = ws.open(@spec.Request::new("GET", "/chat"))
  let _ = ws.response(stream)
  ws.send(stream, @utf8.encode("hello"), end=false)
  match ws.read(stream) {
    Some(reply) => println(@utf8.decode_lossy(reply[:]))
    None => println("no reply")
  }
  ws.close()
}
```

## The pool

A pool hands out the contract, not the socket. What `get` returns answers the same eight
methods as an adapter, so the code above it names no protocol, and a connection is kept only
for what it was opened for: the key is the host, the port and the ALPN the connection settled
on.

Closing is what returns a connection. A connection whose exchange failed, that cannot take
another one, or that sat idle past its time is shut instead, and the slot goes to whoever is
waiting.

```moonbit native
async fn pooled(tls : @tls.Client) -> Unit {
  let pool = @pool.Pool::new(
    key => {
      let sock = @tcp.dial(key.host, port=key.port, tls=tls)
      @pool.Opened::new(sock, @h2.client(sock, scheme="https", authority=key.host))
    },
    config={ ..@pool.defaults, idle: 60000, max_total: 128 },
  )
  let key = @pool.Key::new("example.com", 443, alpn="h2")
  assert_eq(key.alpn, "h2")
  // The same `fetch` the adapters answer, on a connection the pool chose.
  let conn = pool.get(key)
  let body = fetch(conn, "/")
  println(body.length())
  conn.close()
  pool.close()
}
```

`Opened` is the pair a pool keeps: the socket, and the adapter over it. The two stay together
for as long as both live, because a protocol's connection carries state a fresh one over the
same socket would not have — HTTP/2 sends its preface once, and a WebSocket session is one
upgrade and then messages.

| Field | Preset | What it is |
|:--|:--:|:--|
| `idle` | 30000 ms | how long a connection may sit idle before it is closed instead of reused |
| `max_idle` | 8 | how many idle connections one key keeps |
| `max_total` | 64 | how many the pool holds open at once, in use or idle |
| `liveness` | `Peek` | what a reused connection is asked first: nothing, or a read that does not wait |
| `wait` | 5000 ms | how long a caller waits for a slot when the pool is full |

`Peek` is a read that does not wait: a peer that has closed while the connection sat idle is
dropped, and one that said something is kept along with what it said, so the next exchange
starts from those octets rather than after them. A pool that is full raises `Busy` rather than
opening past `max_total`.

## UDP and QUIC

`moonnet/udp` is the datagram socket and the client end of a QUIC connection on it.

```moonbit native
async fn datagrams() -> Unit {
  let socket = @udp.bind(port=12000)
  let to = socket.addr()
  socket.send(to, b"ping")
  match socket.recv(timeout=100) {
    Some((bytes, _)) => println("\{bytes.length()} octets")
    None => println("nothing came back")
  }
  socket.close()
}

async fn quic_session(tls : @tls.Client) -> Unit {
  let quic = @udp.dial("example.com", port=443, tls=tls)
  let stream = quic.open_bi()
  quic.write(stream, b"hello", fin=true)
  quic.close()
}
```

`Quic::step` is one turn of the connection — send what is queued, take one datagram in — and
`take`, `ended`, `open_bi` and `open_uni` read what came of it. Reading is a poll rather than a
blocking call because the same connection also carries control and QPACK streams.

## TCP

`moonnet/tcp` is the connection underneath the adapters: TCP, TLS 1.3 over it, the listener
and accept loop, the dialler, and one port that serves TLS and the clear.

|  | |
|:--|:--|
| `Conn::plain(sock)` | a socket in the clear |
| `Conn::server(sock, config)` | the server side of TLS, returned after the handshake |
| `Conn::client(sock, config, host)` | the client side, returned after the server's chain is judged |
| `starts_with(prefix)` | whether the stream opens with `prefix`, reading only as far as the first byte that differs |
| `opens_tls()`, `secure(config)` | serve TLS and the clear on one port |
| `is_alive(wait~)` | whether the peer is still there, asked without waiting |
| `shutdown()`, `close()` | a close_notify, then the socket |

```moonbit native
@tcp.serve((conn, _) => {
  while conn.read_until("\n") is Some(line) {
    conn.write(line + "\n")
  }
}, port=12000)
```

`serve` listens on `127.0.0.1:12000` unless told otherwise. One task may read while another
writes, and writes are serialised, so concurrent writers put whole messages on the wire and
TLS records stay in sequence.

The sockets are `moonbitlang/async`'s, which exist on the native and wasm backends; on js and
wasm-gc the packages that drive them are empty.

## Examples

| Directory | What it does |
|:--|:--|
| `src/examples/tour` | a TLS server and a client talking over it in one run |
| `src/examples/01-interop` | one client that speaks all four protocols through the contract, for driving against another server |
| `src/examples/02-plug` | a connection implemented outside this library, run through the same helpers |
| `src/examples/03-front-door` | the front door on its own: a listener and a client with one import |
| `src/examples/04-ws-conformance` | the client end of a WebSocket conformance run, for a fuzzing server to drive |
| `src/examples/tls-peer` | a TLS peer for interop runs against OpenSSL and tlsfuzzer |

```
moon run src/examples/tour --target native
```

## Conformance

The adapters are clients, so the evidence is what they carry against implementations they did
not write, over real sockets:

| What | Against | Result |
|:--|:--|:--|
| HTTP/1.1 — a head, a declared-length body, a chunked body with trailers, a body to the close | two independent servers | all exchanges answered, bodies byte for byte |
| HTTP/2 — preface, settings, one exchange per stream, flow control both ways | the same two | all exchanges answered; a reply over one window arrives whole |
| HTTP/3 — QUIC handshake, settings with the QPACK table shut, one stream per exchange | both, where the server offers `h3` | all exchanges answered |
| WebSocket — the upgrade, framing, ping and pong, close, invalid UTF-8, reserved bits | Autobahn's fuzzing server | 244 graded cases pass, 4 of them non-strict; no failures |
| TLS 1.3 over TCP — handshake, certificate chain, alerts | OpenSSL, and tlsfuzzer | OpenSSL interop passes; tlsfuzzer runs in CI |

`scripts/http_interop.sh` is the run behind the first four rows: it starts a server of this
family and one in a container, and asks each of them for HTTP/1.1, HTTP/2 and HTTP/3, plus a
WebSocket message. `scripts/ws_conformance.sh` is the fifth: it starts Autobahn's fuzzing
server and plays its cases with this library's client, and the verdict is the server's report.
Both are jobs in CI, on real sockets, on every push.

The WebSocket run leaves out two sections of the suite: 9.\* measures throughput with messages
from 64 KiB to 16 MiB, and 12.\* and 13.\* exercise permessage-deflate, which this adapter does
not negotiate. The four non-strict cases are 6.4.1–6.4.4, where a message that is not valid
UTF-8 is rejected when the message ends rather than at the first bad octet.

h2spec and h3spec are conformance suites for servers; nothing here serves HTTP/2 or HTTP/3, so
they do not apply to these adapters. The codecs underneath have their own conformance runs.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
