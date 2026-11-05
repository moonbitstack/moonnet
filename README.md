# moonnet

The connection layer: one contract for a request and a reply, whatever carries it, and the
sockets underneath.

`moonhttp`, `moontls` and `moonquic` are the wire formats, and they touch no socket. This is
what puts them on one: TCP and UDP, TLS over TCP, QUIC over UDP, and an adapter for each
protocol that turns it into the same `open` / `send` / `response` / `read`.

```moonbit
// One request, whichever of the four carries it.
let conn = @h2.connect("example.com", port=443, tls=@tls.Client::new(@roots.mozilla(), alpn=["h2"]))
let (response, body) = @spec.call(conn, @spec.Request::new("GET", "/"))
println("\{response.status} \{body.length()}")
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

```moonbit nocheck
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

```moonbit
async fn get(conn : &@spec.Conn, path : String) -> String {
  let stream = conn.open(@spec.Request::new("GET", path))
  let response = conn.response(stream)
  let body = @spec.read_to_end(conn, stream)
  "\{response.status} \{body.length()}"
}
```

The same `get` runs on every adapter below. `is_ready` is what a connection that carries one
exchange at a time says about itself: HTTP/1.1 is False while one is in flight, HTTP/2, HTTP/3
and a WebSocket session are True.

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

```moonbit
// A session, and the close the peer gave.
let ws = @ws.connect("wss://example.com/chat", tls=client)
let stream = ws.open(@spec.Request::new("GET", "/chat"))
let _ = ws.response(stream)
ws.send_text("hello")
match ws.next() {
  Some(@frame.Message::Text(reply)) => println(reply)
  Some(@frame.Message::Close(status~, ..)) => println("closed \{status}")
  _ => ()
}
```

## The pool

Connections are kept by what makes two of them interchangeable: the host, the port, and the
protocol ALPN settled on. Every knob is a field of a record with a published preset, so a
caller changes one without guessing at the rest.

```moonbit
let pool = @pool.Pool::new(
  key => @tcp.dial(key.host, port=key.port, tls=tls_for(key)),
  config={ ..@pool.defaults, idle: 60000, max_total: 128 },
)
let key = @pool.Key::new("example.com", 443, alpn="h2")
let conn = pool.get(key)
// ... one connection's worth of work ...
pool.put(key, conn)
```

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

```moonbit
let socket = @udp.bind(port=12000)
socket.send(to, datagram)
let next = socket.recv(timeout=100)

let quic = @udp.dial("example.com", port=443, tls=client)
let stream = quic.open_bi()
quic.write(stream, b"hello", fin=true)
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

```moonbit
@tcp.serve((conn, peer) => {
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
| `src/examples/tls-peer` | a TLS peer for interop runs against OpenSSL and tlsfuzzer |

```
moon run src/examples/tour --target native
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
