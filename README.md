# moonnet

The networking front door: the wire formats under one import, and the
connections that carry them.

`moonhttp`, `moontls` and `moonquic` are the formats, and they touch no socket.
This is what sits above them: the connection layer that puts them on a socket,
and in time the same names re-exported so one import is enough.

```moonbit
// A TLS server: the handshake is done before the handler sees the connection.
let tls = @tls.Server::new(@x509.pems(cert_pem), @x509.PrivateKey::pem(key_pem), alpn=["h2", "http/1.1"])
@tcp.serve(tls~, (conn, peer) => {
  while conn.read_until("\n") is Some(line) {
    conn.write(line + "\n")
  }
})

// A client: resolved, connected, the chain judged against the roots.
let conn = @tcp.dial("example.com", port=443, tls=@tls.Client::new(@roots.mozilla(), alpn=["http/1.1"]))
conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
```

`Conn` is an `@io.Reader` and an `@io.Writer` whether it is encrypted or not,
so code written against the async stream traits serves both. Run
`moon run src/examples/tour --target native` for a server and a client talking over
TLS 1.3 in one go.

## Packages

| Package | What it does | State |
|:--:|:--|:--:|
| `tcp` | TCP and TLS over TCP: a connection that reads and writes the same either way, the listener and accept loop, the dialler, a sniff that tells an HTTP/2 preface from an HTTP/1.1 request without consuming it, and TLS and the clear on one port | **0.1.3** |

Planned, in order: one contract for a request, a response and a stream across
HTTP/1, 2 and 3 with adapters for each; UDP and QUIC; the facade that
re-exports the three format libraries.

## The connection

|  | |
|:--|:--|
| `Conn::plain(sock)` | A socket in the clear |
| `Conn::server(sock, config)` | The server side of TLS, returned after the handshake |
| `Conn::client(sock, config, host)` | The client side, returned after the server's chain is judged |
| `starts_with(prefix)` | Whether the stream opens with `prefix`; reads only as far as the first byte that differs |
| `opens_tls()` | Whether the stream opens with a TLS handshake record, without consuming it |
| `secure(config)` | The server side of TLS on a connection still in the clear, starting from what a sniff read ahead |
| `alpn()`, `server_name()`, `peer()` | What the handshake settled; `None` and empty in the clear |
| `shutdown()`, `close()` | close_notify, then the socket |

One task may read while another writes. Writes are serialised, so concurrent
writers put whole messages on the wire and TLS records stay in sequence.

`serve` listens on `127.0.0.1:12000` unless told otherwise: loopback, as uvicorn
and Starlette default to, and the family's port. A connection whose handshake
or handler fails is closed without stopping the server, and a TLS handshake has
60 seconds to finish, as in asyncio and hypercorn.

`listen` is `serve` in two steps: it returns once the socket is bound, so a
caller can connect at once or hand out the port; port 0 asks the system for a
free one, which `addr()` reports. `accept` and `serve` then take connections.

```moonbit
let listener = @tcp.listen(port=0, tls~)
let port = listener.addr().port()
listener.serve((conn, peer) => ...)
```

`listen(tls~, cleartext=true)` serves TLS and the clear on one port: a connection that opens with a TLS handshake record is secured, any other stays in the clear. Without it a TLS listener takes TLS only.

The sockets are `moonbitlang/async`'s, which exist on the native and wasm
backends; on js and wasm-gc the package is empty.

## Install

```bash
moon add moonbitstack/moonnet
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
