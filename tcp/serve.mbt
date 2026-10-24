// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The address a server listens on when none is given: loopback only, as uvicorn and Starlette
/// default to, so a development server is not reachable from the network by accident.
pub let host : String = "127.0.0.1"

///|
/// The port every server in the family listens on by default.
pub let port : Int32 = 12000

///|
/// How long a TLS handshake may take, in milliseconds: asyncio's and hypercorn's 60 seconds. A
/// peer that connects and never finishes holds a connection slot until then.
pub let handshake : Int32 = 60000

///|
/// A bound, listening socket. Connections queue from the moment `listen` returns, so a caller
/// can connect to it, or hand its port out, without racing the server.
struct Listener {
  server : @socket.TcpServer
  tls : @tls.Server?
  handshake : Int32?
}

///|
/// Bind `host:port` and listen, for TLS connections when `tls` is given. Port 0 asks the system
/// for a free one; `addr` says which. `reuse_addr` lets a restarted server bind while the old
/// socket lingers in TIME_WAIT, as uvicorn does. `handshake` bounds each TLS handshake; `None`
/// waits for ever.
pub async fn listen(
  host~ : String = host,
  port~ : Int32 = port,
  tls? : @tls.Server,
  reuse_addr~ : Bool = true,
  handshake~ : Int32? = Some(handshake),
) -> Listener {
  let server = @socket.TcpServer(
    @socket.Addr::parse(join(host, port)),
    reuse_addr~,
  )
  { server, tls, handshake, }
}

///|
/// The address listened on; with port 0 asked for, the port the system chose.
pub fn Listener::addr(self : Listener) -> @socket.Addr {
  self.server.addr
}

///|
/// A connection as the handler gets it: TLS done within the handshake bound, when there is TLS.
async fn Listener::open(self : Listener, sock : @socket.Tcp) -> Conn {
  guard self.tls is Some(config) else { return Conn::plain(sock) }
  match self.handshake {
    Some(ms) => @async.with_timeout(ms, () => Conn::server(sock, config))
    None => Conn::server(sock, config)
  }
}

///|
/// The next connection and its peer's address, after the TLS handshake when there is TLS. A
/// handshake that fails or runs out of time raises, with the socket closed.
pub async fn Listener::accept(self : Listener) -> (Conn, @socket.Addr) {
  let (sock, peer) = self.server.accept()
  errdefer sock.close()
  (self.open(sock), peer)
}

///|
/// Run `handler` on each connection with the peer's address. When the handler returns, a TLS
/// connection is shut down with a close_notify. A connection whose handshake fails, or whose
/// handler raises, is closed without stopping the server. Runs until cancelled, then closes the
/// listener.
///
/// `limit` caps the connections served at once; the rest wait in the listen queue.
pub async fn Listener::serve(
  self : Listener,
  handler : async (Conn, @socket.Addr) -> Unit,
  limit? : Int32,
) -> Unit {
  self.server.run_forever(
    (sock, peer) => {
      let conn = self.open(sock)
      handler(conn, peer)
      conn.shutdown() catch {
        _ => ()
      }
    },
    max_connections?=limit,
  )
}

///|
/// Stop listening.
pub fn Listener::close(self : Listener) -> Unit {
  self.server.close()
}

///|
/// `listen`, then `serve`: accept connections on `host:port` and run `handler` on each until
/// cancelled.
pub async fn serve(
  handler : async (Conn, @socket.Addr) -> Unit,
  host~ : String = host,
  port~ : Int32 = port,
  tls? : @tls.Server,
  limit? : Int32,
  reuse_addr~ : Bool = true,
  handshake~ : Int32? = Some(handshake),
) -> Unit {
  listen(host~, port~, tls?, reuse_addr~, handshake~).serve(handler, limit?)
}

///|
/// Connect to `host:port`, under TLS when `tls` is given, and return once the handshake is done.
/// The host is resolved, then names the server for SNI and for checking its certificate.
pub async fn dial(
  host : String,
  port~ : Int32,
  tls? : @tls.Client,
  now? : Int64,
) -> Conn {
  let sock = @socket.Tcp::connect_to_host(host, port~)
  errdefer sock.close()
  match tls {
    Some(config) => Conn::client(sock, config, host, now?)
    None => Conn::plain(sock)
  }
}

///|
/// `host:port`, with an IPv6 literal in brackets (RFC 3986 §3.2.2).
fn join(host : String, port : Int32) -> String {
  if host.contains(":") && !host.has_prefix("[") {
    "[\{host}]:\{port}"
  } else {
    "\{host}:\{port}"
  }
}
