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
/// Accept connections on `host:port` and run `handler` on each with the peer's address, after the
/// TLS handshake when `tls` is given. When the handler returns, a TLS connection is shut down with
/// a close_notify. A connection whose handshake fails, or whose handler raises, is closed without
/// stopping the server. Runs until cancelled.
///
/// `limit` caps the connections served at once; the rest wait in the listen queue. `reuse_addr`
/// lets a restarted server bind while the old socket lingers in TIME_WAIT, as uvicorn does.
pub async fn serve(
  handler : async (Conn, @socket.Addr) -> Unit,
  host~ : String = host,
  port~ : Int32 = port,
  tls? : @tls.Server,
  limit? : Int32,
  reuse_addr~ : Bool = true,
) -> Unit {
  let addr = @socket.Addr::parse(join(host, port))
  let server = @socket.TcpServer(addr, reuse_addr~)
  server.run_forever(
    (sock, peer) => {
      let conn = match tls {
        Some(config) => Conn::server(sock, config)
        None => Conn::plain(sock)
      }
      handler(conn, peer)
      conn.shutdown() catch {
        _ => ()
      }
    },
    max_connections?=limit,
  )
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
