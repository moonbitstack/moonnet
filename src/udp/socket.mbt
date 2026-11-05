// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A datagram socket. One task may receive while others send; two tasks receiving at once
/// would each take half the datagrams, so a connection that needs one reader keeps one.
pub struct Socket {
  sock : @socket.UdpServer
}

///|
/// Bind `host:port`. Port 0 asks the system for a free one, which `addr` reports.
pub async fn bind(
  host~ : String = "127.0.0.1",
  port~ : Int32 = 12000,
) -> Socket {
  { sock: @socket.UdpServer::UdpServer(@socket.Addr::parse(join(host, port))), }
}

///|
/// The address bound; with port 0 asked for, the port the system chose.
pub fn Socket::addr(self : Socket) -> @socket.Addr {
  self.sock.addr
}

///|
/// Send one datagram.
pub async fn Socket::send(
  self : Socket,
  to : @socket.Addr,
  bytes : Bytes,
) -> Unit {
  self.sock.sendto(bytes, to)
}

///|
/// The next datagram, or `None` when `timeout` milliseconds pass first. Without a timeout
/// it waits for one, which is what a server does and a client polling a handshake does not.
pub async fn Socket::recv(
  self : Socket,
  max~ : Int32 = 65535,
  timeout? : Int32,
) -> (Bytes, @socket.Addr)? {
  let buffer = FixedArray::make(max, b'\x00')
  let take = async fn() {
    let (n, from) = self.sock.recvfrom(buffer)
    (Bytes::makei(n, i => buffer[i]), from)
  }
  match timeout {
    Some(ms) => @async.with_timeout_opt(ms, take)
    None => Some(take())
  }
}

///|
/// Stop using the socket.
pub fn Socket::close(self : Socket) -> Unit {
  self.sock.close()
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
