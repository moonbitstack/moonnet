// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The names this library is used by, in one import: the connection, the datagram socket and
/// the contract. A caller that wants an adapter names that package, so a program that only
/// opens TCP links nothing else.
pub using @tcp {type Conn, type Listener, listen, serve, dial}

///|
pub using @udp {type Socket, bind}

///|
pub using @spec {
  type Body,
  type Field,
  type Refused,
  type Request,
  type Response,
  type Stream,
}

///|
/// What `connect` settled on.
pub(all) struct Opened {
  /// The connection, ready to carry an exchange.
  conn : @tcp.Conn
  /// The protocol ALPN settled on, or `""` in the clear.
  alpn : String
  /// For `http` and `https`: the path and query the URL named, which an HTTP request needs.
  target : String
}

///|
/// Connect to `url` in one line: the scheme decides TLS, the ALPN list is offered, and the
/// chain is judged against the roots the caller passes — Mozilla's when none are given.
///
/// The connection is returned before any protocol is chosen for it: `alpn` says what the
/// server picked, and the matching adapter is the one to hand it to.
///
/// ```moonbit nocheck
/// let opened = @moonnet.connect("https://example.com/", alpn=["h2", "http/1.1"])
/// if opened.alpn == "h2" {
///   let conn = @h2.client(opened.conn, scheme="https", authority="example.com")
///   let (response, body) = @spec.call(conn, @spec.Request::new("GET", opened.target))
///   println("\{response.status} \{body.length()}")
/// }
/// ```
pub async fn connect(
  url : StringView,
  alpn~ : Array[String] = ["h2", "http/1.1"],
  roots? : @x509.Roots,
  now? : Int64,
) -> Opened {
  let parsed = @url.Url::decode(url) catch {
    _ => raise @spec.Refused::Unsupported("a URL this cannot read")
  }
  let secure = match parsed.scheme {
    Some("https") | Some("wss") => true
    Some("http") | Some("ws") => false
    Some(other) =>
      raise @spec.Refused::Unsupported("a scheme this cannot open: \{other}")
    None => raise @spec.Refused::Unsupported("a URL with no scheme")
  }
  guard parsed.host is Some(host) else {
    raise @spec.Refused::Unsupported("a URL with no host")
  }
  let port = parsed.port.unwrap_or(if secure { 443 } else { 80 })
  let target = match parsed.query {
    Some(query) => "\{parsed.path}?\{query}"
    None => parsed.path
  }
  // Forwarded as an option, since `dial` asks for the config rather than for an option of one.
  let tls : @tls.Client? = if secure {
    Some(@tls.Client::new(roots.unwrap_or(@roots.mozilla()), alpn~))
  } else {
    None
  }
  let conn = @tcp.dial(host, port~, tls?, now?)
  { conn, alpn: conn.alpn().unwrap_or(""), target, }
}
