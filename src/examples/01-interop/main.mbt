// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A client that speaks each protocol through the one contract. Its output is what
/// `scripts/http_interop.sh` compares, so the same four lines must come back whatever
/// carried them.
///
///     http-peer h1 <url> [ca=<pem file>] [insecure] [body=<bytes>]
///     http-peer h2 <url> [ca=<pem file>] [insecure] [body=<bytes>]
///     http-peer h3 <url> [ca=<pem file>] [insecure] [body=<bytes>]
///     http-peer ws <url> [ca=<pem file>] [insecure] [message=<text>]
///
/// Prints `status <code>`, `alpn <name>`, `body <text>` (or `message <text>` for a session),
/// and `refused <why>` when the server would not have it.

///|
fn options(args : ArrayView[String]) -> Map[String, String] {
  let out = Map([])
  for arg in args {
    match arg.find("=") {
      Some(i) => out[arg[:i].to_owned()] = arg[i + 1:].to_owned()
      None => out[arg] = ""
    }
  }
  out
}

///|
/// The TLS client for `mode`, trusting `ca` when one is named and judging nothing when
/// `insecure` is: this is a test peer, and the scripts that drive it say so on the command
/// line.
async fn tls_client(
  mode : String,
  options : Map[String, String],
) -> @tls.Client {
  let alpn = match mode {
    "h1" => ["http/1.1"]
    "h2" => ["h2"]
    "h3" => ["h3"]
    "ws" => ["http/1.1"]
    _ => ["http/1.1"]
  }
  let roots = match options.get("ca") {
    Some(path) => @x509.Roots::pem(@fs.read_file(path).text())
    None => @roots.mozilla()
  }
  if options.contains("insecure") {
    @tls.Client::new(roots, alpn~, verify=@tls.Verify::Custom((_, _) => ()))
  } else {
    @tls.Client::new(roots, alpn~)
  }
}

///|
async fn main {
  let args = @env.args()
  guard args.length() >= 3 else {
    println(
      "usage: http-peer <h1|h2|h3|ws> <url> [ca=<pem>] [insecure] [body=<bytes>] [message=<text>]",
    )
    return
  }
  let mode = args[1]
  let url = args[2]
  let options = options(args[3:])
  let parsed = @url.Url::decode(url) catch {
    _ => {
      println("refused a URL this cannot read")
      return
    }
  }
  guard parsed.host is Some(host) else {
    println("refused a URL with no host")
    return
  }
  let port = parsed.port.unwrap_or(
    if parsed.scheme is Some("https") || parsed.scheme is Some("wss") {
      443
    } else {
      80
    },
  )
  let secure = parsed.scheme is Some("https") || parsed.scheme is Some("wss")
  let target = match parsed.query {
    Some(query) => "\{parsed.path}?\{query}"
    None => parsed.path
  }
  let body = match options.get("body") {
    Some(size) => sized_body(size)
    None => b""
  }
  try {
    match mode {
      "h1" =>
        with_tls(secure, mode, options, tls => {
          let conn = @h1.connect(host, port~, tls?)
          let (response, payload) = @spec.call(
            conn,
            @spec.Request::new(
              if body.length() > 0 {
                "POST"
              } else {
                "GET"
              },
              target,
              body=if body.length() > 0 {
                @spec.Body::Bytes(body)
              } else {
                @spec.Body::Empty
              },
            ),
          )
          print(conn.kind(), response.status, payload)
          conn.close()
        })
      "h2" =>
        with_tls(secure, mode, options, tls => {
          let conn = @h2.connect(host, port~, tls?)
          let (response, payload) = @spec.call(conn, request_of(target, body))
          print(conn.kind(), response.status, payload)
          conn.close()
        })
      "h3" =>
        with_tls(secure, mode, options, tls => {
          guard tls is Some(client) else {
            println("refused h3 needs TLS")
            return
          }
          let conn = @h3.connect(host, port~, tls=client)
          let (response, payload) = @spec.call(conn, request_of(target, body))
          print(conn.kind(), response.status, payload)
          conn.close()
        })
      "ws" =>
        with_tls(secure, mode, options, tls => {
          let conn = @ws.connect(url, tls?)
          let stream = conn.open(
            @spec.Request::new("GET", target, fields=[
              @spec.Field::new("Sec-WebSocket-Protocol", "echo"),
            ]),
          )
          let response = conn.response(stream)
          let text = options.get("message").unwrap_or("hello")
          conn.send_text(text)
          let answer = match conn.next() {
            Some(@frame.Message::Text(got)) => got
            Some(@frame.Message::Binary(got)) => @utf8.decode_lossy(got[:])
            Some(@frame.Message::Close(status~, ..)) => "closed \{status}"
            None => "closed"
          }
          println("status \{response.status}")
          println("message \{answer}")
          conn.close()
        })
      _ => println("refused a mode this does not know: \{mode}")
    }
  } catch {
    @spec.Refused::Malformed(why) => println("refused \{why}")
    @spec.Refused::Unsupported(why) => println("refused \{why}")
    @spec.Refused::Closed => println("refused closed")
    @spec.Refused::Broken(why) => println("refused \{why}")
    e => println("refused \{e}")
  }
}

///|
fn request_of(target : String, body : Bytes) -> @spec.Request {
  if body.length() > 0 {
    @spec.Request::new("POST", target, body=@spec.Body::Bytes(body))
  } else {
    @spec.Request::new("GET", target)
  }
}

///|
fn print(kind : String, status : Int32, payload : Bytes) -> Unit {
  println("status \{status}")
  println("alpn \{kind}")
  println("body \{@utf8.decode_lossy(payload[:])}")
}

///|
/// A body of `size` octets that a person can see the shape of: the letters of the alphabet,
/// over and over.
fn sized_body(size : String) -> Bytes {
  let count = parse_size(size)
  Bytes::makei(count, i => (i % 26 + 97).to_byte())
}

///|
fn parse_size(text : StringView) -> Int32 {
  let mut n = 0
  let mut i = 0
  while i < text.length() && text[i].to_int() >= 48 && text[i].to_int() <= 57 {
    n = n * 10 + (text[i].to_int() - 48)
    i = i + 1
  }
  n
}

///|
async fn with_tls(
  secure : Bool,
  mode : String,
  options : Map[String, String],
  body : async (@tls.Client?) -> Unit,
) -> Unit {
  if secure {
    body(Some(tls_client(mode, options)))
  } else {
    body(None)
  }
}
