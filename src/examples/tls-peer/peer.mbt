// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A TLS peer for interop runs against other implementations: a server that
/// echoes each line it reads, or a client that sends one request and prints
/// what came back. Certificates and keys are PEM files; `scripts/tls_interop.sh`
/// drives both against OpenSSL.
///
///     tls-peer server <port> <chain.pem> <key.pem> [alpn=h2,http/1.1] [suites=aes128,...] [groups=x25519,...] [http]
///     tls-peer client <host> <port> <roots.pem> [sni=name] [alpn=...] [suites=...] [groups=...]
///                     [get=/path | send=text] [update]
///
/// A server line `update` makes the server send a KeyUpdate before echoing it. With `http` the
/// server answers each request head with one response in one write instead of echoing, which is
/// what tlsfuzzer's conversations expect.
/// The client prints `ok suite=... alpn=... bytes=N` and the first line of the
/// answer, or `refused <why>`.
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
fn split(list : String?) -> Array[String]? {
  list.map(text => text.split(",").map(s => s.to_owned()).collect())
}

///|
fn suites_of(names : Array[String]?) -> Array[@record.Suite]? {
  names.map(ns => {
    ns.map(n => {
      match n {
        "aes128" => Aes128Gcm
        "aes256" => Aes256Gcm
        "chacha20" => ChaCha20Poly1305
        other => abort("no such suite: " + other)
      }
    })
  })
}

///|
fn groups_of(names : Array[String]?) -> Array[Int32]? {
  names.map(ns => {
    ns.map(n => {
      match n {
        "x25519" => @ext.x25519
        "x448" => @ext.x448
        "p256" => @ext.secp256r1
        "p384" => @ext.secp384r1
        "p521" => @ext.secp521r1
        "ffdhe2048" => @ext.ffdhe2048
        "ffdhe3072" => @ext.ffdhe3072
        "ffdhe4096" => @ext.ffdhe4096
        "ffdhe6144" => @ext.ffdhe6144
        "ffdhe8192" => @ext.ffdhe8192
        other => abort("no such group: " + other)
      }
    })
  })
}

///|
fn suite_name(suite : @record.Suite?) -> String {
  match suite {
    Some(Aes128Gcm) => "aes128"
    Some(Aes256Gcm) => "aes256"
    Some(ChaCha20Poly1305) => "chacha20"
    None => "-"
  }
}

///|
async fn text_of(path : String) -> String {
  @fs.read_file(path).text() catch {
    e => abort("cannot read \{path}: \{e}")
  }
}

///|
async fn serve(
  port : Int32,
  chain : String,
  key : String,
  opts : Map[String, String],
) -> Unit {
  let config = @tls.Server::new(
    @x509.pems(text_of(chain)),
    @x509.PrivateKey::pem(text_of(key)),
    alpn?=split(opts.get("alpn")),
    suites?=suites_of(split(opts.get("suites"))),
    groups?=groups_of(split(opts.get("groups"))),
  ) catch {
    e => abort("bad server configuration: \{e}")
  }
  println("listening on \{port}")
  @tcp.serve(host="127.0.0.1", port~, tls=config, (conn, _) => {
    let tls = conn.tls()
    println(
      "handshake suite=\{suite_name(tls.bind(t => t.suite()))} alpn=\{conn.alpn().unwrap_or("-")} sni=\{conn.server_name().unwrap_or("-")}",
    )
    if opts.contains("http") {
      let mut head = 0
      while conn.read_until("\n") is Some(line) {
        head = head + 1
        if line.trim_end(chars="\r") == "" {
          conn.write(
            "HTTP/1.0 200 OK\r\ncontent-type: text/plain\r\ncontent-length: \{head}\r\n\r\n" +
            "x".repeat(head),
          )
          head = 0
        }
      }
    } else {
      while conn.read_until("\n") is Some(line) {
        if line.trim_end(chars="\r") == "update" && tls is Some(t) {
          t.update(request=true)
        }
        conn.write(line + "\n")
      }
    }
    conn.shutdown()
  })
}

///|
async fn connect(
  host : String,
  port : Int32,
  roots : String,
  opts : Map[String, String],
) -> Unit {
  let config = @tls.Client::new(
    @x509.Roots::pem(text_of(roots)),
    alpn?=split(opts.get("alpn")),
    suites?=suites_of(split(opts.get("suites"))),
    groups?=groups_of(split(opts.get("groups"))),
  ) catch {
    e => abort("bad client configuration: \{e}")
  }
  let name = opts.get("sni").unwrap_or(host)
  let sock = @socket.Tcp::connect(@socket.Addr::parse("\{host}:\{port}"))
  let conn = @tcp.Conn::client(sock, config, name)
  defer conn.close()
  if opts.contains("update") && conn.tls() is Some(t) {
    t.update(request=true)
  }
  let request = match (opts.get("get"), opts.get("send")) {
    (Some(path), _) => "GET \{path} HTTP/1.0\r\nHost: \{name}\r\n\r\n"
    (None, Some(text)) => text + "\n"
    (None, None) => "ping\n"
  }
  conn.write(request)
  let answer = if opts.contains("get") {
    conn.read_all().binary()
  } else {
    match conn.read_until("\n") {
      Some(line) => @utf8.encode(line)
      None => b""
    }
  }
  let first = @utf8.decode_lossy(answer)
    .split("\n")
    .next()
    .unwrap_or("")
    .to_owned()
  println(
    "ok suite=\{suite_name(conn.tls().bind(t => t.suite()))} alpn=\{conn.alpn().unwrap_or("-")} bytes=\{answer.length()} first=\{first}",
  )
  if !opts.contains("get") {
    conn.shutdown()
  }
}

///|
fn port_of(text : String) -> Int32 {
  @string.parse_int(text) catch {
    _ => abort("not a port: " + text)
  }
}

///|
async fn main {
  match @env.args() {
    [_, "server", port, chain, key, .. rest] =>
      serve(port_of(port), chain, key, options(rest))
    [_, "client", host, port, roots, .. rest] =>
      connect(host, port_of(port), roots, options(rest)) catch {
        e => println("refused \{e}")
      }
    _ =>
      println(
        "usage: tls-peer server <port> <chain.pem> <key.pem> [...] | client <host> <port> <roots.pem> [...]",
      )
  }
}
