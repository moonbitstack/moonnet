// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A QUIC stream, abandoned and refused, against a peer of another implementation. Three
/// exchanges run on one connection, each a case the RFC names:
///
///     quic-reset <host> <port> [ca=<pem file>] [insecure]
///
/// 1. `hello` on a stream this side then abandons: the peer's half is reset with 99, and this
///    side sends RESET_STREAM with 42 (RFC 9000 §19.4).
/// 2. `abc` on a stream this side then asks the peer to stop sending on, with 7 (§19.5); the
///    peer answers with a reset of its own.
/// 3. `ping` on a stream the peer asks *this* side to stop sending on, with 55: the next write
///    is refused with that code, and the RESET_STREAM §3.5 requires goes back.
///
/// Every line printed here is a fact about this side; `scripts/quic_reset.sh` holds what the
/// peer reported beside it.

///|
/// One option of the form `name=value`, which is the only shape the command line has.
fn option(args : Array[String], name : String) -> String? {
  let prefix = name + "="
  for arg in args {
    if arg.has_prefix(prefix) {
      return Some(arg[prefix.length():].to_owned())
    }
  }
  None
}

///|
/// Turn the connection until `done` holds, and answer whether it does.
async fn until(
  quic : @udp.Quic,
  done : () -> Bool,
  rounds~ : Int32 = 500,
) -> Bool {
  let mut left = rounds
  while left > 0 {
    if done() {
      return true
    }
    ignore(quic.step(timeout=20) catch { _ => false })
    left -= 1
  }
  done()
}

///|
/// What the peer said about `stream`, as one line, or `None` while it has said nothing.
fn refused_line(quic : @udp.Quic, stream : UInt64) -> String? {
  match quic.refused(stream) {
    Some(@udp.QuicRefused::Reset(code)) => Some("peer reset \{code}")
    Some(@udp.QuicRefused::Stopped(code)) => Some("peer stop \{code}")
    _ => None
  }
}

///|
async fn run(host : String, port : Int32, ca : String, insecure : Bool) -> Unit {
  let roots = @x509.Roots::new(certs=@x509.pems(ca)[:])
  // The hybrid key share's ServerHello is longer than one Initial packet, and this client does
  // not complete a handshake against a peer of another implementation when it is offered; the
  // script drives it with x25519 alone until that is fixed.
  let tls = if insecure {
    @tls.Client::new(
      roots,
      alpn=["moonnet-reset"],
      groups=[@ext.x25519],
      verify=@tls.Verify::Custom((_, _) => ()),
    )
  } else {
    @tls.Client::new(roots, alpn=["moonnet-reset"], groups=[@ext.x25519])
  }
  let quic = @udp.dial(host, port~, tls~)
  println("alpn \{quic.alpn().unwrap_or("none")}")

  // 1. An exchange this side abandons: the peer resets its half, this side resets its own.
  let first = quic.open_bi()
  quic.write(first, @utf8.encode("hello"), fin=false)
  if until(quic, () => refused_line(quic, first) is Some(_)) {
    println(
      "stream \{first}: \{refused_line(quic, first).unwrap_or("nothing")}",
    )
  }
  quic.reset(first, code=42UL)
  println("stream \{first}: reset sent 42")

  // 2. A stream this side stops reading: the peer's code comes back as the reset on it.
  let second = quic.open_bi()
  quic.write(second, @utf8.encode("abc"), fin=false)
  let echoed : Ref[Bytes] = Ref(b"")
  if until(quic, () => {
      let more = quic.take(second) catch { _ => b"" }
      echoed.val = echoed.val + more
      more.length() > 0
    }) {
    println("stream \{second}: echo \{@utf8.decode_lossy(echoed.val[:])}")
  }
  quic.stop(second, code=7UL)
  println("stream \{second}: stop sent 7")
  if until(quic, () => refused_line(quic, second) is Some(_)) {
    println(
      "stream \{second}: \{refused_line(quic, second).unwrap_or("nothing")}",
    )
  }

  // 3. A stream the peer stops: the write after it is refused with the peer's code, and the
  //    reset §3.5 owes goes back without being asked for.
  let third = quic.open_bi()
  quic.write(third, @utf8.encode("ping"), fin=false)
  if until(quic, () => refused_line(quic, third) is Some(_)) {
    println(
      "stream \{third}: \{refused_line(quic, third).unwrap_or("nothing")}",
    )
  }
  let refused = try {
    quic.write(third, @utf8.encode("again"))
    "no"
  } catch {
    @udp.QuicRefused::Stopped(code) => "\{code}"
    @udp.QuicRefused::Reset(code) => "\{code}"
    _ => "another"
  }
  println("stream \{third}: write refused \{refused}")

  // Enough turns for the peer to see the frames above; the script reads its report.
  ignore(until(quic, () => false, rounds=20))
  quic.close()
  println("done")
}

///|
async fn main {
  let args = @env.args()
  guard args.length() >= 3 else {
    println("usage: quic-reset <host> <port> [ca=<pem file>]")
    return
  }
  let port = @string.parse_int(args[2]) catch {
    _ => {
      println("usage: quic-reset <host> <port> [ca=<pem file>]")
      return
    }
  }
  let ca = match option(args, "ca") {
    Some(path) => @fs.read_file(path).text()
    None => ""
  }
  if ca.length() == 0 {
    println("a certificate to trust is required: pass ca=<pem file>")
    return
  }
  let insecure = args.any(arg => arg == "insecure")
  run(args[1], port, ca, insecure) catch {
    @udp.QuicRefused::Broken(why) => println("refused broken: \{why}")
    @udp.QuicRefused::Timeout => println("refused timeout")
    @udp.QuicRefused::Closed => println("refused closed")
    @udp.QuicRefused::Reset(code) => println("refused reset \{code}")
    @udp.QuicRefused::Stopped(code) => println("refused stopped \{code}")
    _ => println("refused")
  }
}
