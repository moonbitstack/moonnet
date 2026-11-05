// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The client end of a WebSocket conformance run (Autobahn's `fuzzingserver`, which fuzzes
/// clients): the server says how many cases it has, plays them one connection at a time, and
/// writes its verdict into a report this prints the shape of.
///
///     ws-conformance [host] [port]
///
/// What the client does is what any echo client does: text back as text, binary back as
/// binary, and let a protocol violation end the connection rather than the process.

///|
/// One case is given ten seconds; a case that hangs is a failed case, not a stuck run.
let case_timeout : Int32 = 10000

///|
/// The nth argument as a number, or `fallback` when it is missing or not one.
fn int_arg(args : Array[String], at : Int32, fallback : Int32) -> Int32 {
  guard args.length() > at else { return fallback }
  @string.parse_int(args[at]) catch {
    _ => fallback
  }
}

///|
fn port_of(args : Array[String]) -> Int32 {
  guard args.length() > 2 else { return 9001 }
  @string.parse_int(args[2]) catch {
    _ => 9001
  }
}

///|
fn host_of(args : Array[String]) -> String {
  guard args.length() > 1 else { return "127.0.0.1" }
  args[1]
}

///|
/// One WebSocket exchange against `path`, with `body` handled by `answer` until the server
/// closes or the case runs out of time.
async fn with_session(
  host : String,
  port : Int32,
  path : String,
  answer : async (@ws.Conn) -> Unit raise @spec.Refused,
) -> Unit {
  @async.with_timeout(case_timeout, () => {
    let ws = @ws.connect("ws://\{host}:\{port}/")
    let stream = ws.open(@spec.Request::new("GET", path))
    let _ = ws.response(stream)
    answer(ws)
    ws.close()
  }) catch {
    _ => ()
  }
}

///|
/// How many cases the server has.
async fn case_count(host : String, port : Int32) -> Int32 {
  let count : Ref[Int32] = Ref(0)
  with_session(host, port, "/getCaseCount", ws => {
    match ws.next() {
      Some(@frame.Message::Text(text)) =>
        count.val = @string.parse_int(text) catch { _ => 0 }
      _ => ()
    }
  })
  count.val
}

///|
/// Echo until the server closes: the whole of what the client side of these cases is. A server
/// that says nothing for two seconds has finished with the case, so the connection is closed
/// rather than held until the case's own deadline.
async fn echo(ws : @ws.Conn) -> Unit raise @spec.Refused {
  while true {
    let step = Ok(@async.with_timeout(2000, () => ws.next())) catch {
      e => Err(e)
    }
    match step {
      Ok(Some(@frame.Message::Text(text))) => ws.send_text(text)
      Ok(Some(@frame.Message::Binary(bytes))) => ws.send_binary(bytes)
      Ok(Some(@frame.Message::Close(..))) => return
      Ok(None) => return
      // A timeout means the server has finished with the case. A refusal is the session saying
      // why it is over, and that close is already on the wire.
      Err(e) =>
        match e {
          @spec.Refused::Malformed(why) => raise @spec.Refused::Malformed(why)
          @spec.Refused::Unsupported(why) =>
            raise @spec.Refused::Unsupported(why)
          @spec.Refused::Broken(why) => raise @spec.Refused::Broken(why)
          @spec.Refused::Closed => raise @spec.Refused::Closed
          _ => return
        }
    }
  }
}

///|
async fn main {
  let args = @env.args()
  let agent = "moonnet"
  let host = host_of(args)
  let port = port_of(args)
  let count = case_count(host, port)
  let from = int_arg(args, 3, 1)
  let last = int_arg(args, 4, count)
  let to = if last < count { last } else { count }
  println("cases: \{count}, playing \{from}..\{to}")
  for i = from; i <= to; i = i + 1 {
    with_session(host, port, "/runCase?case=\{i}&agent=\{agent}", echo)
    if i % 25 == 0 {
      println("played \{i}")
    }
  }
  // The server writes its verdict when a session asks it to; until then the run is only a set
  // of connections. The request is a WebSocket one, not a plain HTTP one.
  with_session(host, port, "/updateReports?agent=\{agent}", _ws => ())
  println("reports: asked")
}
