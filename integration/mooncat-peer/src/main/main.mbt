// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An app for moonnet's interop runs: `/` answers with the protocol, the method and the size
/// of the body it was given; `/echo` echoes whatever it is sent; a WebSocket session echoes
/// every message back.
///
///     mooncat-peer <port> <chain.pem> <key.pem>
///
/// Both halves of the server run at once: TLS over TCP for HTTP/1.1, HTTP/2 and WebSocket,
/// and QUIC on the same port for HTTP/3.
async fn app(
  scope : @moonasgi.Scope,
  receive : @moonasgi.Receive,
  send : @moonasgi.Send,
) -> Unit {
  match scope {
    WebSocket(_) =>
      for ;; {
        match receive() {
          WebSocketConnect =>
            send(@moonasgi.Event::WebSocketAccept(subprotocol=None, headers=[]))
          WebSocketReceive(text=Some(text), ..) =>
            send(@moonasgi.Event::WebSocketSendText(text))
          WebSocketReceive(bytes=Some(bytes), ..) =>
            send(@moonasgi.Event::WebSocketSendBytes(bytes))
          WebSocketDisconnect(..) => break
          _ => ()
        }
      }
    Http(http) => {
      let mut held = 0
      let mut echo = b""
      for ;; {
        guard receive() is HttpRequest(body~, more_body~) else { return }
        held = held + body.length()
        if http.path == "/echo" {
          echo = echo + body
        }
        if !more_body {
          break
        }
      }
      let line = if http.path == "/echo" {
        echo
      } else {
        @utf8.encode("\{http.http_version} \{http.http_method} \{http.path} \{held}\n")
      }
      send(
        @moonasgi.Event::HttpResponseStart(
          status=200,
          headers=[("content-type", "text/plain")],
          trailers=false,
        ),
      )
      send(@moonasgi.Event::HttpResponseBody(body=line, more_body=false))
    }
    _ => ()
  }
}

///|
async fn main {
  let args = @env.args()
  guard args.length() >= 4 else {
    println("usage: mooncat-peer <port> <chain.pem> <key.pem>")
    return
  }
  let port = @string.parse_int(args[1]) catch {
    _ => 12000
  }
  let cert = @mooncat.TlsCert::pem(args[2], args[3])
  let config = @mooncat.Config::new(host="127.0.0.1", port~)
  // The HTTP/3 entry point serves TLS over TCP beside it, on the same port: HTTP/1.1, HTTP/2
  // and WebSocket on the one, HTTP/3 on the other.
  @quic.serve_config(app, config, cert)
}
