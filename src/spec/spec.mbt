// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One field of a message head: the name, and the value, as they go on the wire.
#derive(Eq, Debug)
pub(all) struct Field {
  name : String
  value : String
}

///|
pub extend Field with Eq::{equal, not_equal}

///|
pub extend Field with Debug::{to_repr}

///|
pub fn Field::new(name : String, value : String) -> Field {
  { name, value, }
}

///|
/// The name in the form a comparison uses: HTTP field names are case-insensitive
/// (RFC 9110 §5.1), and a lower-case copy is what every lookup compares.
pub fn Field::key(self : Field) -> String {
  self.name.to_lower()
}

///|
/// Where a message's body comes from.
#derive(Eq, Debug)
pub(all) enum Body {
  /// No body: the message ends where its head does.
  Empty
  /// A body that is at hand, sent in full before the reply is read.
  Bytes(Bytes)
  /// A body the caller sends with `send` after the exchange is open, in pieces whose
  /// length is not known when the head goes out.
  Streaming
}

///|
pub extend Body with Eq::{equal, not_equal}

///|
pub extend Body with Debug::{to_repr}

///|
/// A request: what to ask for, and what to carry along.
#derive(Eq, Debug)
pub(all) struct Request {
  verb : String
  target : String
  fields : Array[Field]
  body : Body
}

///|
pub extend Request with Eq::{equal, not_equal}

///|
pub extend Request with Debug::{to_repr}

///|
pub fn Request::new(
  verb : String,
  target : String,
  fields~ : Array[Field] = [],
  body~ : Body = Empty,
) -> Request {
  { verb, target, fields, body, }
}

///|
/// A reply head: the status and the fields. The body is read through the connection,
/// because it may be larger than anything worth holding at once.
#derive(Eq, Debug)
pub(all) struct Response {
  status : Int32
  fields : Array[Field]
}

///|
pub extend Response with Eq::{equal, not_equal}

///|
pub extend Response with Debug::{to_repr}

///|
/// One exchange on a connection, named by the connection rather than by the protocol
/// underneath: on a connection that carries one exchange at a time it is 1, and on one
/// that multiplexes it is whatever that connection gave out.
#derive(Eq, Debug)
pub(all) struct Stream {
  id : Int32
}

///|
pub extend Stream with Eq::{equal, not_equal}

///|
pub extend Stream with Debug::{to_repr}

///|
/// What a connection will not do.
#derive(Eq, Debug)
pub(all) suberror Refused {
  /// The peer's octets are not what the protocol allows.
  Malformed(String)
  /// The request, or the peer, asks for something this connection does not do.
  Unsupported(String)
  /// The connection ended before the exchange did.
  Closed
  /// The socket failed under the connection.
  Broken(String)
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
/// The one contract a connection presents, whatever carries it: HTTP/1.1, HTTP/2,
/// HTTP/3 or WebSocket. Code written against this runs on any of them; an
/// implementation is all a new protocol needs.
///
/// An exchange is opened, the request body is sent through it, and the reply's head and
/// body are read from it. A connection that carries one exchange at a time says so
/// through `is_ready`, which a caller waits on before opening the next.
pub(open) trait Conn {
  /// Open an exchange on `request`, and send its head and whatever body came with it.
  async fn open(self : Self, request : Request) -> Stream

  /// Send more of the request's body; `end` marks the last of it. Only an exchange
  /// opened with `Body::Streaming` takes this.
  async fn send(self : Self, stream : Stream, bytes : Bytes, end~ : Bool) -> Unit

  /// The reply's head, once the peer has sent it.
  async fn response(self : Self, stream : Stream) -> Response

  /// The next run of the reply's body, read as it arrives; `None` ends it.
  async fn read(self : Self, stream : Stream) -> Bytes?

  /// The fields that came after the body, once `read` has ended it.
  fn trailers(self : Self, stream : Stream) -> Array[Field]

  /// Whether another exchange can start on this connection now. False while one is in
  /// flight on a connection that carries them one at a time, and after it has ended.
  fn is_ready(self : Self) -> Bool

  /// The protocol the connection settled on, as ALPN names it: `http/1.1`, `h2`, `h3`.
  fn kind(self : Self) -> String

  /// End the connection, in whatever way the protocol under it asks for.
  async fn close(self : Self) -> Unit
}

///|
/// The first field named `name`, matched without regard to case.
pub fn find(fields : Array[Field], name : String) -> String? {
  let key = name.to_lower()
  for field in fields {
    if field.key() == key {
      return Some(field.value)
    }
  }
  None
}

///|
pub fn Request::field(self : Request, name : String) -> String? {
  find(self.fields, name)
}

///|
pub fn Response::field(self : Response, name : String) -> String? {
  find(self.fields, name)
}
