// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A connection the library has never heard of: it answers from a table in memory, which is
/// enough to show that the contract is the whole of what a protocol has to implement, and
/// that the code above it is written against the contract and not against this library.
pub struct Table {
  answers : Map[String, String]
  mut next : Int32
  // The exchange in flight, and whether its one body has been handed out.
  mut target : String
  mut served : Bool
}

///|
pub fn Table::new(answers : Map[String, String]) -> Table {
  { answers, next: 1, target: "", served: false, }
}

///|
pub impl @spec.Conn for Table with fn open(self, request) {
  guard self.answers.get(request.target) is Some(_) else {
    raise @spec.Refused::Unsupported("no answer for \{request.target}")
  }
  self.target = request.target
  self.served = false
  let stream : @spec.Stream = { id: self.next, }
  self.next += 1
  stream
}

///|
pub impl @spec.Conn for Table with fn send(self, at, bytes, end~) {
  let _ = (self, at, bytes, end)
  raise @spec.Refused::Unsupported("a table has no body to take")
}

///|
pub impl @spec.Conn for Table with fn response(self, at) {
  let _ = (self, at)
  { status: 200, fields: [@spec.Field::new("content-type", "text/plain")], }
}

///|
pub impl @spec.Conn for Table with fn read(self, at) {
  let _ = at
  if self.served {
    return None
  }
  self.served = true
  match self.answers.get(self.target) {
    Some(text) => Some(@utf8.encode(text))
    None => None
  }
}

///|
pub impl @spec.Conn for Table with fn trailers(self, at) {
  let _ = (self, at)
  []
}

///|
pub impl @spec.Conn for Table with fn is_ready(self) {
  let _ = self
  true
}

///|
pub impl @spec.Conn for Table with fn kind(self) {
  let _ = self
  "table"
}

///|
pub impl @spec.Conn for Table with fn close(self) {
  let _ = self
}

///|
pub extend Table with @spec.Conn::{
  open,
  send,
  response,
  read,
  trailers,
  is_ready,
  kind,
  close,
}

///|
/// The same code that runs on HTTP/1.1, HTTP/2 and HTTP/3, run over a table.
async fn page(conn : &@spec.Conn, target : String) -> String {
  let stream = conn.open(@spec.Request::new("GET", target))
  let response = conn.response(stream)
  let body = @spec.read_to_end(conn, stream)
  "\{conn.kind()} \{response.status} \{body.length()}: \{@utf8.decode_lossy(body[:])}"
}

///|
async fn main {
  let table = Table::new(
    Map::from_array([("/", "a page from a table"), ("/about", "still a table")]),
  )
  println(page(table, "/"))
  println(page(table, "/about"))
  let refused = try {
    let _ = page(table, "/missing")
    "answered"
  } catch {
    @spec.Unsupported(why) => "refused: \{why}"
    _ => "raised something else"
  }
  println(refused)
}
