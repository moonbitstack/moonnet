// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Send `request` and read the whole reply, body included. The body is held in memory,
/// so this is for replies of a bounded size; a reply read as it arrives goes through the
/// methods of the contract one at a time.
pub async fn call(conn : &Conn, request : Request) -> (Response, Bytes) {
  let stream = conn.open(request)
  let response = conn.response(stream)
  (response, read_to_end(conn, stream, limit=16384 * 1024))
}

///|
/// Read the rest of an exchange's body and join it into one run of octets. `limit` is
/// the most this will hold: a reply larger than that is refused rather than buffered
/// without end.
pub async fn read_to_end(
  conn : &Conn,
  stream : Stream,
  limit~ : Int32 = 16384 * 1024,
) -> Bytes {
  let buffer = @buffer.Buffer::Buffer(size_hint=1024)
  while conn.read(stream) is Some(chunk) {
    if buffer.length() + chunk.length() > limit {
      raise Refused::Unsupported(
        "a body larger than the limit this reader holds",
      )
    }
    buffer.write_bytes(chunk)
  }
  buffer.to_bytes()
}

///|
/// Every field of a head as one lower-cased name to its value, the last one winning, as
/// a map lookup would.
pub fn table(fields : Array[Field]) -> Map[String, String] {
  let table : Map[String, String] = Map([])
  for field in fields {
    table[field.key()] = field.value
  }
  table
}

///|
/// `name: value` lines, the form a head is shown in by a person reading a log.
pub fn lines(fields : Array[Field]) -> String {
  let parts : Array[String] = []
  for field in fields {
    parts.push("\{field.name}: \{field.value}")
  }
  parts.join("\r\n")
}
