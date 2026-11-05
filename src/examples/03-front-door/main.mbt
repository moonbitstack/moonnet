// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One import does the whole job: `serve` accepts, `connect` dials, and the connection that
/// comes back is read and written directly. `moon run src/examples/03-front-door`.
async fn main {
  @async.with_task_group(g => {
    let serving = g.spawn(() => {
      @moonnet.serve(
        (conn, _peer) => {
          while conn.read_until("\n") is Some(line) {
            conn.write(line + "\n")
          }
        },
        port=12000,
      )
    })
    @async.sleep(100)
    let opened = @moonnet.connect("http://127.0.0.1:12000/")
    println("connected to \{opened.target}")
    opened.conn.write("hello from the front door\n")
    println(opened.conn.read_until("\n").unwrap_or("-"))
    opened.conn.shutdown()
    serving.cancel()
  })
}
