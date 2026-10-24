// Concurrent connections, native only: the wasm host's socket table and listen queue are small
// enough that a burst is refused. A hundred at once stays under macOS's default listen queue of
// 128, past which it refuses rather than queueing.

///|
async test "tcp: a hundred TLS clients at once, each with a hundred kilobytes" {
  let size = 100 * 1024
  let handler = async fn(conn : @tcp.Conn, _ : @socket.Addr) {
    conn.write(conn.read_exactly(size))
  }
  with_server(handler, tls=server_config(), port => {
    let done = Ref(0)
    @async.with_task_group(g => {
      for i in 0..<100 {
        g.spawn_bg(() => {
          let conn = @tcp.dial("localhost", port~, tls=client_config())
          defer conn.close()
          let data = Bytes::makei(size, j => ((i + j) % 251).to_byte())
          conn.write(data)
          if conn.read_exactly(size) == data {
            done.val += 1
          }
        })
      }
    })
    assert_eq(done.val, 100)
  })
}

///|
async test "tcp: a dozen clients at once, each answered on its own connection" {
  let handler = async fn(conn : @tcp.Conn, peer : @socket.Addr) {
    echo(conn, peer)
  }
  with_server(handler, tls=server_config(), port => {
    let answers : Array[String] = []
    @async.with_task_group(g => {
      for i in 0..<12 {
        g.spawn_bg(() => {
          let conn = @tcp.dial("localhost", port~, tls=client_config())
          defer conn.close()
          conn.write("client \{i}\n")
          answers.push(conn.read_until("\n").unwrap_or("-"))
        })
      }
    })
    assert_eq(answers.length(), 12)
    for i in 0..<12 {
      assert_true(answers.contains("client \{i}"))
    }
  })
}
