# moonnet

The networking front door: the wire formats under one import, and the
connections that carry them.

> **Status: planned.** The repository is set up; nothing is
> implemented yet.

`moonhttp`, `moontls` and `moonquic` are the formats, and they touch no socket.
This is what sits above them: the same names re-exported so one import is enough,
and the connection layer that makes a request travel.

| Identity | What it does |
|:--|:--|
| Facade | `pub using` re-exports the three libraries unchanged — no renaming, no wrapping |
| Connections | Sockets, the handshake, the retry: what the format libraries deliberately leave out |
| One vocabulary | A request, a response and a stream mean the same thing across HTTP/1, 2 and 3 |

## Install

```bash
moon add moonbitstack/moonnet
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
