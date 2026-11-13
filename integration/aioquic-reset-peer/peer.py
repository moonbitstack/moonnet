"""A QUIC server that reports the stream frames it is sent, for scripts/quic_reset.sh.

The same three scripted streams as the Go peer next door, on a second implementation: one
connection, and a line for every frame that matters.

    data <stream> <octets>        STREAM data arrived
    reset <stream> <code>         RESET_STREAM arrived from the client
    stop <stream> <code>          STOP_SENDING arrived from the client
    sent reset <stream> <code>    this side abandoned the stream
    sent stop <stream> <code>     this side asked the client to stop sending

One difference is the library's, not this script's: aioquic answers a STOP_SENDING with
RESET_STREAM carrying NO_ERROR before the application is told, and a reset it has already
queued cannot be given another code. An application here that wants a code of its own on a
stream it stops reading has to call `reset_stream` first. The script expects code 0 on that
stream for this peer and code 7 for the Go one, which is a fact about each library worth
keeping visible.

The port is asked for from the system and printed once; the script reads it back rather than
guessing one.
"""

import argparse
import asyncio
import sys
import traceback

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ProtocolNegotiated,
    StreamDataReceived,
    StreamReset,
    StopSendingReceived,
)

ALPN = "moonnet-reset"


def report(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


class Peer(QuicConnectionProtocol):
    """Three streams, answered as the case says, and a line for each frame."""

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            report(f"alpn {event.alpn_protocol}")
        elif isinstance(event, StreamDataReceived):
            self.on_data(event.stream_id, event.data)
        elif isinstance(event, StopSendingReceived):
            # The client's STOP_SENDING cancels this side's writing, with its code. The reset
            # aioquic has queued already carries NO_ERROR, so this is the report, not the frame.
            report(f"stop {event.stream_id} {event.error_code}")
        elif isinstance(event, StreamReset):
            report(f"reset {event.stream_id} {event.error_code}")

    def on_data(self, stream_id, data):
        report(f"data {stream_id} {len(data)}")
        if stream_id == 0:
            # The reply is given up: the client sees RESET_STREAM 99 on its reading half.
            self._quic.reset_stream(stream_id, 99)
            report(f"sent reset {stream_id} 99")
        elif stream_id == 4:
            # An echo is what tells the client the stream exists here, so the stop it sends next
            # is about a stream this side has, not one it has never seen.
            self._quic.send_stream_data(stream_id, b"echo:" + data, end_stream=False)
        elif stream_id == 8:
            # This side has had enough: the client's next write is refused with 55.
            self._quic.stop_stream(stream_id, 55)
            report(f"sent stop {stream_id} 55")
        self.transmit()


async def run(cert, key):
    config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN])
    config.load_cert_chain(cert, key)
    server = await serve("127.0.0.1", 0, configuration=config, create_protocol=Peer)
    report(f"listening {server._transport.get_extra_info('sockname')[1]}")
    await asyncio.Future()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cert", required=True, help="certificate chain, PEM")
    parser.add_argument("--key", required=True, help="private key, PEM")
    args = parser.parse_args()
    try:
        asyncio.run(run(args.cert, args.key))
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
