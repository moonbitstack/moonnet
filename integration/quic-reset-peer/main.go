// A QUIC server that reports the stream frames it is sent, for scripts/quic_reset.sh.
//
// One connection, three scripted streams, and a line for every frame that matters:
//
//	data <stream> <octets>        STREAM data arrived
//	reset <stream> <code>         RESET_STREAM arrived from the client
//	stop <stream> <code>          STOP_SENDING arrived from the client
//	sent reset <stream> <code>    this side abandoned the stream
//	sent stop <stream> <code>     this side asked the client to stop sending
//	curve <id>                    the key-exchange group the handshake settled on
//
// The curve is worth a line of its own: with the hybrid share the ServerHello is longer than one
// Initial packet, so a client that only ever offers x25519 would pass every other check here
// while skipping the part of the handshake this run exists for. 4588 is X25519MLKEM768.
//
// What the client is told to do is what an application does with those frames: abandon the reply
// to a request it has read, stop reading a stream it has no use for, and stop a stream it cannot
// take any more of. The port is asked for from the system and printed once, since the script
// that drives this reads it back rather than guessing one.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/quic-go/quic-go"
)

func report(format string, args ...any) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
	os.Stdout.Sync()
}

// codeOf is the stream error code an error carries, or 0 when it is not one.
func codeOf(err error) (uint64, bool) {
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return uint64(streamErr.ErrorCode), true
	}
	return 0, false
}

// causeOf is the stream error a cancelled stream context holds.
func causeOf(ctx context.Context) (uint64, bool) {
	return codeOf(context.Cause(ctx))
}

func main() {
	certFile := flag.String("cert", "", "certificate chain, PEM")
	keyFile := flag.String("key", "", "private key, PEM")
	host := flag.String("host", "127.0.0.1", "address to listen on")
	// 1200 is the smallest Initial a QUIC endpoint may send, and it is what any peer that keeps to
	// the datagram minimum will use: a ServerHello carrying the hybrid share then arrives in two
	// datagrams, which is the reassembly this flag exists to exercise.
	initial := flag.Int("initial", 1280, "Initial packet size, in octets")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"moonnet-reset"},
	}
	listener, err := quic.ListenAddr(*host+":0", config, &quic.Config{
		InitialPacketSize: uint16(*initial),
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	report("listening %d", listener.Addr().(*net.UDPAddr).Port)
	defer listener.Close()

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	report("alpn %s", conn.ConnectionState().TLS.NegotiatedProtocol)
	report("curve %d", conn.ConnectionState().TLS.CurveID)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handle(stream)
	}
}

// handle runs one stream's case: read what the client sends, answer as the case says, and report
// how the stream ended.
func handle(stream *quic.Stream) {
	id := stream.StreamID()
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if n > 0 {
		report("data %d %d", id, n)
		switch id {
		case 0:
			// The reply is given up: the client sees RESET_STREAM 99 on its reading half.
			stream.CancelWrite(99)
			report("sent reset %d %d", id, 99)
		case 4:
			// An echo is what tells the client the stream exists here, so the stop it sends
			// next is about a stream this side has, not one it has never seen.
			stream.Write([]byte("echo:" + string(buf[:n])))
		case 8:
			// This side has had enough: the client's next write is refused with 55.
			stream.CancelRead(55)
			report("sent stop %d %d", id, 55)
		}
	}
	_ = err
	if id == 4 {
		// The client's STOP_SENDING cancels this side's writing, with its code.
		<-stream.Context().Done()
		code, _ := causeOf(stream.Context())
		report("stop %d %d", id, code)
		return
	}
	for {
		_, err := stream.Read(buf)
		if err == nil {
			continue
		}
		code, isStream := codeOf(err)
		var streamErr *quic.StreamError
		if isStream && errors.As(err, &streamErr) && !streamErr.Remote {
			// This side cancelled the read; the client's own reset is still to come.
			continue
		}
		if isStream {
			report("reset %d %d", id, code)
		} else {
			report("end %d %v", id, err)
		}
		return
	}
}
