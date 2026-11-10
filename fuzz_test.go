package fasth2

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func init() { panicHook = func(r any) { panic(r) } } // surface panics in tests

// ---- HPACK ----

func FuzzHPACKDecode(f *testing.F) {
	f.Add([]byte{0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'})
	f.Add([]byte{0x3f, 0xe1, 0x1f, 0x82})                                                // table size update
	f.Add([]byte{0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x01, 'v'}) // huffman name
	f.Add([]byte{0xbe, 0xff, 0xff, 0xff, 0x0f})                                          // huge index
	f.Fuzz(func(t *testing.T, data []byte) {
		d := newDecoder()
		for i := 0; i < 2; i++ { // decoder is stateful: decode twice
			var arena []byte
			var fields []HeaderField
			_, _ = d.decode(data, &arena, &fields, 1<<30)
			if d.size > d.maxSize || d.maxSize > d.allowed {
				t.Fatalf("table invariant broken: size=%d max=%d allowed=%d", d.size, d.maxSize, d.allowed)
			}
		}
	})
}

// Test-only Huffman encoder (RFC 7541 Appendix B) for round-trip checks.
func huffmanEncode(src []byte) []byte {
	var out []byte
	var acc uint64
	var n uint
	for _, b := range src {
		acc = acc<<huffmanCodeLens[b] | uint64(huffmanCodes[b])
		n += uint(huffmanCodeLens[b])
		for n >= 8 {
			n -= 8
			out = append(out, byte(acc>>n))
		}
	}
	if n > 0 { // pad with the EOS prefix (all ones)
		out = append(out, byte(acc<<(8-n))|byte(0xff>>n))
	}
	return out
}

func FuzzHuffmanRoundTrip(f *testing.F) {
	f.Add([]byte("www.example.com"))
	f.Add([]byte{0, 1, 2, 255, 254})
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, s []byte) {
		got, err := huffmanDecode(nil, huffmanEncode(s))
		if err != nil || !bytes.Equal(got, s) {
			t.Fatalf("round trip %q -> %q, %v", s, got, err)
		}
	})
}

func FuzzHuffmanDecode(f *testing.F) {
	f.Add([]byte{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := huffmanDecode(nil, data)
		if err == nil && !bytes.Equal(huffmanEncode(out), data) {
			t.Fatalf("accepted non-canonical input %x -> %q", data, out)
		}
	})
}

// ---- whole connection: arbitrary frames after a valid preface ----

func frame(typ, flags byte, sid uint32, payload []byte) []byte {
	b := appendFrameHeader(nil, len(payload), typ, flags, sid)
	return append(b, payload...)
}

var getBlock = []byte{0x82, 0x86, 0x84, 0x41, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'}
var postBlock = []byte{0x83, 0x86, 0x84, 0x41, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func connSeeds() [][]byte {
	cat := func(fs ...[]byte) []byte { return bytes.Join(fs, nil) }
	return [][]byte{
		frame(frHeaders, flEndHeaders|flEndStream, 1, getBlock),
		cat(frame(frHeaders, flEndHeaders, 1, postBlock), frame(frData, 0, 1, []byte("hello")),
			frame(frData, flEndStream|flPadded, 1, []byte{2, 'x', 0, 0})),
		cat(frame(frHeaders, flEndStream, 3, getBlock[:4]), frame(frContinuation, flEndHeaders, 3, getBlock[4:])),
		cat(frame(frSettings, 0, 0, []byte{0, 4, 0, 0, 0, 1}), frame(frHeaders, flEndHeaders|flEndStream, 1, getBlock),
			frame(frWindowUpdate, 0, 1, u32(5)), frame(frWindowUpdate, 0, 0, u32(5))),
		cat(frame(frPing, 0, 0, make([]byte, 8)), frame(frPriority, 0, 5, []byte{0, 0, 0, 1, 16}),
			frame(frRSTStream, 0, 1, u32(8)), frame(frGoAway, 0, 0, make([]byte, 8))),
		cat(frame(frHeaders, flEndHeaders, 1, postBlock), frame(frRSTStream, 0, 1, u32(8)),
			frame(frData, flEndStream, 1, []byte("late"))),
		cat(frame(frHeaders, flEndHeaders|flEndStream|flPriority, 1, append([]byte{0, 0, 0, 1, 16}, getBlock...))),
		{0, 0, 0, 0xee, 0xff, 0, 0, 0, 1}, // unknown frame type
	}
}

func runFuzzConn(t *testing.T, async bool, data []byte) {
	srvSide, cliSide := net.Pipe()
	s := &Server{Async: async, MaxConcurrentStreams: 100, MaxRequestBodySize: 1 << 20,
		Handler: func(req *Request, resp *Response) {
			resp.AddHeader("x-path", string(req.Path))
			resp.Write(req.Body)
			resp.WriteString("ok")
		}}
	done := make(chan struct{})
	go func() { s.ServeConn(srvSide); close(done) }()
	go io.Copy(io.Discard, cliSide)
	cliSide.SetWriteDeadline(time.Now().Add(2 * time.Second))
	cliSide.Write([]byte(clientPreface))
	cliSide.Write(frame(frSettings, 0, 0, nil))
	cliSide.Write(data)
	cliSide.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection goroutine did not exit (hang)")
	}
}

func FuzzConnInline(f *testing.F) {
	for _, s := range connSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) { runFuzzConn(t, false, data) })
}

func FuzzConnAsync(f *testing.F) {
	for _, s := range connSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) { runFuzzConn(t, true, data) })
}
