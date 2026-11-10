package fasth2

// Regression tests for the security review of 2026-11-10. They target the
// async mode and the net/http adapter (ConfigureServer), and assert protocol
// behaviour rather than timings, so they stay stable under -race.

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- client helpers ----

type tframe struct {
	typ, flags byte
	sid        uint32
	p          []byte
}

type tclient struct {
	t       *testing.T
	nc      net.Conn
	frames  chan tframe
	eof     chan struct{}
	backlog []tframe // received frames no await has matched yet
}

func secSettings(kv ...uint32) []byte {
	var p []byte
	for i := 0; i < len(kv); i += 2 {
		p = binary.BigEndian.AppendUint16(p, uint16(kv[i]))
		p = binary.BigEndian.AppendUint32(p, kv[i+1])
	}
	return frame(frSettings, 0, 0, p)
}

// dialH2 sends the preface and SETTINGS (key/value pairs). With read=false
// nothing is read from the connection (a client that does not read).
func dialH2(t *testing.T, addr string, read bool, settings ...uint32) *tclient {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	c := &tclient{t: t, nc: nc, frames: make(chan tframe, 4096), eof: make(chan struct{})}
	c.send(append([]byte(clientPreface), secSettings(settings...)...))
	if read {
		go c.readLoop()
	}
	return c
}

func (c *tclient) send(b ...[]byte) {
	c.nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.nc.Write(bytes.Join(b, nil)); err != nil {
		c.t.Logf("client write: %v", err)
	}
}

func (c *tclient) readLoop() {
	defer close(c.eof)
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c.nc, hdr); err != nil {
			return
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		p := make([]byte, n)
		if _, err := io.ReadFull(c.nc, p); err != nil {
			return
		}
		c.frames <- tframe{hdr[3], hdr[4], binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff, p}
	}
}

// await returns the first frame that matches, or fails after d. Frames that
// do not match are kept for later awaits.
func (c *tclient) await(d time.Duration, what string, match func(tframe) bool) tframe {
	c.t.Helper()
	for i, f := range c.backlog {
		if match(f) {
			c.backlog = append(c.backlog[:i], c.backlog[i+1:]...)
			return f
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case f := <-c.frames:
			if match(f) {
				return f
			}
			c.backlog = append(c.backlog, f)
		case <-c.eof: // readLoop has exited: drain what it delivered first
			for len(c.frames) > 0 {
				if f := <-c.frames; match(f) {
					return f
				} else {
					c.backlog = append(c.backlog, f)
				}
			}
			c.t.Fatalf("connection closed while waiting for %s", what)
		case <-timer.C:
			c.t.Fatalf("timeout waiting for %s", what)
		}
	}
}

func (c *tclient) awaitEOF(d time.Duration) {
	c.t.Helper()
	select {
	case <-c.eof:
	case <-time.After(d):
		c.t.Fatalf("connection not closed within %v", d)
	}
}

// status decodes :status from a response HEADERS frame (the server encodes
// statelessly, so a fresh decoder works).
func respFields(t *testing.T, f tframe) map[string]string {
	t.Helper()
	d := newDecoder()
	var arena []byte
	var fields []headerField
	if _, err := d.decode(f.p, &arena, &fields, 1<<20); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, hf := range fields {
		m[string(hf.Name)] = string(hf.Value)
	}
	return m
}

func (c *tclient) awaitStatus(sid uint32) string {
	c.t.Helper()
	f := c.await(3*time.Second, "response HEADERS", func(f tframe) bool {
		if f.sid == sid && f.typ == frRSTStream {
			c.t.Fatalf("stream %d reset with code %d, want a response", sid, binary.BigEndian.Uint32(f.p))
		}
		return f.sid == sid && f.typ == frHeaders
	})
	return respFields(c.t, f)[":status"]
}

func (c *tclient) awaitRST(sid uint32) uint32 {
	c.t.Helper()
	f := c.await(3*time.Second, "RST_STREAM", func(f tframe) bool {
		if f.sid == sid && f.typ == frHeaders {
			c.t.Fatalf("stream %d got a response, want RST_STREAM", sid)
		}
		return f.sid == sid && f.typ == frRSTStream
	})
	return binary.BigEndian.Uint32(f.p)
}

func (c *tclient) awaitGoAway() uint32 {
	c.t.Helper()
	f := c.await(3*time.Second, "GOAWAY", func(f tframe) bool { return f.typ == frGoAway })
	return binary.BigEndian.Uint32(f.p[4:8])
}

func (c *tclient) awaitBody(sid uint32) string {
	c.t.Helper()
	var b []byte
	for {
		f := c.await(3*time.Second, "DATA", func(f tframe) bool {
			return f.sid == sid && (f.typ == frData || f.typ == frHeaders || f.typ == frRSTStream)
		})
		if f.typ == frRSTStream {
			c.t.Fatalf("stream %d reset", sid)
		}
		if f.typ == frData {
			b = append(b, f.p...)
		}
		if f.flags&flEndStream != 0 {
			return string(b)
		}
	}
}

var reqGET = []byte{0x82, 0x86, 0x84} // :method GET, :scheme http, :path /

func lit(dst []byte, name, value string) []byte { // literal without indexing, new name
	dst = append(dst, 0x00)
	dst = appendHpackInt(dst, 0, 7, uint64(len(name)))
	dst = append(dst, name...)
	dst = appendHpackInt(dst, 0, 7, uint64(len(value)))
	return append(dst, value...)
}

func litIndexed(dst []byte, name, value string) []byte { // literal with incremental indexing
	dst = append(dst, 0x40)
	dst = appendHpackInt(dst, 0, 7, uint64(len(name)))
	dst = append(dst, name...)
	dst = appendHpackInt(dst, 0, 7, uint64(len(value)))
	return append(dst, value...)
}

func reqBlock(method, path string, extra ...string) []byte {
	b := lit(nil, ":method", method)
	b = append(b, 0x86) // :scheme http
	b = lit(b, ":path", path)
	b = lit(b, ":authority", "example.com")
	for i := 0; i+1 < len(extra); i += 2 {
		b = lit(b, extra[i], extra[i+1])
	}
	return b
}

func headers(sid uint32, endStream bool, block []byte) []byte {
	fl := byte(flEndHeaders)
	if endStream {
		fl |= flEndStream
	}
	return frame(frHeaders, fl, sid, block)
}

// startMux serves h through a real http.Server with ConfigureServer (h2c).
func startMux(t *testing.T, hs *http.Server, s *Server) (string, *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs.Protocols = new(http.Protocols)
	hs.Protocols.SetHTTP1(true)
	hs.Protocols.SetUnencryptedHTTP2(true)
	s = ConfigureServer(hs, s)
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return ln.Addr().String(), s
}

func connCount(s *Server) int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return len(s.conns)
}

func okHandler(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }

// ---- tests ----

// HTTP/2 Rapid Reset (CVE-2023-44487): resetting streams must not let a
// client run more handlers than MaxConcurrentStreams.
func TestSecRapidResetBoundsHandlers(t *testing.T) {
	var running, peak atomic.Int64
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := running.Add(1)
		defer running.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release // ignores r.Context() on purpose
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxConcurrentStreams: 100})
	defer close(release)
	c := dialH2(t, addr, true)
	var b []byte
	for i := 0; i < 1000; i++ {
		sid := uint32(2*i + 1)
		b = append(b, headers(sid, true, reqGET)...)
		b = append(b, frame(frRSTStream, 0, sid, u32(codeCancel))...)
	}
	c.send(b)
	c.await(3*time.Second, "REFUSED_STREAM", func(f tframe) bool {
		return f.typ == frRSTStream && binary.BigEndian.Uint32(f.p) == codeRefusedStream
	})
	time.Sleep(200 * time.Millisecond)
	if p := peak.Load(); p > 100 {
		t.Fatalf("%d handlers ran concurrently, MaxConcurrentStreams is 100", p)
	}
}

// A client that does not read must not make the server buffer responses
// without limit: the reader stops reading new requests.
func TestSecBackpressureNonReadingClient(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 64<<10)
	var calls atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write(body)
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxConcurrentStreams: 50})
	c := dialH2(t, addr, false, 4, 1<<30)
	c.nc.(*net.TCPConn).SetReadBuffer(4096)
	c.send(frame(frWindowUpdate, 0, 0, u32(1<<30)))
	const n = 4000
	var b []byte
	for i := 0; i < n; i++ {
		b = append(b, headers(uint32(2*i+1), true, reqGET)...)
	}
	c.send(b)
	time.Sleep(time.Second)
	if got := calls.Load(); got > n/4 {
		t.Fatalf("%d of %d requests were handled while the client read nothing", got, n)
	}
}

// Indexed fields that expand to a large dynamic-table entry: the decoded
// header list is limited, the request gets 431, and the connection stays
// usable (HPACK state in sync).
func TestSecHeaderListLimit(t *testing.T) {
	var calls atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		okHandler(w, r)
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	blk := litIndexed(append([]byte{}, reqGET...), "x-a", strings.Repeat("a", 4000))
	for i := 0; i < 1020; i++ {
		blk = append(blk, 0xbe) // dynamic index 62 = x-a: aaaa...
	}
	c.send(headers(1, true, blk))
	if st := c.awaitStatus(1); st != "431" {
		t.Fatalf("status %q, want 431", st)
	}
	blk2 := append(append([]byte{}, reqGET...), 0xbe, 0xbe) // 2 x 4 KB: fine
	c.send(headers(3, true, blk2))
	if st := c.awaitStatus(3); st != "200" {
		t.Fatalf("status %q after 431, want 200", st)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler called %d times, want 1", calls.Load())
	}
}

func TestSecSettingsFlood(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, nil)
	c := dialH2(t, addr, true)
	var kv []uint32
	for i := 0; i < 16384/6; i++ {
		kv = append(kv, 4, uint32(1000+i%2))
	}
	f := secSettings(kv...)
	var b []byte
	for i := 0; i <= maxWindowSettings; i++ {
		b = append(b, f...)
	}
	c.send(b)
	if code := c.awaitGoAway(); code != codeEnhanceYourCalm {
		t.Fatalf("GOAWAY code %d, want ENHANCE_YOUR_CALM", code)
	}
}

// A connection error while a worker is blocked writing to a client that does
// not read: the connection must go away after WriteByteTimeout (no spinning
// reader, no stuck goroutine).
func TestSecConnErrorWhileWriteBlocked(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 8<<20)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	addr, s := startMux(t, &http.Server{Handler: h}, &Server{WriteByteTimeout: time.Second})
	c := dialH2(t, addr, false, 4, 1<<30)
	c.nc.(*net.TCPConn).SetReadBuffer(4096)
	c.send(frame(frWindowUpdate, 0, 0, u32(1<<30)), headers(1, true, reqGET))
	time.Sleep(200 * time.Millisecond)
	c.send(frame(frPing, 0, 1, make([]byte, 8))) // PING on a stream: connection error
	deadline := time.Now().Add(3 * time.Second)
	for connCount(s) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("connection still open 3s after the error; writer not bounded")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSecHandlerPanic(t *testing.T) {
	var logbuf syncBuffer
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/panic" {
			panic("boom")
		}
		okHandler(w, r)
	})
	addr, _ := startMux(t, &http.Server{Handler: h, ErrorLog: log.New(&logbuf, "", 0)}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqBlock("GET", "/panic")))
	if code := c.awaitRST(1); code != codeInternal {
		t.Fatalf("RST code %d, want INTERNAL_ERROR", code)
	}
	c.send(headers(3, true, reqBlock("GET", "/ok")))
	if st := c.awaitStatus(3); st != "200" {
		t.Fatalf("status %q after a panic, want 200", st)
	}
	if !strings.Contains(logbuf.String(), "panic serving") {
		t.Fatalf("panic not logged to http.Server.ErrorLog: %q", logbuf.String())
	}
}

// HEADERS with END_STREAM and content-length > 0 used to leak the stream slot.
func TestSecMalformedEndStreamNoSlotLeak(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, &Server{MaxConcurrentStreams: 10})
	c := dialH2(t, addr, true)
	var b []byte
	for i := 0; i < 20; i++ {
		b = append(b, headers(uint32(2*i+1), true, reqBlock("GET", "/", "content-length", "1"))...)
	}
	c.send(b)
	for i := 0; i < 20; i++ {
		if code := c.awaitRST(uint32(2*i + 1)); code != codeProtocol {
			t.Fatalf("stream %d: RST code %d, want PROTOCOL_ERROR", 2*i+1, code)
		}
	}
	c.send(headers(41, true, reqGET))
	if st := c.awaitStatus(41); st != "200" {
		t.Fatalf("status %q, want 200", st)
	}
}

// r.Body must not expose the next request's body to a goroutine that
// outlives the handler (http.TimeoutHandler).
func TestSecAdapterLateBodyRead(t *testing.T) {
	got := make(chan string, 2)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		b, err := io.ReadAll(r.Body)
		got <- r.Header.Get("X-User") + ":" + string(b) + ":" + errString(err)
	})
	addr, _ := startMux(t, &http.Server{Handler: http.TimeoutHandler(inner, 50*time.Millisecond, "timeout")}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "x-user", "alice")), frame(frData, flEndStream, 1, []byte("alice-secret-0001")))
	time.Sleep(150 * time.Millisecond)
	c.send(headers(3, false, reqBlock("POST", "/", "x-user", "bob")), frame(frData, flEndStream, 3, []byte("bob-public-000002")))
	for i := 0; i < 2; i++ {
		s := <-got
		if strings.HasPrefix(s, "alice:") && strings.Contains(s, "bob") {
			t.Fatalf("alice's handler read bob's body: %s", s)
		}
		if strings.Contains(s, "::<nil>") {
			t.Fatalf("late read returned no error: %s", s)
		}
	}
}

// A write after the handler returned must not land in another response.
func TestSecAdapterLateWrite(t *testing.T) {
	lateErr := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			go func() {
				time.Sleep(100 * time.Millisecond)
				_, err := w.Write([]byte("LEAK"))
				lateErr <- err
			}()
			io.WriteString(w, "first")
			return
		}
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "second")
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqBlock("GET", "/first")))
	if b := c.awaitBody(1); b != "first" {
		t.Fatalf("first body %q", b)
	}
	c.send(headers(3, true, reqBlock("GET", "/second")))
	if b := c.awaitBody(3); b != "second" {
		t.Fatalf("second body %q: a late write leaked into it", b)
	}
	if err := <-lateErr; err == nil {
		t.Fatal("late Write returned no error")
	}
}

func TestSecRequestValidation(t *testing.T) {
	var calls atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Host") != "" {
			t.Errorf("Host left in r.Header")
		}
		okHandler(w, r)
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	authority := func(a string, extra ...string) []byte {
		b := append([]byte{0x82, 0x86, 0x84}, lit(nil, ":authority", a)...)
		for i := 0; i+1 < len(extra); i += 2 {
			b = lit(b, extra[i], extra[i+1])
		}
		return b
	}
	bad := map[string][]byte{
		"CRLF in value":         reqBlock("GET", "/", "x-a", "a\r\nset-cookie: s=1"),
		"NUL in value":          reqBlock("GET", "/", "x-a", "a\x00b"),
		"space in name":         reqBlock("GET", "/", "x a", "1"),
		"NUL in name":           reqBlock("GET", "/", "x\x00a", "1"),
		"uppercase name":        reqBlock("GET", "/", "X-A", "1"),
		"method not a token":    reqBlock("GET /admin HTTP/1.1\r\nx:", "/"),
		"path without slash":    reqBlock("GET", "admin"),
		"absolute-form path":    reqBlock("GET", "http://other/admin"),
		"space in path":         reqBlock("GET", "/a b"),
		"asterisk not OPTIONS":  reqBlock("GET", "*"),
		"CRLF in authority":     authority("example.com\r\nx-a: 1"),
		"space in authority":    authority("exa mple.com"),
		"Host differs":          authority("example.com", "host", "evil.com"),
		"two Host fields":       authority("example.com", "host", "example.com", "host", "example.com"),
		"bad scheme":            append(lit(append([]byte{0x82}, lit(nil, ":scheme", "ht tp")...), ":path", "/"), lit(nil, ":authority", "a")...),
		"CRLF in Host (no :au)": append([]byte{0x82, 0x86, 0x84}, lit(nil, "host", "a\r\nb")...),
	}
	sid := uint32(1)
	for name, blk := range bad {
		c.send(headers(sid, true, blk))
		if code := c.awaitRST(sid); code != codeProtocol {
			t.Errorf("%s: RST code %d, want PROTOCOL_ERROR", name, code)
		}
		sid += 2
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("handler called %d times for malformed requests", n)
	}
	good := map[string][]byte{
		"authority with port": authority("example.com:8443"),
		"HTAB in value":       reqBlock("GET", "/", "x-a", "a\tb"),
		"obs-text in value":   reqBlock("GET", "/", "x-a", "caf\xc3\xa9"),
		"OPTIONS *":           reqBlock("OPTIONS", "*"),
		"Host equal (case)":   authority("Example.COM", "host", "example.com"),
		"IPv6 authority":      authority("[::1]:8080"),
		"query and percent":   reqBlock("GET", "/a%20b?q=1&r=%2F"),
	}
	for name, blk := range good {
		c.send(headers(sid, true, blk))
		if st := c.awaitStatus(sid); st != "200" {
			t.Errorf("%s: status %q, want 200", name, st)
		}
		sid += 2
	}
}

func TestSecResponseHeaderNames(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["X Bad"] = []string{"1"}
		w.Header()[":status"] = []string{"999"}
		w.Header().Set("X-Crlf", "a\r\nb")
		w.Header().Set("X-Ok", "v")
		okHandler(w, r)
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqGET))
	f := c.await(3*time.Second, "response HEADERS", func(f tframe) bool { return f.sid == 1 && f.typ == frHeaders })
	m := respFields(t, f)
	if m[":status"] != "200" || m["x-ok"] != "v" {
		t.Fatalf("fields %v", m)
	}
	for _, k := range []string{"x bad", "x-crlf"} {
		if _, ok := m[k]; ok {
			t.Fatalf("invalid field %q sent: %v", k, m)
		}
	}
}

func TestSecHandshakeTimeout(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, &Server{HandshakeTimeout: 200 * time.Millisecond})
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.Write([]byte(clientPreface)) // and no SETTINGS frame
	nc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, nc); err != nil { // returns at EOF
		t.Fatalf("connection not closed by the server: %v", err)
	}
}

func TestSecIdleTimeoutFromHTTPServer(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler), IdleTimeout: 300 * time.Millisecond}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqGET))
	c.awaitStatus(1)
	if code := c.awaitGoAway(); code != codeNo {
		t.Fatalf("GOAWAY code %d, want NO_ERROR", code)
	}
	c.awaitEOF(3 * time.Second)
}

func TestSecStreamReadTimeoutFromHTTPServer(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler), ReadTimeout: 300 * time.Millisecond}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/"))) // body never comes
	if code := c.awaitRST(1); code != codeCancel {
		t.Fatalf("RST code %d, want CANCEL", code)
	}
}

func TestSecHeaderBlockTimeout(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, &Server{ReadTimeout: 300 * time.Millisecond})
	c := dialH2(t, addr, true)
	c.send(frame(frHeaders, flEndStream, 1, reqGET)) // no END_HEADERS, no CONTINUATION
	if code := c.awaitGoAway(); code != codeEnhanceYourCalm {
		t.Fatalf("GOAWAY code %d, want ENHANCE_YOUR_CALM", code)
	}
}

// A response blocked by a zero flow-control window must not pin the stream
// forever.
func TestSecPendingResponseTimeout(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, &Server{WriteByteTimeout: 300 * time.Millisecond})
	c := dialH2(t, addr, true, 4, 0) // INITIAL_WINDOW_SIZE = 0
	c.send(headers(1, true, reqGET))
	c.awaitStatus(1)
	if code := c.awaitRST(1); code != codeCancel {
		t.Fatalf("RST code %d, want CANCEL", code)
	}
}

func TestSecConnBodyBudget(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, &Server{MaxConnBodySize: 1 << 20, MaxRequestBodySize: 512 << 10})
	c := dialH2(t, addr, true)
	chunk := make([]byte, 16<<10)
	var b []byte
	for sid := uint32(1); sid <= 5; sid += 2 {
		b = append(b, headers(sid, false, reqBlock("POST", "/"))...)
		for i := 0; i < 25; i++ { // 400 KiB per stream
			b = append(b, frame(frData, 0, sid, chunk)...)
		}
	}
	c.send(b)
	if code := c.awaitRST(5); code != codeRefusedStream {
		t.Fatalf("third stream: RST code %d, want REFUSED_STREAM", code)
	}
	c.send(frame(frData, flEndStream, 1, nil), frame(frData, flEndStream, 3, nil))
	for _, sid := range []uint32{1, 3} {
		if st := c.awaitStatus(sid); st != "200" {
			t.Fatalf("stream %d: status %q", sid, st)
		}
	}
}

type countingConn struct {
	net.Conn
	reads atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

// A deadline that fires while no new one is needed (busy connection, no
// stream deadlines) must be cleared, or every Read fails at once and the
// reader spins until the handler returns.
func TestSecExpiredDeadlineDoesNotSpin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := &Server{HandshakeTimeout: 150 * time.Millisecond}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond) // handshake deadline fires while this runs
		okHandler(w, r)
	})
	cc := make(chan *countingConn, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		w := &countingConn{Conn: nc}
		cc <- w
		s.serveConn(w, connOpts{handler: httpHandler(h)})
	}()
	c := dialH2(t, ln.Addr().String(), true)
	c.send(headers(1, true, reqGET))
	if st := c.awaitStatus(1); st != "200" {
		t.Fatalf("status %q", st)
	}
	if n := (<-cc).reads.Load(); n > 20 {
		t.Fatalf("%d reads for one request: the reader spun on an expired deadline", n)
	}
	s.shutdown()
}

func TestSecTLSPolicy(t *testing.T) {
	cases := []struct {
		v, cs uint16
		ok    bool
	}{
		{tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, true},
		{tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true},
		{tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, true},
		{tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, false},
		{tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, false},
		{tls.VersionTLS11, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, false},
	}
	for _, c := range cases {
		if got := tlsOK(&tls.ConnectionState{Version: c.v, CipherSuite: c.cs}); got != c.ok {
			t.Errorf("version %x cipher %x: got %v, want %v", c.v, c.cs, got, c.ok)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
