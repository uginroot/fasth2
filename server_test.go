package fasth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- RFC 7541 Appendix C test vectors ----

type hf struct{ n, v string }

func runVectors(t *testing.T, blocks []string, want [][]hf, sizes []int) {
	d := newDecoder()
	for i, hx := range blocks {
		raw, err := hex.DecodeString(strings.ReplaceAll(hx, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		var arena []byte
		var fields []HeaderField
		if err := d.decode(raw, &arena, &fields); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		if len(fields) != len(want[i]) {
			t.Fatalf("block %d: got %d fields, want %d", i, len(fields), len(want[i]))
		}
		for j, f := range fields {
			if string(f.Name) != want[i][j].n || string(f.Value) != want[i][j].v {
				t.Fatalf("block %d field %d: got %q=%q", i, j, f.Name, f.Value)
			}
		}
		if d.size != sizes[i] {
			t.Fatalf("block %d: table size %d, want %d", i, d.size, sizes[i])
		}
	}
}

var c3want = [][]hf{
	{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}},
	{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}, {"cache-control", "no-cache"}},
	{{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"}, {"custom-key", "custom-value"}},
}

func TestHPACK_RFC7541_C3(t *testing.T) { // requests without Huffman
	runVectors(t, []string{
		"8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
		"8286 84be 5808 6e6f 2d63 6163 6865",
		"8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
	}, c3want, []int{57, 110, 164})
}

func TestHPACK_RFC7541_C4(t *testing.T) { // requests with Huffman
	runVectors(t, []string{
		"8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
		"8286 84be 5886 a8eb 1064 9cbf",
		"8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
	}, c3want, []int{57, 110, 164})
}

// ---- interop with Go's net/http HTTP/2 client (h2c prior knowledge) ----

var bigBody = func() []byte {
	b := make([]byte, 3<<20)
	rand.Read(b)
	return b
}()

func startServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &Server{Handler: func(req *Request, resp *Response) {
		switch string(req.Path) {
		case "/echo":
			resp.AddHeader("x-method", string(req.Method))
			resp.Write(req.Body)
		case "/big":
			resp.Write(bigBody)
		case "/404":
			resp.SetStatus(404)
		case "/418":
			resp.SetStatus(418)
			resp.AddHeader("x-custom-header", strings.Repeat("v", 20000)) // forces CONTINUATION
		default:
			resp.AddHeader("content-type", "text/plain")
			resp.WriteString("Hello, World!")
		}
	}}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String()
}

func h2cClient() *http.Client {
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: p}}
}

func TestInteropGoClient(t *testing.T) {
	base := startServer(t)
	cl := h2cClient()

	resp, err := cl.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 || string(b) != "Hello, World!" ||
		resp.Header.Get("Content-Type") != "text/plain" || resp.ContentLength != 13 {
		t.Fatalf("GET /: proto=%d status=%d body=%q hdr=%v", resp.ProtoMajor, resp.StatusCode, b, resp.Header)
	}

	// POST with a 5 MB body: exercises receive-side flow control and WINDOW_UPDATE.
	payload := make([]byte, 5<<20)
	rand.Read(payload)
	resp, err = cl.Post(base+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, payload) || resp.Header.Get("X-Method") != "POST" {
		t.Fatalf("echo mismatch: got %d bytes", len(b))
	}

	// 3 MB response: exercises send-side flow control (pending streams).
	resp, err = cl.Get(base + "/big")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, bigBody) {
		t.Fatalf("big body mismatch: %d bytes", len(b))
	}

	for _, tc := range []struct {
		path string
		code int
	}{{"/404", 404}, {"/418", 418}} {
		resp, err = cl.Get(base + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatalf("%s: status %d", tc.path, resp.StatusCode)
		}
	}
}

func TestInteropConcurrent(t *testing.T) {
	base := startServer(t)
	cl := h2cClient()
	var wg sync.WaitGroup
	errs := make(chan error, 500)
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/"
			if i%10 == 0 {
				path = "/big"
			}
			req, _ := http.NewRequestWithContext(context.Background(), "GET", base+path, nil)
			resp, err := cl.Do(req)
			if err != nil {
				errs <- err
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			want := int64(13)
			if path == "/big" {
				want = int64(len(bigBody))
			}
			if n != want {
				errs <- fmt.Errorf("%s: got %d bytes", path, n)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// ---- async mode ----

func startAsync(t *testing.T, h Handler) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go (&Server{Async: true, Handler: h}).Serve(ln)
	return "http://" + ln.Addr().String()
}

// 200 requests that each block for 100 ms, multiplexed over ONE connection,
// must finish in ~100 ms (not 20 s): blocking handlers don't block the conn.
func TestAsyncBlockingHandlers(t *testing.T) {
	base := startAsync(t, func(req *Request, resp *Response) {
		time.Sleep(100 * time.Millisecond)
		resp.Write(req.Path)
	})
	cl := h2cClient()
	cl.Get(base + "/warmup") // make sure a single connection is established
	start := time.Now()
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/r%d", i)
			resp, err := cl.Get(base + path)
			if err != nil {
				bad.Add(1)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != path {
				bad.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d bad responses", bad.Load())
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v: handlers are serialized", d)
	}
}

func TestAsyncInterop(t *testing.T) {
	base := startAsync(t, func(req *Request, resp *Response) {
		if string(req.Path) == "/panic" {
			panic("boom")
		}
		if string(req.Path) == "/big" {
			resp.Write(bigBody)
			return
		}
		resp.Write(req.Body)
	})
	cl := h2cClient()
	payload := make([]byte, 2<<20)
	rand.Read(payload)
	resp, err := cl.Post(base+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, payload) {
		t.Fatal("echo mismatch")
	}
	resp, err = cl.Get(base + "/big")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, bigBody) {
		t.Fatal("big mismatch")
	}
	if _, err := cl.Get(base + "/panic"); err == nil { // RST_STREAM INTERNAL_ERROR
		t.Fatal("expected stream error on panic")
	}
	if _, err := cl.Get(base + "/after-panic"); err != nil { // connection survives
		t.Fatal(err)
	}
}

func TestHuffmanInvalid(t *testing.T) {
	for name, in := range map[string][]byte{
		"eos":            {0xff, 0xff, 0xff, 0xff}, // contains the 30-bit EOS code
		"padding-zeros":  {0x00},                   // '0' (00000) + 000 padding
		"padding-8-bits": {0xff},                   // 8 bits of padding
	} {
		if _, err := huffmanDecode(nil, in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if out, err := huffmanDecode(nil, []byte{0x07}); err != nil || string(out) != "0" { // '0'=00000 + 111 padding
		t.Fatalf("got %q %v", out, err)
	}
}
