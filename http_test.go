package fasth2

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// App under test: an ordinary net/http application built with gorilla/mux.
func testRouter(ctxCanceled chan<- struct{}) http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/users/{id:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id": mux.Vars(r)["id"], "q": r.URL.Query().Get("q"), "proto": r.Proto,
			"host": r.Host, "cookie": r.Header.Get("Cookie"), "ua": r.UserAgent(),
			"tls": fmt.Sprint(r.TLS != nil), "remote": fmt.Sprint(r.RemoteAddr != ""),
		})
	}).Methods("GET")
	r.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/users/42")
		w.Header().Add("X-Multi", "a")
		w.Header().Add("X-Multi", "b")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "created %v len=%d", in["name"], r.ContentLength)
	}).Methods("POST")
	r.HandleFunc("/nocontent", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	r.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>hi</body></html>") // content-type is sniffed
	})
	r.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			ctxCanceled <- struct{}{}
		case <-time.After(5 * time.Second):
		}
	})
	return r
}

type env struct {
	base   string
	client *http.Client
	hs     *http.Server
	fs     *Server
}

func newTLSEnv(t *testing.T, h http.Handler) *env {
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	ts.Close()

	hs := &http.Server{Handler: h}
	fs := ConfigureServer(hs, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	go hs.ServeTLS(ln, "", "")
	t.Cleanup(func() { hs.Close() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	return &env{"https://" + ln.Addr().String(), &http.Client{Transport: tr}, hs, fs}
}

func newH2CEnv(t *testing.T, h http.Handler) *env {
	hs := &http.Server{Handler: h, Protocols: new(http.Protocols)}
	hs.Protocols.SetHTTP1(true)
	hs.Protocols.SetUnencryptedHTTP2(true)
	fs := ConfigureServer(hs, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return &env{"http://" + ln.Addr().String(), h2cClient(), hs, fs}
}

func (e *env) fasth2Conns() int {
	e.fs.connMu.Lock()
	defer e.fs.connMu.Unlock()
	return len(e.fs.conns)
}

func runCompat(t *testing.T, e *env, wantTLS bool) {
	// GET with path var, query, cookies (sent as separate HTTP/2 crumbs).
	req, _ := http.NewRequest("GET", e.base+"/users/7?q=x%20y", nil)
	req.AddCookie(&http.Cookie{Name: "a", Value: "1"})
	req.AddCookie(&http.Cookie{Name: "b", Value: "2"})
	req.Header.Set("User-Agent", "compat-test")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 || got["id"] != "7" || got["q"] != "x y" ||
		got["proto"] != "HTTP/2.0" || got["cookie"] != "a=1; b=2" || got["ua"] != "compat-test" ||
		got["tls"] != fmt.Sprint(wantTLS) || got["remote"] != "true" || got["host"] == "" ||
		resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Date") == "" {
		t.Fatalf("GET: %d %v %v", resp.StatusCode, got, resp.Header)
	}
	if e.fasth2Conns() == 0 {
		t.Fatal("request was not served by fasth2")
	}

	// POST JSON -> 201 with Location and a multi-value header.
	resp, err = e.client.Post(e.base+"/users", "application/json", strings.NewReader(`{"name":"anton"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || string(b) != "created anton len=16" || resp.Header.Get("Location") != "/users/42" ||
		strings.Join(resp.Header.Values("X-Multi"), ",") != "a,b" {
		t.Fatalf("POST: %d %q %v", resp.StatusCode, b, resp.Header)
	}

	// Router behaviour: 404, 405, 204, sniffed content type, HEAD.
	for _, tc := range []struct {
		method, path string
		code         int
		ctype        string
	}{
		{"GET", "/nope", 404, ""},
		{"DELETE", "/users/7", 405, ""},
		{"GET", "/nocontent", 204, ""},
		{"GET", "/html", 200, "text/html; charset=utf-8"},
		{"HEAD", "/html", 200, "text/html; charset=utf-8"},
	} {
		req, _ := http.NewRequest(tc.method, e.base+tc.path, nil)
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.code || (tc.ctype != "" && resp.Header.Get("Content-Type") != tc.ctype) {
			t.Fatalf("%s %s: %d %q", tc.method, tc.path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if tc.method == "HEAD" && (len(b) != 0 || resp.ContentLength != 28) {
			t.Fatalf("HEAD: body=%d cl=%d", len(b), resp.ContentLength)
		}
	}
}

func TestCompatTLS(t *testing.T) {
	runCompat(t, newTLSEnv(t, testRouter(nil)), true)
}

func TestCompatH2C(t *testing.T) {
	e := newH2CEnv(t, testRouter(nil))
	runCompat(t, e, false)
	// The same port still speaks HTTP/1.1 (served by net/http itself).
	resp, err := http.Get(e.base + "/users/1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 1 || resp.StatusCode != 200 {
		t.Fatalf("HTTP/1.1: %s %d", resp.Proto, resp.StatusCode)
	}
}

func TestCompatServeMux(t *testing.T) { // stdlib router with Go 1.22 patterns
	m := http.NewServeMux()
	m.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "item "+r.PathValue("id"))
	})
	e := newH2CEnv(t, m)
	resp, err := e.client.Get(e.base + "/items/abc")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "item abc" {
		t.Fatalf("got %q", b)
	}
}

func TestCompatContextCancel(t *testing.T) {
	canceled := make(chan struct{}, 1)
	e := newTLSEnv(t, testRouter(canceled))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.base+"/slow", nil)
	if _, err := e.client.Do(req); err == nil {
		t.Fatal("expected client timeout")
	}
	select {
	case <-canceled: // client's RST_STREAM canceled r.Context()
	case <-time.After(2 * time.Second):
		t.Fatal("handler context was not canceled")
	}
}

func TestCompatShutdown(t *testing.T) {
	e := newTLSEnv(t, testRouter(nil))
	resp, err := e.client.Get(e.base + "/users/1") // leaves an idle HTTP/2 connection
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := e.hs.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v after %v", err, time.Since(start))
	}
}

func TestCompatLargeBodies(t *testing.T) {
	m := http.NewServeMux()
	m.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) })
	e := newTLSEnv(t, m)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 256<<10) // 4 MiB
	resp, err := e.client.Post(e.base+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, payload) {
		t.Fatalf("echo: got %d bytes", len(b))
	}
}
