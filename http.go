package fasth2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConfigureServer replaces the HTTP/2 implementation of hs with fasth2.
// Everything else (HTTP/1.1, TLS, timeouts for HTTP/1, Shutdown, ConnState
// for HTTP/1 connections, the Handler) stays net/http.
//
//   - TLS ("h2" via ALPN) is enabled as usual with ListenAndServeTLS / ServeTLS.
//   - h2c (prior knowledge) is served when hs.Protocols has UnencryptedHTTP2.
//
// hs.ReadTimeout, IdleTimeout, WriteTimeout, MaxHeaderBytes and ErrorLog are
// read when a connection starts and fill the zero fields of s (see Server).
// TLS connections below TLS 1.2, or TLS 1.2 without an ECDHE AEAD cipher, are
// refused with INADEQUATE_SECURITY (RFC 9113 9.2).
//
// Handlers run on fasth2 worker goroutines, so they may block exactly like
// under net/http. s may be nil.
func ConfigureServer(hs *http.Server, s *Server) *Server {
	if s == nil {
		s = &Server{}
	}
	if hs.TLSNextProto == nil {
		hs.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	hs.TLSNextProto["h2"] = func(hs *http.Server, tc *tls.Conn, h http.Handler) {
		cs := tc.ConnectionState()
		if !tlsOK(&cs) {
			rejectInadequateTLS(tc)
			return
		}
		s.serveConn(tc, connOpts{handler: httpHandler(h), ctx: baseContext(h), tls: &cs, hs: hs})
	}
	// Go 1.24+ hands h2c connections (preface already consumed) to this key.
	hs.TLSNextProto["unencrypted_http2"] = func(hs *http.Server, tc *tls.Conn, h http.Handler) {
		nc := tc.NetConn()
		if u, ok := nc.(interface{ UnencryptedNetConn() net.Conn }); ok {
			nc = u.UnencryptedNetConn()
		}
		s.serveConn(nc, connOpts{handler: httpHandler(h), ctx: baseContext(h), sawPreface: true, hs: hs})
	}
	hs.RegisterOnShutdown(s.shutdown)
	return s
}

// rejectInadequateTLS sends the server preface and GOAWAY INADEQUATE_SECURITY.
func rejectInadequateTLS(tc *tls.Conn) {
	b := appendFrameHeader(nil, 0, frSettings, 0, 0)
	b = appendFrameHeader(b, 8, frGoAway, 0, 0)
	b = appendU32(b, 0)
	b = appendU32(b, codeInadequateSec)
	tc.SetWriteDeadline(time.Now().Add(time.Second))
	tc.Write(b)
	tc.Close()
}

func baseContext(h http.Handler) context.Context {
	if b, ok := h.(interface{ BaseContext() context.Context }); ok {
		return b.BaseContext()
	}
	return context.Background()
}

// httpHandler adapts a standard http.Handler (http.ServeMux, gorilla/mux,
// chi, middleware...) to fasth2.
// Not supported: http.Flusher/streaming responses, Hijacker, 1xx responses,
// request and response trailers. Request bodies are fully buffered.
func httpHandler(h http.Handler) handlerFunc {
	return func(req *request, resp *response) { serveHTTP(h, req, resp) }
}

func internMethod(b []byte) string {
	switch string(b) {
	case "GET":
		return "GET"
	case "POST":
		return "POST"
	case "PUT":
		return "PUT"
	case "DELETE":
		return "DELETE"
	case "HEAD":
		return "HEAD"
	case "PATCH":
		return "PATCH"
	case "OPTIONS":
		return "OPTIONS"
	}
	return string(b)
}

var commonCanon = func() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"Accept", "Accept-Encoding", "Accept-Language", "Authorization",
		"Cache-Control", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Date",
		"Etag", "Host", "If-Modified-Since", "If-None-Match", "Location", "Origin", "Referer",
		"Server", "Set-Cookie", "User-Agent", "Vary", "X-Forwarded-For", "X-Real-Ip",
		"X-Request-Id", "Last-Modified", "Access-Control-Allow-Origin", "Te", "Traceparent"} {
		m[strings.ToLower(k)] = k
	}
	return m
}()

var commonLower = func() map[string]string {
	m := map[string]string{}
	for l, c := range commonCanon {
		m[c] = l
	}
	return m
}()

func canonicalKey(b []byte) string {
	if k, ok := commonCanon[string(b)]; ok {
		return k
	}
	return textproto.CanonicalMIMEHeaderKey(string(b))
}

func lowerKey(k string) string {
	if l, ok := commonLower[k]; ok {
		return l
	}
	return strings.ToLower(k)
}

func serveHTTP(h http.Handler, req *request, resp *response) {
	method := internMethod(req.method)
	hr := &http.Request{
		Method:     method,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     make(http.Header, len(req.header)),
		RemoteAddr: req.remoteAddr,
		TLS:        req.tls,
		Host:       string(req.authority),
	}
	if method == "CONNECT" {
		hr.URL = &url.URL{Host: hr.Host}
		hr.RequestURI = hr.Host
	} else {
		hr.RequestURI = string(req.path)
		u, err := url.ParseRequestURI(hr.RequestURI)
		if err != nil {
			resp.status = 400
			return
		}
		hr.URL = u
	}
	var cookies []string
	for i := range req.header {
		f := &req.header[i]
		if string(f.Name) == "cookie" { // RFC 9113 8.2.3: re-join cookie crumbs
			cookies = append(cookies, string(f.Value))
			continue
		}
		k := canonicalKey(f.Name)
		hr.Header[k] = append(hr.Header[k], string(f.Value))
	}
	if len(cookies) > 0 {
		hr.Header["Cookie"] = []string{strings.Join(cookies, "; ")}
	}
	// Like net/http: the Host lives in r.Host, not in r.Header. parseRequest
	// has checked that it matches :authority.
	if hv, ok := hr.Header["Host"]; ok {
		if hr.Host == "" && len(hv) > 0 {
			hr.Host = hv[0]
		}
		delete(hr.Header, "Host")
	}
	hr.ContentLength = int64(len(req.body))
	var body *reqBody
	if len(req.body) == 0 {
		hr.Body = http.NoBody
	} else {
		body = &reqBody{b: req.body}
		hr.Body = body
	}
	if ctx := req.context(); ctx != context.Background() {
		hr = hr.WithContext(ctx)
	}

	rw := &responseWriter{resp: resp, header: make(http.Header), head: method == "HEAD"}
	h.ServeHTTP(rw, hr)
	// req.body and resp are stream buffers that the next request on this
	// connection reuses. Detach them before returning, so a goroutine that
	// outlives the handler (http.TimeoutHandler does that) gets an error
	// instead of another request's body or another response.
	if body != nil {
		body.finish()
	}
	rw.finish()
}

// reqBody reads a request body that aliases a reusable stream buffer.
type reqBody struct {
	mu     sync.Mutex
	b      []byte
	closed bool
}

func (r *reqBody) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func (r *reqBody) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func (r *reqBody) finish() {
	r.mu.Lock()
	r.closed, r.b = true, nil
	r.mu.Unlock()
}

var errWriteAfterHandler = errors.New("fasth2: Write after the handler returned")

type responseWriter struct {
	mu      sync.Mutex
	resp    *response
	header  http.Header
	status  int
	wrote   bool
	done    bool // handler returned; resp belongs to the stream again
	head    bool
	hasType bool
	hasDate bool
	clen    int64 // explicit Content-Length (HEAD), -1 if unset
	headN   int64 // bytes "written" in reply to HEAD
}

func (w *responseWriter) Header() http.Header { return w.header }

func bodyAllowed(code int) bool {
	return code != 204 && code != 304 && (code < 100 || code > 199)
}

// WriteHeader snapshots the header map, like net/http does.
func (w *responseWriter) WriteHeader(code int) {
	w.mu.Lock()
	w.writeHeaderLocked(code)
	w.mu.Unlock()
}

func (w *responseWriter) writeHeaderLocked(code int) {
	if w.done || w.wrote || code < 200 || code > 999 { // 1xx informational responses are not supported
		return
	}
	w.wrote = true
	w.status = code
	w.clen = -1
	w.resp.status = code
	for k, vs := range w.header {
		lk := lowerKey(k)
		if !validFieldName(lk) { // also drops pseudo-header names (":...")
			continue
		}
		switch lk {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "trailer":
			continue
		case "content-length":
			if len(vs) > 0 {
				if n, err := strconv.ParseInt(vs[0], 10, 64); err == nil && n >= 0 {
					w.clen = n
				}
			}
			continue
		case "content-type":
			w.hasType = true
		case "date":
			w.hasDate = true
		}
		for _, v := range vs {
			if validFieldValue(v) {
				w.resp.addHeader(lk, v)
			}
		}
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeLocked(p)
}

func (w *responseWriter) writeLocked(p []byte) (int, error) {
	if w.done {
		return 0, errWriteAfterHandler
	}
	if !w.wrote {
		w.writeHeaderLocked(200)
	}
	if !bodyAllowed(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	if w.head {
		w.headN += int64(len(p))
		if !w.hasType && w.headN == int64(len(p)) && len(p) > 0 {
			w.resp.addHeader("content-type", http.DetectContentType(p))
			w.hasType = true
		}
		return len(p), nil
	}
	w.resp.write(p)
	return len(p), nil
}

func (w *responseWriter) WriteString(s string) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.head || w.done {
		return w.writeLocked([]byte(s))
	}
	if !w.wrote {
		w.writeHeaderLocked(200)
	}
	if !bodyAllowed(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	w.resp.writeString(s)
	return len(s), nil
}

func (w *responseWriter) finish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.wrote {
		w.writeHeaderLocked(200)
	}
	w.done = true
	body := w.resp.body
	if !w.hasType && len(body) > 0 && bodyAllowed(w.status) {
		n := len(body)
		if n > 512 {
			n = 512
		}
		w.resp.addHeader("content-type", http.DetectContentType(body[:n]))
	}
	if !w.hasDate {
		w.resp.addHeader("date", httpDate())
	}
	if w.head {
		if w.clen >= 0 {
			w.resp.contentLength = w.clen
		} else {
			w.resp.contentLength = w.headN
		}
	}
}

type cachedDate struct {
	sec int64
	s   string
}

var dateCache atomic.Pointer[cachedDate]

func httpDate() string {
	now := time.Now()
	if d := dateCache.Load(); d != nil && d.sec == now.Unix() {
		return d.s
	}
	d := &cachedDate{now.Unix(), now.UTC().Format(http.TimeFormat)}
	dateCache.Store(d)
	return d.s
}
