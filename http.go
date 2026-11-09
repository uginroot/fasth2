package fasth2

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
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
// Handlers run on fasth2 worker goroutines (s.Async is forced on), so they
// may block exactly like under net/http. s may be nil.
func ConfigureServer(hs *http.Server, s *Server) *Server {
	if s == nil {
		s = &Server{}
	}
	s.Async = true
	if hs.TLSNextProto == nil {
		hs.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	hs.TLSNextProto["h2"] = func(_ *http.Server, tc *tls.Conn, h http.Handler) {
		cs := tc.ConnectionState()
		s.serveConn(tc, connOpts{handler: HTTPHandler(h), ctx: baseContext(h), tls: &cs})
	}
	// Go 1.24+ hands h2c connections (preface already consumed) to this key.
	hs.TLSNextProto["unencrypted_http2"] = func(_ *http.Server, tc *tls.Conn, h http.Handler) {
		nc := tc.NetConn()
		if u, ok := nc.(interface{ UnencryptedNetConn() net.Conn }); ok {
			nc = u.UnencryptedNetConn()
		}
		s.serveConn(nc, connOpts{handler: HTTPHandler(h), ctx: baseContext(h), sawPreface: true})
	}
	hs.RegisterOnShutdown(s.Shutdown)
	return s
}

func baseContext(h http.Handler) context.Context {
	if b, ok := h.(interface{ BaseContext() context.Context }); ok {
		return b.BaseContext()
	}
	return context.Background()
}

// HTTPHandler adapts a standard http.Handler (http.ServeMux, gorilla/mux,
// chi, middleware...) to fasth2. Use it with Server.Async = true.
// Not supported: http.Flusher/streaming responses, Hijacker, 1xx responses,
// request and response trailers. Request bodies are fully buffered.
func HTTPHandler(h http.Handler) Handler {
	return func(req *Request, resp *Response) { serveHTTP(h, req, resp) }
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

func serveHTTP(h http.Handler, req *Request, resp *Response) {
	method := internMethod(req.Method)
	hr := &http.Request{
		Method:     method,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     make(http.Header, len(req.Header)),
		RemoteAddr: req.RemoteAddr,
		TLS:        req.TLS,
		Host:       string(req.Authority),
	}
	if method == "CONNECT" {
		hr.URL = &url.URL{Host: hr.Host}
		hr.RequestURI = hr.Host
	} else {
		hr.RequestURI = string(req.Path)
		u, err := url.ParseRequestURI(hr.RequestURI)
		if err != nil {
			resp.SetStatus(400)
			return
		}
		hr.URL = u
	}
	var cookies []string
	for i := range req.Header {
		f := &req.Header[i]
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
	if hr.Host == "" {
		hr.Host = hr.Header.Get("Host")
	}
	hr.ContentLength = int64(len(req.Body))
	if len(req.Body) == 0 {
		hr.Body = http.NoBody
	} else {
		hr.Body = io.NopCloser(bytes.NewReader(req.Body))
	}
	if ctx := req.Context(); ctx != context.Background() {
		hr = hr.WithContext(ctx)
	}

	rw := responseWriter{resp: resp, header: make(http.Header), head: method == "HEAD"}
	h.ServeHTTP(&rw, hr)
	rw.finish()
}

type responseWriter struct {
	resp    *Response
	header  http.Header
	status  int
	wrote   bool
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

func validValue(v string) bool {
	return strings.IndexByte(v, '\r') < 0 && strings.IndexByte(v, '\n') < 0 && strings.IndexByte(v, 0) < 0
}

// WriteHeader snapshots the header map, like net/http does.
func (w *responseWriter) WriteHeader(code int) {
	if w.wrote || code < 200 || code > 999 { // 1xx informational responses are not supported
		return
	}
	w.wrote = true
	w.status = code
	w.clen = -1
	w.resp.SetStatus(code)
	for k, vs := range w.header {
		lk := lowerKey(k)
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
		if strings.HasPrefix(lk, "trailer:") {
			continue
		}
		for _, v := range vs {
			if validValue(v) {
				w.resp.AddHeader(lk, v)
			}
		}
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	if !bodyAllowed(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	if w.head {
		w.headN += int64(len(p))
		if !w.hasType && w.headN == int64(len(p)) && len(p) > 0 {
			w.resp.AddHeader("content-type", http.DetectContentType(p))
			w.hasType = true
		}
		return len(p), nil
	}
	return w.resp.Write(p)
}

func (w *responseWriter) WriteString(s string) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	if !bodyAllowed(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	if w.head {
		return w.Write([]byte(s))
	}
	return w.resp.WriteString(s)
}

func (w *responseWriter) finish() {
	if !w.wrote {
		w.WriteHeader(200)
	}
	body := w.resp.body
	if !w.hasType && len(body) > 0 && bodyAllowed(w.status) {
		n := len(body)
		if n > 512 {
			n = 512
		}
		w.resp.AddHeader("content-type", http.DetectContentType(body[:n]))
	}
	if !w.hasDate {
		w.resp.AddHeader("date", httpDate())
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
