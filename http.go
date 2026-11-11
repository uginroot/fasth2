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
// Not supported: Hijacker, 1xx responses, request trailers.
// Flush (http.Flusher) отправляет заголовки и записанное тело сразу.
// Трейлеры ответа поддержаны: ключи с префиксом http.TrailerPrefix и ключи,
// объявленные в заголовке "Trailer" (как в net/http).
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
	// Запрос сразу с контекстом: WithContext на готовом запросе скопировал бы
	// его ещё раз (вторая аллокация http.Request на каждый запрос).
	hr := (&http.Request{}).WithContext(req.context())
	hr.Method = method
	hr.Proto = "HTTP/2.0"
	hr.ProtoMajor = 2
	hr.Header = make(http.Header, len(req.header))
	hr.RemoteAddr = req.remoteAddr
	hr.TLS = req.tls
	hr.Host = req.authorityStr
	if hr.Host == "" {
		hr.Host = string(req.authority)
	}
	if method == "CONNECT" {
		hr.URL = &url.URL{Host: hr.Host}
		hr.RequestURI = hr.Host
	} else {
		hr.RequestURI = req.pathStr
		if hr.RequestURI == "" {
			hr.RequestURI = string(req.path)
		}
		u := fastURL(hr.RequestURI)
		if u == nil {
			var err error
			if u, err = url.ParseRequestURI(hr.RequestURI); err != nil {
				resp.status = 400
				return
			}
		}
		hr.URL = u
	}
	var cookies []string
	// Один массив на значения всех заголовков вместо []string на каждый.
	// Срезы с cap = len: append в обработчике скопирует, а не затрёт соседа.
	vals := make([]string, len(req.header))
	nv := 0
	for i := range req.header {
		f := &req.header[i]
		if string(f.Name) == "cookie" { // RFC 9113 8.2.3: re-join cookie crumbs
			cookies = append(cookies, string(f.Value))
			continue
		}
		// Поле из таблицы HPACK — готовые строки (без аллокации на запрос).
		k, v := f.key, f.sval
		if k == "" {
			k = canonicalKey(f.Name)
		}
		if v == "" && len(f.Value) > 0 {
			v = string(f.Value)
		}
		if prev, ok := hr.Header[k]; ok {
			hr.Header[k] = append(prev, v)
			continue
		}
		vals[nv] = v
		hr.Header[k] = vals[nv : nv+1 : nv+1]
		nv++
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
	var sbody *streamBody
	switch {
	case req.streaming: // тело ещё приходит, длина неизвестна
		hr.ContentLength = -1
		sbody = &streamBody{c: req.c, st: req.st, gen: req.gen}
		hr.Body = sbody
	case len(req.body) == 0:
		hr.Body = http.NoBody
	default:
		body = &reqBody{b: req.body}
		hr.Body = body
	}

	rw := &responseWriter{resp: resp, req: req, header: make(http.Header), head: method == "HEAD"}
	h.ServeHTTP(rw, hr)
	// req.body and resp are stream buffers that the next request on this
	// connection reuses. Detach them before returning, so a goroutine that
	// outlives the handler (http.TimeoutHandler does that) gets an error
	// instead of another request's body or another response.
	if body != nil {
		body.finish()
	}
	if sbody != nil {
		sbody.Close()
	}
	rw.finish()
}

// rwState — состояние responseWriter, которое живёт в response потока (он
// повторно используется), а не в самом responseWriter (аллокация на запрос).
// Транспорт только вызывает reset перед новым запросом.
type rwState struct {
	clen     int64    // явный Content-Length (HEAD), -1 — не задан
	headN    int64    // байт, «записанных» в ответ на HEAD
	declared []string // имена из заголовка "Trailer" (канонический вид)
}

func (s *rwState) reset() {
	s.clen, s.headN = -1, 0
	clear(s.declared)
	s.declared = s.declared[:0]
}

// streamBody — тело запроса, которое приходит, пока обработчик работает.
// Read ждёт данных (conn.readBody); после конца обработчика — ошибка.
type streamBody struct {
	c      *conn
	st     *stream
	gen    uint64
	closed atomic.Bool
}

func (b *streamBody) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	if len(p) == 0 {
		return 0, nil
	}
	return b.c.readBody(b.st, b.gen, p)
}

func (b *streamBody) Close() error {
	b.closed.Store(true)
	return nil
}

// fastURL разбирает простой путь запроса без url.ParseRequestURI: путь только
// из букв, цифр и "/-_.~", запрос после "?" берётся как есть (так же делает
// ParseRequestURI). Для остального (%, ;, # и т. д.) — nil, тогда разбирает
// url.ParseRequestURI. parseRequest уже проверил, что управляющих символов нет.
func fastURL(s string) *url.URL {
	if len(s) == 0 || s[0] != '/' {
		return nil
	}
	path, query, hasQuery := s, "", false
	if i := strings.IndexByte(s, '?'); i >= 0 {
		path, query, hasQuery = s[:i], s[i+1:], true
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			c == '/' || c == '-' || c == '_' || c == '.' || c == '~') {
			return nil
		}
	}
	if strings.IndexByte(query, '#') >= 0 {
		return nil
	}
	return &url.URL{Path: path, RawQuery: query, ForceQuery: hasQuery && query == ""}
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
	req     *request // для Flush: соединение и поток
	flushed bool     // был Flush: заголовки ушли, ответ идёт частями
	header  http.Header
	status  int
	wrote   bool
	done    bool // handler returned; resp belongs to the stream again
	head    bool
	hasType bool
	hasDate bool
	// clen, headN и имена из заголовка "Trailer" живут в w.resp.rw (rwState):
	// так responseWriter — 48 байт, а не 96 (аллокация на запрос).
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
	w.resp.rw.clen = -1
	w.resp.status = code
	for _, v := range w.header["Trailer"] {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				w.resp.rw.declared = append(w.resp.rw.declared, http.CanonicalHeaderKey(name))
			}
		}
	}
	for k, vs := range w.header {
		if w.isDeclared(k) {
			continue // уйдёт трейлером
		}
		lk := lowerKey(k)
		if !validFieldName(lk) { // also drops pseudo-header names (":...")
			continue
		}
		if connectionSpecific(lk) || lk == "trailer" {
			continue
		}
		switch lk {
		case "content-length":
			if len(vs) > 0 {
				if n, err := strconv.ParseInt(vs[0], 10, 64); err == nil && n >= 0 {
					w.resp.rw.clen = n
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
		w.resp.rw.headN += int64(len(p))
		if !w.hasType && w.resp.rw.headN == int64(len(p)) && len(p) > 0 {
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

// Flush отправляет заголовки и уже записанное тело, не дожидаясь конца
// обработчика (http.Flusher). Так работают server stream и bidi в connect-go
// и grpc-go, SSE. Пока клиент не даёт окна, а в очереди потока больше
// maxStreamOut байт, Flush ждёт (как Write в net/http).
func (w *responseWriter) Flush() { w.FlushError() }

// FlushError — Flush с ошибкой (его вызывает http.ResponseController).
func (w *responseWriter) FlushError() error {
	w.mu.Lock()
	if w.done {
		w.mu.Unlock()
		return errWriteAfterHandler
	}
	if !w.wrote {
		w.writeHeaderLocked(200)
	}
	if !w.flushed {
		w.flushed = true
		// Заголовки уходят сейчас: content-type и date добавляются здесь, а не в finish.
		if body := w.resp.body; !w.hasType && len(body) > 0 && bodyAllowed(w.status) {
			w.resp.addHeader("content-type", http.DetectContentType(body[:min(len(body), 512)]))
			w.hasType = true
		}
		if !w.hasDate {
			w.resp.addHeader("date", httpDate())
			w.hasDate = true
		}
	}
	c, st := w.req.c, w.req.st
	gen, err := c.flushQueue(st, w.resp)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	// Окна клиента ждём без w.mu: иначе обработчик, который вернулся, пока
	// другая горутина ждёт в Flush, встал бы в finish до таймаута записи.
	return c.flushWait(st, gen)
}

func (w *responseWriter) finish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.wrote {
		w.writeHeaderLocked(200)
	}
	w.done = true
	body := w.resp.body
	if !w.flushed && !w.hasType && len(body) > 0 && bodyAllowed(w.status) {
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
		if !w.flushed {
			if w.resp.rw.clen >= 0 {
				w.resp.contentLength = w.resp.rw.clen
			} else {
				w.resp.contentLength = w.resp.rw.headN
			}
		}
		// У ответа на HEAD нет тела, и трейлеры не отправляются (как в x/net):
		// иначе HEADERS ушли бы без content-length.
		return
	}
	w.appendTrailers()
}

func (w *responseWriter) isDeclared(k string) bool {
	for _, d := range w.resp.rw.declared {
		if d == k {
			return true
		}
	}
	return false
}

// appendTrailers собирает трейлеры ответа в w.resp.trailers, как их понимает
// net/http: ключи с префиксом http.TrailerPrefix ("Trailer:Grpc-Status") и
// ключи, объявленные в заголовке "Trailer" до WriteHeader. Так отдают статус
// gRPC (grpc-status, grpc-message) connect-go и grpc-go.
func (w *responseWriter) appendTrailers() {
	for k, vs := range w.header {
		var name string
		switch {
		case strings.HasPrefix(k, http.TrailerPrefix):
			name = strings.ToLower(k[len(http.TrailerPrefix):])
		case w.isDeclared(k):
			name = lowerKey(k)
		default:
			continue
		}
		if !validTrailerName(name) {
			continue
		}
		for _, v := range vs {
			if validFieldValue(v) {
				w.resp.addTrailer(name, v)
			}
		}
	}
}

// validTrailerName отсекает псевдозаголовки и поля, которые не могут быть
// трейлерами (RFC 9110 6.5.1, RFC 9113 8.2.2).
func validTrailerName(name string) bool {
	if !validFieldName(name) || connectionSpecific(name) {
		return false
	}
	switch name {
	case "te", "trailer", "content-length", "host":
		return false
	}
	return true
}

// connectionSpecific: поля соединения, запрещённые в HTTP/2 (RFC 9113 8.2.2).
// Их нет ни в заголовках, ни в трейлерах ответа.
func connectionSpecific(name string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	}
	return false
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
