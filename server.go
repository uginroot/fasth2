// Package fasth2 replaces the HTTP/2 implementation of a net/http server
// (see ConfigureServer). Design borrows from hyper/h2:
//   - one reader goroutine per connection, no goroutine/channel per frame;
//   - handlers run on pooled worker goroutines and may block; frames from
//     many workers are coalesced into few write syscalls;
//   - reusable buffers for frames, header blocks, requests and responses.
package fasth2

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	frData         = 0x0
	frHeaders      = 0x1
	frPriority     = 0x2
	frRSTStream    = 0x3
	frSettings     = 0x4
	frPushPromise  = 0x5
	frPing         = 0x6
	frGoAway       = 0x7
	frWindowUpdate = 0x8
	frContinuation = 0x9

	flEndStream  = 0x1
	flAck        = 0x1
	flEndHeaders = 0x4
	flPadded     = 0x8
	flPriority   = 0x20
)

const (
	codeNo              = 0x0
	codeProtocol        = 0x1
	codeInternal        = 0x2
	codeFlowControl     = 0x3
	codeStreamClosed    = 0x5
	codeFrameSize       = 0x6
	codeRefusedStream   = 0x7
	codeCancel          = 0x8
	codeCompression     = 0x9
	codeEnhanceYourCalm = 0xb
	codeInadequateSec   = 0xc
)

const (
	clientPreface  = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	maxFrameSize   = 16384
	ourInitWindow  = 1 << 20
	ourConnWindow  = 1 << 20 // added on top of the default 65535
	maxWindow      = 1<<31 - 1
	maxHeaderBlock = 1 << 18
	readBufSize    = 1 << 16
	ringSize       = 256
	maxFreeStreams = 128

	// The reader stops reading new frames while more than this many bytes
	// wait to be written and a write is in progress (backpressure).
	maxPendingWrite = 1 << 18
	// Writes are split into chunks of this size; each chunk gets its own
	// write deadline (WriteByteTimeout).
	writeChunk = 64 << 10

	// At most this many SETTINGS frames with INITIAL_WINDOW_SIZE per
	// settingsWindow; each one walks all open streams.
	maxWindowSettings = 100
	settingsWindow    = 10 * time.Second

	defaultMaxStreams     = 250
	defaultMaxBody        = 16 << 20
	defaultMaxConnBody    = 64 << 20
	defaultMaxHeaderList  = 1 << 20
	defaultHandshakeTO    = 10 * time.Second
	defaultReadTO         = 60 * time.Second
	defaultIdleTO         = 120 * time.Second
	defaultWriteByteTO    = 30 * time.Second
	maxRetainedArena      = 64 << 10
	maxRetainedFields     = 256
	maxRetainedWriteBuf   = 1 << 20
	maxRetainedStreamBufs = 1 << 20
)

type connError uint32

func (connError) Error() string { return "http2: connection error" }

// request is valid only for the duration of the handler call; its slices
// alias stream buffers.
type request struct {
	remoteAddr string
	tls        *tls.ConnectionState
	method     []byte
	path       []byte
	authority  []byte
	header     []headerField // regular (non-pseudo) headers
	body       []byte

	c  *conn
	st *stream
}

// context returns the request context. It is canceled when the client resets
// the stream, the connection goes away or the handler returns.
func (r *request) context() context.Context {
	c, st := r.c, r.st
	if st.ctx != nil { // only the owning worker touches ctx creation
		return st.ctx
	}
	ctx, cancel := context.WithCancel(c.baseCtx)
	c.mu.Lock()
	st.ctx, st.cancel = ctx, cancel
	dead := st.canceled || c.closed
	c.mu.Unlock()
	if dead {
		cancel()
	}
	return ctx
}

// response is reused between requests on a connection.
type response struct {
	status        int
	contentLength int64  // -1: use len(body)
	hdr           []byte // pre-encoded HPACK fields
	body          []byte
}

func (r *response) reset() {
	r.status = 200
	r.contentLength = -1
	r.hdr = r.hdr[:0]
	r.body = r.body[:0]
}

// addHeader adds a response header. name must be a lowercase token and value
// must be valid (the net/http adapter checks both). content-length is added
// automatically.
func (r *response) addHeader(name, value string) { r.hdr = appendLiteral(r.hdr, name, value) }

func (r *response) write(p []byte)       { r.body = append(r.body, p...) }
func (r *response) writeString(s string) { r.body = append(r.body, s...) }

type handlerFunc func(req *request, resp *response)

// Server holds the HTTP/2 settings of ConfigureServer. For timeouts zero means
// the default and a negative value disables the timeout. A zero field takes
// the corresponding http.Server value when that one is set.
type Server struct {
	// MaxConcurrentStreams limits open streams per connection, including
	// streams the client reset while their handler still runs. Default 250.
	MaxConcurrentStreams uint32
	MaxRequestBodySize   int // per request; default 16 MiB
	// MaxConnBodySize limits request body bytes buffered on one connection
	// (received and not yet released by the handler). A stream that would
	// exceed it is reset with REFUSED_STREAM. Default 64 MiB.
	MaxConnBodySize int
	// MaxHeaderListSize limits the decoded request header list
	// (name+value+32 per field, RFC 9113 6.5.2); larger requests get 431.
	// Default 1 MiB, or http.Server.MaxHeaderBytes with ConfigureServer.
	MaxHeaderListSize int

	// HandshakeTimeout limits the time until the client preface and first
	// SETTINGS frame. Default 10s.
	HandshakeTimeout time.Duration
	// ReadTimeout limits the time from a request's HEADERS to its END_STREAM
	// (and of an unfinished header block). The stream is reset with CANCEL.
	// Default 60s, or http.Server.ReadTimeout.
	ReadTimeout time.Duration
	// IdleTimeout closes a connection with GOAWAY after this long without
	// open streams. Default 120s, or http.Server.IdleTimeout (ReadTimeout
	// when IdleTimeout is zero, like net/http).
	IdleTimeout time.Duration
	// WriteByteTimeout closes the connection when a chunk of up to 64 KiB
	// cannot be written within it, and resets a stream whose response waits
	// longer than this for flow-control credit. Default 30s, or
	// http.Server.WriteTimeout.
	WriteByteTimeout time.Duration

	// ErrorLog receives handler panics. Nil means http.Server.ErrorLog, else
	// the log package's standard logger.
	ErrorLog *log.Logger

	poolOnce sync.Once
	pool     *workerPool

	connMu sync.Mutex
	conns  map[*conn]struct{}
}

// shutdown sends GOAWAY to every connection; each connection is closed once
// its in-flight streams finish. It does not wait. Registered with
// http.Server.RegisterOnShutdown.
func (s *Server) shutdown() {
	s.connMu.Lock()
	cs := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		cs = append(cs, c)
	}
	s.connMu.Unlock()
	for _, c := range cs {
		c.mu.Lock()
		if !c.closed && !c.goingAway {
			c.goingAway = true
			c.writeGoAway(codeNo)
			c.flushLocked()
			c.maybeFinishLocked()
		}
		c.mu.Unlock()
	}
}

func (s *Server) track(c *conn, add bool) {
	s.connMu.Lock()
	if add {
		if s.conns == nil {
			s.conns = make(map[*conn]struct{})
		}
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	s.connMu.Unlock()
}

// ---------------- worker pool (fasthttp-style: reuse idle goroutines) ----------------

const maxIdleWorkers = 4096

type task struct {
	c  *conn
	st *stream
}

type worker struct{ ch chan task }

type workerPool struct {
	mu   sync.Mutex
	idle []*worker
}

func (p *workerPool) submit(t task) {
	p.mu.Lock()
	if n := len(p.idle); n > 0 {
		w := p.idle[n-1]
		p.idle[n-1] = nil
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		w.ch <- t
		return
	}
	p.mu.Unlock()
	w := &worker{ch: make(chan task, 1)}
	go w.run(p, t)
}

func (w *worker) run(p *workerPool, t task) {
	for {
		t.c.runHandler(t.st)
		p.mu.Lock()
		if len(p.idle) >= maxIdleWorkers {
			p.mu.Unlock()
			return
		}
		p.idle = append(p.idle, w)
		p.mu.Unlock()
		t = <-w.ch
	}
}

type stream struct {
	id         uint32
	halfClosed bool // END_STREAM received
	gotHeaders bool
	pending    bool
	sendWindow int64
	recvWindow int64
	recvUnack  uint32
	contentLen int64
	dataLen    int64
	regStart   int
	arena      []byte
	fields     []headerField
	method     []byte
	path       []byte
	scheme     []byte
	authority  []byte
	body       []byte
	out        []byte
	ctx        context.Context
	cancel     context.CancelFunc
	inHandler  bool // owned by a worker goroutine
	canceled   bool // stream went away while its handler was running
	orphan     bool // released while inHandler; still counts toward maxConc
	// deadline: request must be fully received by then (before dispatch), or
	// a flow-blocked response must make progress by then (pending).
	deadline time.Time
	req      request
	resp     response
}

func (s *stream) reset(id uint32, sendWin int64) {
	s.id = id
	s.halfClosed, s.gotHeaders, s.pending = false, false, false
	s.inHandler, s.canceled, s.orphan = false, false, false
	s.deadline = time.Time{}
	s.ctx, s.cancel = nil, nil
	s.sendWindow = sendWin
	s.recvWindow = ourInitWindow
	s.recvUnack = 0
	s.contentLen = -1
	s.dataLen = 0
	s.regStart = -1
	s.arena = s.arena[:0]
	s.fields = s.fields[:0]
	s.method, s.path, s.scheme, s.authority = nil, nil, nil, nil
	s.body = s.body[:0]
	s.out = s.out[:0]
}

type closedEntry struct {
	id    uint32
	reset bool // we sent RST_STREAM: silently ignore late frames
}

const (
	kindNew = iota
	kindTrailers
	kindRSTClosed
	kindRefuse
	kindIgnore
)

type conn struct {
	srv *Server
	nc  net.Conn

	// mu guards all connection state below except the read buffer, which is
	// owned by the reader goroutine.
	mu        sync.Mutex
	wcond     sync.Cond // on mu; signals write progress and close to the reader
	writing   bool      // some goroutine is inside nc.Write
	closed    bool
	goingAway bool
	wbuf2     []byte
	wdl       time.Time // write deadline currently set (owned by the writer)

	// limits and timeouts (see Server)
	maxHeaderList int
	maxConnBody   int
	readTO        time.Duration
	idleTO        time.Duration
	writeTO       time.Duration
	errorLog      *log.Logger

	orphans   int // streams released while their handler still runs
	bodyBytes int // request body bytes buffered on this connection

	// read deadline bookkeeping; rdl is the deadline set on nc. Deadlines may
	// be stale (earlier than needed): the reader then wakes up and re-arms.
	rdl        time.Time
	hsDeadline time.Time // preface + first SETTINGS
	idleSince  time.Time // zero while streams are open
	streamDL   time.Time // lower bound of open streams' deadlines
	hbDL       time.Time // header block (HEADERS+CONTINUATION) must finish by then

	iwWindow time.Time // SETTINGS INITIAL_WINDOW_SIZE rate limit
	iwCount  int

	handler    handlerFunc
	baseCtx    context.Context
	remoteAddr string
	tlsState   *tls.ConnectionState
	rbuf       []byte
	rpos       int
	rend       int
	wbuf       []byte
	hbuf       []byte
	dec        hpackDecoder

	prefaceDone  bool
	settingsSeen bool

	streams map[uint32]*stream
	pending []*stream
	free    []*stream
	discard stream // decodes header blocks of refused streams and trailers

	lastStreamID uint32
	ring         [ringSize]closedEntry
	ringPos      int

	peerInitWindow int64
	peerMaxFrame   int
	sendWindow     int64
	recvWindow     int64
	recvUnack      uint32
	maxConc        int
	maxBody        int

	// header block being assembled (HEADERS + CONTINUATION)
	hbID        uint32
	hbBlock     []byte
	hbStream    *stream
	hbKind      int
	hbEndStream bool
	hbSelfDep   bool
}

type connOpts struct {
	handler    handlerFunc
	ctx        context.Context
	tls        *tls.ConnectionState
	sawPreface bool
	hs         *http.Server // ConfigureServer: source of defaults
}

// timeout resolves a Server timeout: own value, else the http.Server one,
// else def. Negative disables (0).
func timeout(own, fromHS, def time.Duration) time.Duration {
	if own == 0 && fromHS > 0 {
		own = fromHS
	}
	if own < 0 {
		return 0
	}
	if own == 0 {
		return def
	}
	return own
}

func (s *Server) serveConn(nc net.Conn, o connOpts) {
	c := &conn{
		handler:        o.handler,
		baseCtx:        o.ctx,
		tlsState:       o.tls,
		prefaceDone:    o.sawPreface,
		srv:            s,
		nc:             nc,
		rbuf:           make([]byte, readBufSize),
		wbuf:           make([]byte, 0, 32*1024),
		dec:            newDecoder(),
		streams:        make(map[uint32]*stream),
		peerInitWindow: 65535,
		peerMaxFrame:   maxFrameSize,
		sendWindow:     65535,
		recvWindow:     65535 + ourConnWindow,
		maxConc:        int(s.MaxConcurrentStreams),
		maxBody:        s.MaxRequestBodySize,
		maxConnBody:    s.MaxConnBodySize,
		maxHeaderList:  s.MaxHeaderListSize,
		errorLog:       s.ErrorLog,
	}
	c.wcond.L = &c.mu
	s.poolOnce.Do(func() { s.pool = &workerPool{} })
	if c.maxConc <= 0 {
		c.maxConc = defaultMaxStreams
	}
	if c.maxBody <= 0 {
		c.maxBody = defaultMaxBody
	}
	if c.maxConnBody <= 0 {
		c.maxConnBody = defaultMaxConnBody
	}
	var hsRead, hsIdle, hsWrite time.Duration
	if hs := o.hs; hs != nil {
		hsRead, hsIdle, hsWrite = hs.ReadTimeout, hs.IdleTimeout, hs.WriteTimeout
		if hsIdle == 0 {
			hsIdle = hs.ReadTimeout // net/http: zero IdleTimeout means ReadTimeout
		}
		if c.maxHeaderList == 0 && hs.MaxHeaderBytes > 0 {
			c.maxHeaderList = hs.MaxHeaderBytes
		}
		if c.errorLog == nil {
			c.errorLog = hs.ErrorLog
		}
	}
	if c.maxHeaderList <= 0 {
		c.maxHeaderList = defaultMaxHeaderList
	}
	c.readTO = timeout(s.ReadTimeout, hsRead, defaultReadTO)
	c.idleTO = timeout(s.IdleTimeout, hsIdle, defaultIdleTO)
	c.writeTO = timeout(s.WriteByteTimeout, hsWrite, defaultWriteByteTO)
	// Also replaces any deadline left by net/http before the hand-off.
	if hsTO := timeout(s.HandshakeTimeout, 0, defaultHandshakeTO); hsTO > 0 {
		c.hsDeadline = time.Now().Add(hsTO)
	}
	c.rdl = c.hsDeadline
	nc.SetReadDeadline(c.rdl)
	nc.SetWriteDeadline(time.Time{})
	if c.baseCtx == nil {
		c.baseCtx = context.Background()
	}
	if ra := nc.RemoteAddr(); ra != nil {
		c.remoteAddr = ra.String()
	}
	s.track(c, true)
	defer s.track(c, false)
	defer c.cancelInflight()
	c.serve()
}

func (c *conn) logf(format string, args ...any) {
	if c.errorLog != nil {
		c.errorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// logPanic logs a recovered handler panic like net/http does.
func (c *conn) logPanic(r any) {
	if r == http.ErrAbortHandler {
		return
	}
	buf := make([]byte, 64<<10)
	buf = buf[:runtime.Stack(buf, false)]
	c.logf("fasth2: panic serving %s: %v\n%s", c.remoteAddr, r, buf)
}

// panicHook is called with a recovered connection-level panic. Tests set it
// to re-panic so that fuzzing and race tests surface bugs instead of
// silently dropping the connection.
var panicHook func(any)

func (c *conn) serve() {
	defer func() {
		if r := recover(); r != nil {
			c.nc.Close()
			if panicHook != nil {
				panicHook(r)
			}
		}
	}()
	c.mu.Lock()
	c.writeServerPreface()
	c.flushLocked()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		c.nc.Close()
		return
	}
	for {
		n, rerr := c.nc.Read(c.rbuf[c.rend:])
		c.mu.Lock()
		c.rend += n
		perr := c.processFramesSafe()
		if perr == nil && rerr != nil && errors.Is(rerr, os.ErrDeadlineExceeded) {
			rerr = nil
			perr = c.onReadDeadlineLocked()
		}
		if perr != nil {
			c.closed = true
			var ce connError
			if errors.As(perr, &ce) {
				// Let an in-flight write finish so GOAWAY goes last. The
				// writer stops after its current chunk (c.closed is set);
				// the write deadline bounds the wait.
				for c.writing {
					c.wcond.Wait()
				}
				c.closed = false
				c.writeGoAway(uint32(ce))
				c.flushLocked()
				c.closed = true
				c.mu.Unlock()
				c.closeGracefully()
				return
			}
			c.mu.Unlock()
			c.nc.Close()
			return
		}
		c.flushLocked()
		c.maybeFinishLocked()
		if rerr == nil && !c.closed {
			c.drainLocked()
		}
		if rerr != nil || c.closed {
			c.closed = true
			c.mu.Unlock()
			c.nc.Close()
			return
		}
		c.noteIdleLocked()
		c.mu.Unlock()
		if c.rpos == c.rend {
			c.rpos, c.rend = 0, 0
		} else if len(c.rbuf)-c.rpos < 9+maxFrameSize {
			c.rend = copy(c.rbuf, c.rbuf[c.rpos:c.rend])
			c.rpos = 0
		}
	}
}

// processFramesSafe runs processFrames and turns a panic (a bug in frame
// handling) into a connection error while c.mu is still held, so the
// deferred cleanup and Shutdown do not deadlock on c.mu.
func (c *conn) processFramesSafe() (err error) {
	defer func() {
		if r := recover(); r != nil {
			if panicHook != nil {
				panicHook(r)
			}
			c.logPanic(r)
			err = connError(codeInternal)
		}
	}()
	return c.processFrames()
}

var errHandshakeTimeout = errors.New("http2: handshake timeout")

func (c *conn) isIdleConn() bool { return len(c.streams) == 0 && c.orphans == 0 && c.hbID == 0 }

// armLocked makes sure the reader wakes up no later than t. Callable from
// workers: SetReadDeadline also affects a Read in progress.
func (c *conn) armLocked(t time.Time) {
	if c.closed || t.IsZero() {
		return
	}
	if c.rdl.IsZero() || t.Before(c.rdl) {
		c.rdl = t
		c.nc.SetReadDeadline(t)
	}
}

func (c *conn) noteStreamDeadlineLocked(t time.Time) {
	if c.streamDL.IsZero() || t.Before(c.streamDL) {
		c.streamDL = t
	}
	c.armLocked(t)
}

// noteIdleLocked starts the idle timer when the connection has just become
// idle and stops it when it is busy again.
func (c *conn) noteIdleLocked() {
	if c.idleTO <= 0 || c.closed {
		return
	}
	if !c.isIdleConn() {
		c.idleSince = time.Time{}
		return
	}
	if c.idleSince.IsZero() {
		c.idleSince = time.Now()
		c.armLocked(c.idleSince.Add(c.idleTO))
	}
}

// onReadDeadlineLocked handles an expired read deadline: the handshake and
// header-block timeouts close the connection, the idle timeout sends GOAWAY,
// expired streams are reset. Deadlines may be stale; then it only re-arms.
func (c *conn) onReadDeadlineLocked() error {
	if c.closed {
		return nil
	}
	now := time.Now()
	c.rdl = time.Time{}
	if !c.settingsSeen && !c.hsDeadline.IsZero() && !now.Before(c.hsDeadline) {
		return errHandshakeTimeout
	}
	if c.hbID != 0 && !c.hbDL.IsZero() && !now.Before(c.hbDL) {
		return connError(codeEnhanceYourCalm)
	}
	if !c.streamDL.IsZero() && !now.Before(c.streamDL) {
		c.streamDL = time.Time{}
		for _, st := range c.streams {
			if st.deadline.IsZero() || (c.hbID != 0 && st == c.hbStream) {
				continue
			}
			if !now.Before(st.deadline) {
				c.resetStream(st, codeCancel)
				continue
			}
			if c.streamDL.IsZero() || st.deadline.Before(c.streamDL) {
				c.streamDL = st.deadline
			}
		}
	}
	idle := c.idleTO > 0 && c.isIdleConn()
	if idle && !c.idleSince.IsZero() && now.Sub(c.idleSince) >= c.idleTO {
		c.goingAway = true
		return connError(codeNo)
	}
	// re-arm exactly
	var want time.Time
	earliest := func(t time.Time) {
		if !t.IsZero() && (want.IsZero() || t.Before(want)) {
			want = t
		}
	}
	if !c.settingsSeen {
		earliest(c.hsDeadline)
	}
	if c.hbID != 0 {
		earliest(c.hbDL)
	}
	earliest(c.streamDL)
	if idle {
		if c.idleSince.IsZero() {
			c.idleSince = now
		}
		earliest(c.idleSince.Add(c.idleTO))
	}
	// Always rewrite: the deadline on nc has expired, and leaving it (when
	// want is zero) would make every following Read fail at once.
	c.rdl = want
	c.nc.SetReadDeadline(want)
	return nil
}

// drainLocked is the reader's backpressure: while too much output is queued
// it waits for the writer (bounded by the write deadline) or writes itself,
// so a client that does not read cannot make the server buffer without limit.
func (c *conn) drainLocked() {
	for len(c.wbuf) > maxPendingWrite && !c.closed {
		if c.writing {
			c.wcond.Wait()
		} else {
			c.flushLocked()
		}
	}
}

// maybeFinishLocked closes a connection that sent GOAWAY and has no streams left.
func (c *conn) maybeFinishLocked() {
	if !c.goingAway || c.closed || len(c.streams) > 0 || c.orphans > 0 || c.writing {
		return
	}
	c.closed = true
	c.wcond.Broadcast()
	if cw, ok := c.nc.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	} else {
		c.nc.Close()
	}
}

func (c *conn) cancelInflight() {
	c.mu.Lock()
	c.closed = true
	for _, st := range c.streams {
		st.canceled = true
		if st.cancel != nil {
			st.cancel()
		}
	}
	c.mu.Unlock()
}

func (c *conn) closeGracefully() {
	if tc, ok := c.nc.(*net.TCPConn); ok {
		tc.CloseWrite()
		tc.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, tc)
	}
	c.nc.Close()
}

// flushLocked writes c.wbuf. Called with c.mu held; the lock is released
// during the syscall. If another goroutine is already writing, it returns at
// once: that writer will pick up whatever was appended meanwhile (write
// combining), so concurrent responses still leave in few syscalls.
func (c *conn) flushLocked() {
	if c.writing || c.closed {
		return
	}
	c.writing = true
	for len(c.wbuf) > 0 && !c.closed {
		buf := c.wbuf
		c.wbuf = c.wbuf2[:0]
		c.wcond.Broadcast() // output queue is empty again: the reader may go on
		c.mu.Unlock()
		err := c.writeAll(buf)
		c.mu.Lock()
		if cap(buf) <= maxRetainedWriteBuf {
			c.wbuf2 = buf[:0]
		} else {
			c.wbuf2 = nil
		}
		if err != nil {
			c.closed = true
			c.nc.Close()
		}
	}
	c.writing = false
	c.wcond.Broadcast()
}

// writeAll writes b in chunks; each chunk must complete within the write
// timeout (WriteByteTimeout/2..WriteByteTimeout). Only the goroutine that set
// c.writing calls it. After a write timeout the connection is closed (a
// tls.Conn cannot be used after a write timeout).
func (c *conn) writeAll(b []byte) error {
	for len(b) > 0 {
		n := min(len(b), writeChunk)
		if c.writeTO > 0 {
			now := time.Now()
			if c.wdl.Sub(now) < c.writeTO/2 {
				c.wdl = now.Add(c.writeTO)
				c.nc.SetWriteDeadline(c.wdl)
			}
		}
		m, err := c.nc.Write(b[:n])
		if err != nil {
			return err
		}
		b = b[m:]
	}
	return nil
}

// ---------------- frame writing ----------------

func appendFrameHeader(b []byte, length int, typ, flags byte, sid uint32) []byte {
	return append(b, byte(length>>16), byte(length>>8), byte(length), typ, flags,
		byte(sid>>24), byte(sid>>16), byte(sid>>8), byte(sid))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (c *conn) writeServerPreface() {
	c.wbuf = appendFrameHeader(c.wbuf, 18, frSettings, 0, 0)
	c.wbuf = append(c.wbuf, 0, 3) // MAX_CONCURRENT_STREAMS
	c.wbuf = appendU32(c.wbuf, uint32(c.maxConc))
	c.wbuf = append(c.wbuf, 0, 4) // INITIAL_WINDOW_SIZE
	c.wbuf = appendU32(c.wbuf, ourInitWindow)
	c.wbuf = append(c.wbuf, 0, 6) // MAX_HEADER_LIST_SIZE
	c.wbuf = appendU32(c.wbuf, uint32(c.maxHeaderList))
	c.writeWindowUpdate(0, ourConnWindow)
}

func (c *conn) writeRST(sid, code uint32) {
	c.wbuf = appendFrameHeader(c.wbuf, 4, frRSTStream, 0, sid)
	c.wbuf = appendU32(c.wbuf, code)
}

func (c *conn) writeWindowUpdate(sid, inc uint32) {
	c.wbuf = appendFrameHeader(c.wbuf, 4, frWindowUpdate, 0, sid)
	c.wbuf = appendU32(c.wbuf, inc)
}

func (c *conn) writeGoAway(code uint32) {
	c.wbuf = appendFrameHeader(c.wbuf, 8, frGoAway, 0, 0)
	c.wbuf = appendU32(c.wbuf, c.lastStreamID)
	c.wbuf = appendU32(c.wbuf, code)
}

// ---------------- reading ----------------

func (c *conn) processFrames() error {
	if !c.prefaceDone {
		avail := c.rend - c.rpos
		n := avail
		if n > len(clientPreface) {
			n = len(clientPreface)
		}
		if string(c.rbuf[c.rpos:c.rpos+n]) != clientPreface[:n] {
			return connError(codeProtocol)
		}
		if avail < len(clientPreface) {
			return nil
		}
		c.rpos += len(clientPreface)
		c.prefaceDone = true
	}
	for {
		avail := c.rend - c.rpos
		if avail < 9 {
			return nil
		}
		b := c.rbuf[c.rpos:c.rend]
		length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if length > maxFrameSize {
			return connError(codeFrameSize)
		}
		if avail < 9+length {
			return nil
		}
		typ, flags := b[3], b[4]
		sid := binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff
		payload := b[9 : 9+length]
		c.rpos += 9 + length
		if err := c.handleFrame(typ, flags, sid, payload); err != nil {
			return err
		}
		if len(c.wbuf) > maxPendingWrite {
			c.drainLocked()
			if c.closed {
				return io.ErrClosedPipe
			}
		}
	}
}

func (c *conn) handleFrame(typ, flags byte, sid uint32, p []byte) error {
	if !c.settingsSeen {
		if typ != frSettings || flags&flAck != 0 {
			return connError(codeProtocol)
		}
		c.settingsSeen = true
	}
	if c.hbID != 0 {
		if typ != frContinuation || sid != c.hbID {
			return connError(codeProtocol)
		}
		return c.onContinuation(flags, p)
	}
	switch typ {
	case frData:
		return c.onData(flags, sid, p)
	case frHeaders:
		return c.onHeaders(flags, sid, p)
	case frPriority:
		return c.onPriority(sid, p)
	case frRSTStream:
		return c.onRST(sid, p)
	case frSettings:
		return c.onSettings(flags, sid, p)
	case frPushPromise, frContinuation:
		return connError(codeProtocol)
	case frPing:
		if sid != 0 {
			return connError(codeProtocol)
		}
		if len(p) != 8 {
			return connError(codeFrameSize)
		}
		if flags&flAck == 0 {
			c.wbuf = appendFrameHeader(c.wbuf, 8, frPing, flAck, 0)
			c.wbuf = append(c.wbuf, p...)
		}
		return nil
	case frGoAway:
		if sid != 0 {
			return connError(codeProtocol)
		}
		if len(p) < 8 {
			return connError(codeFrameSize)
		}
		return nil
	case frWindowUpdate:
		return c.onWindowUpdate(sid, p)
	}
	return nil // unknown frame types are ignored
}

func (c *conn) isIdle(sid uint32) bool { return sid > c.lastStreamID || sid&1 == 0 }

func (c *conn) ringPush(id uint32, reset bool) {
	c.ring[c.ringPos] = closedEntry{id, reset}
	c.ringPos = (c.ringPos + 1) & (ringSize - 1)
}

func (c *conn) ringLookup(id uint32) (closedEntry, bool) {
	for i := range c.ring {
		if c.ring[i].id == id {
			return c.ring[i], true
		}
	}
	return closedEntry{}, false
}

func (c *conn) newStream(sid uint32) *stream {
	var st *stream
	if n := len(c.free); n > 0 {
		st = c.free[n-1]
		c.free = c.free[:n-1]
	} else {
		st = &stream{}
	}
	st.reset(sid, c.peerInitWindow)
	return st
}

// closeStream finishes a stream normally.
func (c *conn) closeStream(st *stream) {
	c.ringPush(st.id, false)
	c.release(st)
}

func (c *conn) release(st *stream) {
	if st == &c.discard {
		return
	}
	delete(c.streams, st.id)
	if st.inHandler {
		// The worker still uses it and drops the stream when done. Until
		// then it counts toward maxConc, so RST_STREAM cannot be used to run
		// more handlers than MaxConcurrentStreams (HTTP/2 Rapid Reset).
		st.canceled = true
		if !st.orphan {
			st.orphan = true
			c.orphans++
		}
		if st.cancel != nil {
			st.cancel()
		}
		return
	}
	if st.pending {
		st.pending = false
		for i, p := range c.pending {
			if p == st {
				c.pending = append(c.pending[:i], c.pending[i+1:]...)
				break
			}
		}
	}
	c.recycle(st)
}

// recycle releases a finished stream's body from the connection budget and
// keeps the stream for reuse when its buffers are small. Called exactly once
// per stream after it left c.streams and no handler uses it.
func (c *conn) recycle(st *stream) {
	c.bodyBytes -= len(st.body)
	st.body = st.body[:0]
	if len(c.free) < maxFreeStreams && cap(st.body) <= maxRetainedStreamBufs && cap(st.out) <= maxRetainedStreamBufs &&
		cap(st.arena) <= maxRetainedArena && cap(st.fields) <= maxRetainedFields {
		c.free = append(c.free, st)
	}
}

// resetStream sends RST_STREAM (stream error) and forgets the stream.
func (c *conn) resetStream(st *stream, code uint32) {
	c.writeRST(st.id, code)
	c.ringPush(st.id, true)
	c.release(st)
}

func (c *conn) streamError(sid, code uint32) {
	if st := c.streams[sid]; st != nil {
		c.resetStream(st, code)
		return
	}
	c.writeRST(sid, code)
	c.ringPush(sid, true)
}

// ---------------- HEADERS / CONTINUATION ----------------

func (c *conn) onHeaders(flags byte, sid uint32, p []byte) error {
	if sid == 0 {
		return connError(codeProtocol)
	}
	pad := 0
	if flags&flPadded != 0 {
		if len(p) < 1 {
			return connError(codeFrameSize)
		}
		pad = int(p[0])
		p = p[1:]
	}
	selfDep := false
	if flags&flPriority != 0 {
		if len(p) < 5 {
			return connError(codeFrameSize)
		}
		selfDep = binary.BigEndian.Uint32(p)&0x7fffffff == sid
		p = p[5:]
	}
	if pad > len(p) {
		return connError(codeProtocol)
	}
	p = p[:len(p)-pad]
	endStream := flags&flEndStream != 0

	var st *stream
	kind := kindNew
	if sid <= c.lastStreamID {
		if st = c.streams[sid]; st != nil {
			if st.halfClosed {
				kind = kindRSTClosed
			} else {
				kind = kindTrailers
			}
		} else {
			e, found := c.ringLookup(sid)
			if !found {
				return connError(codeProtocol) // stream id went backwards
			}
			if !e.reset {
				return connError(codeStreamClosed)
			}
			kind = kindIgnore
		}
	} else {
		if sid&1 == 0 {
			return connError(codeProtocol)
		}
		c.lastStreamID = sid
		switch {
		case len(c.streams)+c.orphans >= c.maxConc || c.goingAway:
			kind = kindRefuse
		default:
			st = c.newStream(sid)
			c.streams[sid] = st
			if c.readTO > 0 && (!endStream || flags&flEndHeaders == 0) {
				st.deadline = time.Now().Add(c.readTO)
				c.noteStreamDeadlineLocked(st.deadline)
			}
		}
	}
	if flags&flEndHeaders != 0 {
		return c.finishHeaders(sid, st, kind, endStream, selfDep, p)
	}
	c.hbID, c.hbStream, c.hbKind, c.hbEndStream, c.hbSelfDep = sid, st, kind, endStream, selfDep
	c.hbBlock = append(c.hbBlock[:0], p...)
	if c.readTO > 0 {
		c.hbDL = time.Now().Add(c.readTO)
		c.armLocked(c.hbDL)
	}
	return nil
}

func (c *conn) onContinuation(flags byte, p []byte) error {
	c.hbBlock = append(c.hbBlock, p...)
	if len(c.hbBlock) > maxHeaderBlock {
		return connError(codeEnhanceYourCalm)
	}
	if flags&flEndHeaders == 0 {
		return nil
	}
	sid := c.hbID
	c.hbID = 0
	return c.finishHeaders(sid, c.hbStream, c.hbKind, c.hbEndStream, c.hbSelfDep, c.hbBlock)
}

func (c *conn) finishHeaders(sid uint32, st *stream, kind int, endStream, selfDep bool, block []byte) error {
	target := st
	if kind != kindNew {
		target = &c.discard
		target.arena, target.fields = target.arena[:0], target.fields[:0]
	}
	// The block is always decoded completely to keep the HPACK dynamic table
	// in sync; tooLarge only stops collecting fields.
	tooLarge, err := c.dec.decode(block, &target.arena, &target.fields, c.maxHeaderList)
	if err != nil {
		return connError(codeCompression)
	}
	if kind != kindNew && cap(c.discard.arena) > maxRetainedArena {
		c.discard.arena = nil
	}
	switch kind {
	case kindIgnore:
		return nil
	case kindRefuse:
		c.writeRST(sid, codeRefusedStream)
		c.ringPush(sid, true)
		return nil
	case kindRSTClosed:
		c.resetStream(st, codeStreamClosed)
		return nil
	case kindTrailers:
		if tooLarge {
			c.resetStream(st, codeEnhanceYourCalm)
			return nil
		}
		if !endStream || selfDep || !validTrailers(c.discard.fields) {
			c.resetStream(st, codeProtocol)
			return nil
		}
		st.halfClosed = true
		if st.contentLen >= 0 && st.dataLen != st.contentLen {
			c.resetStream(st, codeProtocol)
			return nil
		}
		return c.dispatch(st)
	}
	// kindNew
	if tooLarge {
		c.rejectHeaderTooLarge(st, endStream)
		return nil
	}
	if selfDep || !parseRequest(st) {
		c.resetStream(st, codeProtocol)
		return nil
	}
	st.gotHeaders = true
	if endStream {
		st.halfClosed = true
		if st.contentLen > 0 {
			c.resetStream(st, codeProtocol)
			return nil
		}
		return c.dispatch(st)
	}
	return nil
}

// rejectHeaderTooLarge answers 431 Request Header Fields Too Large. If the
// client is still sending the request, the stream is then reset with
// NO_ERROR (RFC 9113 8.1) and late frames are ignored.
func (c *conn) rejectHeaderTooLarge(st *stream, endStream bool) {
	hb := appendStatus(c.hbuf[:0], 431)
	hb = appendHpackInt(hb, 0x00, 4, 28) // content-length: 0
	hb = appendUintString(hb, 0)
	c.hbuf = hb
	c.writeHeaderFrames(st.id, hb, true)
	if !endStream {
		c.writeRST(st.id, codeNo)
	}
	c.ringPush(st.id, !endStream)
	c.release(st)
}

func parseUint(b []byte) (int64, bool) {
	if len(b) == 0 || len(b) > 18 {
		return 0, false
	}
	var v int64
	for _, ch := range b {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		v = v*10 + int64(ch-'0')
	}
	return v, true
}

const (
	hasMethod = 1 << iota
	hasPath
	hasScheme
	hasAuthority
)

// parseRequest extracts pseudo-headers and checks that the request is well
// formed (RFC 9113 8.2-8.3): field names and values, pseudo-header values,
// connection-specific fields, content-length, Host vs :authority.
func parseRequest(st *stream) bool {
	seen := 0
	regular := false
	hosts := 0
	var host []byte
	for i := range st.fields {
		f := &st.fields[i]
		n := f.Name
		if len(n) == 0 {
			return false
		}
		if n[0] == ':' {
			if regular {
				return false
			}
			var bit int
			switch string(n) {
			case ":method":
				bit, st.method = hasMethod, f.Value
			case ":path":
				bit, st.path = hasPath, f.Value
			case ":scheme":
				bit, st.scheme = hasScheme, f.Value
			case ":authority":
				bit, st.authority = hasAuthority, f.Value
			default:
				return false
			}
			if seen&bit != 0 {
				return false
			}
			seen |= bit
			continue
		}
		if !validFieldName(n) || !validFieldValue(f.Value) {
			return false
		}
		if !regular {
			regular = true
			st.regStart = i
		}
		switch string(n) {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			return false
		case "te":
			if string(f.Value) != "trailers" {
				return false
			}
		case "content-length":
			v, ok := parseUint(f.Value)
			if !ok || (st.contentLen >= 0 && st.contentLen != v) {
				return false
			}
			st.contentLen = v
		case "host":
			if hosts++; hosts > 1 || !validHost(f.Value) {
				return false
			}
			host = f.Value
		}
	}
	if seen&hasMethod == 0 || !validToken(st.method) {
		return false
	}
	if seen&hasAuthority != 0 {
		if !validHost(st.authority) {
			return false
		}
		// RFC 9113 8.3.1: Host must not name another origin than :authority.
		if hosts > 0 && !equalFold(host, st.authority) {
			return false
		}
	}
	if string(st.method) == "CONNECT" {
		return seen&(hasPath|hasScheme) == 0 && seen&hasAuthority != 0 && len(st.authority) > 0
	}
	return seen&(hasPath|hasScheme) == hasPath|hasScheme && validScheme(st.scheme) && validPath(st.path, st.method)
}

func equalFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func validTrailers(fields []headerField) bool {
	for i := range fields {
		if !validFieldName(fields[i].Name) || !validFieldValue(fields[i].Value) {
			return false
		}
	}
	return true
}

// ---------------- DATA ----------------

func (c *conn) onData(flags byte, sid uint32, p []byte) error {
	if sid == 0 {
		return connError(codeProtocol)
	}
	flen := len(p)
	if flags&flPadded != 0 {
		if len(p) < 1 {
			return connError(codeFrameSize)
		}
		pad := int(p[0])
		p = p[1:]
		if pad > len(p) {
			return connError(codeProtocol)
		}
		p = p[:len(p)-pad]
	}
	c.recvWindow -= int64(flen)
	if c.recvWindow < 0 {
		return connError(codeFlowControl)
	}
	c.recvUnack += uint32(flen)
	if c.recvUnack >= ourConnWindow/2 {
		c.writeWindowUpdate(0, c.recvUnack)
		c.recvWindow += int64(c.recvUnack)
		c.recvUnack = 0
	}
	var st *stream
	if sid <= c.lastStreamID {
		st = c.streams[sid]
	}
	if st == nil {
		if c.isIdle(sid) {
			return connError(codeProtocol)
		}
		if e, found := c.ringLookup(sid); found && e.reset {
			return nil
		}
		return connError(codeStreamClosed)
	}
	if st.halfClosed {
		c.resetStream(st, codeStreamClosed)
		return nil
	}
	st.recvWindow -= int64(flen)
	if st.recvWindow < 0 {
		c.resetStream(st, codeFlowControl)
		return nil
	}
	st.dataLen += int64(len(p))
	if st.contentLen >= 0 && st.dataLen > st.contentLen {
		c.resetStream(st, codeProtocol)
		return nil
	}
	if len(st.body)+len(p) > c.maxBody {
		c.resetStream(st, codeCancel)
		return nil
	}
	// Flow-control windows are replenished on receipt, so they do not bound
	// buffered bodies; this per-connection budget does.
	if c.bodyBytes+len(p) > c.maxConnBody {
		c.resetStream(st, codeRefusedStream)
		return nil
	}
	st.body = append(st.body, p...)
	c.bodyBytes += len(p)
	if flags&flEndStream != 0 {
		st.halfClosed = true
		if st.contentLen >= 0 && st.dataLen != st.contentLen {
			c.resetStream(st, codeProtocol)
			return nil
		}
		return c.dispatch(st)
	}
	st.recvUnack += uint32(flen)
	if st.recvUnack >= ourInitWindow/2 {
		c.writeWindowUpdate(sid, st.recvUnack)
		st.recvWindow += int64(st.recvUnack)
		st.recvUnack = 0
	}
	return nil
}

// ---------------- control frames ----------------

func (c *conn) onPriority(sid uint32, p []byte) error {
	if sid == 0 {
		return connError(codeProtocol)
	}
	if len(p) != 5 {
		c.streamError(sid, codeFrameSize)
		return nil
	}
	if binary.BigEndian.Uint32(p)&0x7fffffff == sid {
		c.streamError(sid, codeProtocol)
	}
	return nil
}

func (c *conn) onRST(sid uint32, p []byte) error {
	if sid == 0 {
		return connError(codeProtocol)
	}
	if len(p) != 4 {
		return connError(codeFrameSize)
	}
	if c.isIdle(sid) {
		return connError(codeProtocol)
	}
	if st := c.streams[sid]; st != nil {
		c.ringPush(sid, false)
		c.release(st)
	}
	return nil
}

func (c *conn) onSettings(flags byte, sid uint32, p []byte) error {
	if sid != 0 {
		return connError(codeProtocol)
	}
	if flags&flAck != 0 {
		if len(p) != 0 {
			return connError(codeFrameSize)
		}
		return nil
	}
	if len(p)%6 != 0 {
		return connError(codeFrameSize)
	}
	newInit, haveInit := int64(0), false
	for ; len(p) > 0; p = p[6:] {
		id := binary.BigEndian.Uint16(p)
		val := binary.BigEndian.Uint32(p[2:])
		switch id {
		case 2: // ENABLE_PUSH
			if val > 1 {
				return connError(codeProtocol)
			}
		case 4: // INITIAL_WINDOW_SIZE: only the last value matters (deltas add up)
			if val > maxWindow {
				return connError(codeFlowControl)
			}
			newInit, haveInit = int64(val), true
		case 5: // MAX_FRAME_SIZE
			if val < 16384 || val > 1<<24-1 {
				return connError(codeProtocol)
			}
			c.peerMaxFrame = int(val)
		}
	}
	if haveInit {
		// Applying a window change walks every open stream: limit how often
		// a peer can make us do it.
		now := time.Now()
		if now.Sub(c.iwWindow) >= settingsWindow {
			c.iwWindow, c.iwCount = now, 0
		}
		if c.iwCount++; c.iwCount > maxWindowSettings {
			return connError(codeEnhanceYourCalm)
		}
		if delta := newInit - c.peerInitWindow; delta != 0 {
			for _, st := range c.streams {
				st.sendWindow += delta
				if st.sendWindow > maxWindow {
					return connError(codeFlowControl)
				}
			}
		}
		c.peerInitWindow = newInit
	}
	c.wbuf = appendFrameHeader(c.wbuf, 0, frSettings, flAck, 0)
	c.flushPending()
	return nil
}

func (c *conn) onWindowUpdate(sid uint32, p []byte) error {
	if len(p) != 4 {
		return connError(codeFrameSize)
	}
	inc := int64(binary.BigEndian.Uint32(p) & 0x7fffffff)
	if sid == 0 {
		if inc == 0 {
			return connError(codeProtocol)
		}
		c.sendWindow += inc
		if c.sendWindow > maxWindow {
			return connError(codeFlowControl)
		}
		c.flushPending()
		return nil
	}
	if c.isIdle(sid) {
		return connError(codeProtocol)
	}
	if inc == 0 {
		c.streamError(sid, codeProtocol)
		return nil
	}
	st := c.streams[sid]
	if st == nil {
		return nil
	}
	st.sendWindow += inc
	if st.sendWindow > maxWindow {
		c.resetStream(st, codeFlowControl)
		return nil
	}
	if st.pending {
		c.flushPending()
	}
	return nil
}

// ---------------- responses ----------------

// dispatch hands a fully received request to a worker goroutine.
func (c *conn) dispatch(st *stream) error {
	st.deadline = time.Time{} // request fully received; handler time is not limited here
	st.inHandler = true
	c.srv.pool.submit(task{c, st})
	return nil
}

// runHandler executes on a worker goroutine.
func (c *conn) runHandler(st *stream) {
	req, resp := &st.req, &st.resp
	req.c, req.st, req.remoteAddr, req.tls = c, st, c.remoteAddr, c.tlsState
	req.method, req.path, req.authority = st.method, st.path, st.authority
	if st.regStart >= 0 {
		req.header = st.fields[st.regStart:]
	} else {
		req.header = nil
	}
	req.body = st.body
	resp.reset()
	panicked := true
	func() {
		defer func() {
			if r := recover(); r != nil {
				c.logPanic(r)
			}
		}()
		c.handler(req, resp)
		panicked = false
	}()
	c.mu.Lock()
	st.inHandler = false
	cancel := st.cancel
	st.ctx, st.cancel = nil, nil
	switch {
	case st.orphan: // reset by the client while the handler ran
		st.orphan = false
		c.orphans--
		c.recycle(st)
	case c.closed || st.canceled:
		// connection is gone; the stream may still sit in c.streams
	case panicked:
		c.resetStream(st, codeInternal)
	default:
		c.writeResponse(st, resp)
	}
	c.flushLocked()
	c.maybeFinishLocked()
	c.noteIdleLocked()
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *conn) writeResponse(st *stream, resp *response) error {
	hb := appendStatus(c.hbuf[:0], resp.status)
	hb = append(hb, resp.hdr...)
	if resp.status != 204 && resp.status != 304 {
		cl := resp.contentLength
		if cl < 0 {
			cl = int64(len(resp.body))
		}
		hb = appendHpackInt(hb, 0x00, 4, 28) // content-length
		hb = appendUintString(hb, uint64(cl))
	}
	c.hbuf = hb
	endStream := len(resp.body) == 0
	c.writeHeaderFrames(st.id, hb, endStream)
	if endStream {
		c.closeStream(st)
		return nil
	}
	rem := c.sendData(st.id, &st.sendWindow, resp.body)
	if len(rem) == 0 {
		c.closeStream(st)
		return nil
	}
	st.out = append(st.out[:0], rem...)
	st.pending = true
	c.pending = append(c.pending, st)
	if c.writeTO > 0 { // the client must grant flow-control credit in time
		st.deadline = time.Now().Add(c.writeTO)
		c.noteStreamDeadlineLocked(st.deadline)
	}
	return nil
}

func (c *conn) writeHeaderFrames(sid uint32, hb []byte, endStream bool) {
	first := true
	for {
		n := len(hb)
		if n > c.peerMaxFrame {
			n = c.peerMaxFrame
		}
		typ, fl := byte(frContinuation), byte(0)
		if first {
			typ = frHeaders
			if endStream {
				fl |= flEndStream
			}
		}
		if n == len(hb) {
			fl |= flEndHeaders
		}
		c.wbuf = appendFrameHeader(c.wbuf, n, typ, fl, sid)
		c.wbuf = append(c.wbuf, hb[:n]...)
		hb = hb[n:]
		first = false
		if len(hb) == 0 {
			return
		}
	}
}

func (c *conn) sendData(sid uint32, win *int64, data []byte) []byte {
	for len(data) > 0 {
		n := int64(len(data))
		if n > int64(c.peerMaxFrame) {
			n = int64(c.peerMaxFrame)
		}
		if n > *win {
			n = *win
		}
		if n > c.sendWindow {
			n = c.sendWindow
		}
		if n <= 0 {
			break
		}
		fl := byte(0)
		if int(n) == len(data) {
			fl = flEndStream
		}
		c.wbuf = appendFrameHeader(c.wbuf, int(n), frData, fl, sid)
		c.wbuf = append(c.wbuf, data[:n]...)
		*win -= n
		c.sendWindow -= n
		data = data[n:]
	}
	return data
}

func (c *conn) flushPending() {
	if len(c.pending) == 0 {
		return
	}
	j := 0
	var now time.Time
	for i := 0; i < len(c.pending); i++ {
		st := c.pending[i]
		before := len(st.out)
		rem := c.sendData(st.id, &st.sendWindow, st.out)
		if len(rem) == 0 {
			st.pending = false
			c.ringPush(st.id, false)
			delete(c.streams, st.id)
			c.recycle(st)
			continue
		}
		if len(rem) < before && c.writeTO > 0 {
			// progress: extend the deadline (c.streamDL stays a valid lower bound)
			if now.IsZero() {
				now = time.Now()
			}
			st.deadline = now.Add(c.writeTO)
		}
		st.out = st.out[:copy(st.out, rem)]
		c.pending[j] = st
		j++
	}
	for k := j; k < len(c.pending); k++ {
		c.pending[k] = nil
	}
	c.pending = c.pending[:j]
}
