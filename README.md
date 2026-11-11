# fasth2

[![CI](https://github.com/uginroot/fasth2/actions/workflows/ci.yml/badge.svg)](https://github.com/uginroot/fasth2/actions/workflows/ci.yml)

A fast HTTP/2 server for Go. Passes all 146 [h2spec](https://github.com/summerwind/h2spec)
conformance tests and can replace the HTTP/2 implementation of an existing
`net/http` server with one line.

> **Status: experimental.** Well tested for protocol conformance, not yet battle-tested
> in production. See [Limitations](#limitations).

## Why it is fast

The design follows hyper/h2 rather than `net/http`:

- one reader goroutine per connection, no goroutine + channels per frame;
- handlers run on a worker pool; frames from many workers are coalesced into
  shared writes (write combining), one write per response instead of two;
- a handler that finishes while other handlers of the same connection still run
  yields the processor once, so responses that complete together leave in one
  write (one write per ~50 responses at 16 connections × 64 streams on one core);
- reusable buffers for frames, header blocks, requests and responses;
- own HPACK decoder, and an encoder with a per-connection dynamic table: a repeated
  response header block (`content-type`, `date`, `grpc-status`...) takes a few bytes;
- h2c: the reader runs inside one `RawConn.Read` for the connection's life, so after a
  short read it waits for readiness without the extra `read` that returns EAGAIN
  (one `read` per round instead of two);
- the `net/http` adapter builds one `http.Request` per request (not two), keeps all header
  values in one array, parses simple paths without `url.ParseRequestURI`, and derives the
  request context without registering it in the connection's context;
- header strings that come from the HPACK table (repeated `user-agent`, `:authority`, `:path`,
  gRPC headers) are made once per table entry, not once per request.

## Usage

```go
srv := &http.Server{Addr: ":8443", Handler: router} // gorilla/mux, chi, http.ServeMux, middleware...
fasth2.ConfigureServer(srv, nil)                   // the whole migration
log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
```

HTTP/1.1, TLS, `Shutdown` and your handlers stay `net/http`; only HTTP/2
connections are served by fasth2 (via the standard `http.Server.TLSNextProto`
hook, Go 1.24+). For h2c enable `srv.Protocols.SetUnencryptedHTTP2(true)` as usual.
If you build your own `tls.Listener`, add `"h2"` to `NextProtos`.

Handlers run on fasth2 worker goroutines and may block, like under `net/http`.
To change limits and timeouts, pass a `*fasth2.Server` instead of `nil` (see below).

gRPC and streaming work through the same drop-in (checked with connect-go:
Connect, gRPC and gRPC-Web, unary, server/client/bidi streaming, errors, deadlines,
cancellation):

- response trailers: `http.TrailerPrefix` keys and names declared in the `Trailer`
  header, as in `net/http` (gRPC status goes this way);
- `http.Flusher` / `http.ResponseController.Flush`: headers and the body written so
  far leave at once; while more than 256 KiB of a stream's response waits for the
  client's flow-control window, `Flush` blocks (bounded by `WriteByteTimeout`);
- full duplex for streaming RPC: a request with `content-type: application/grpc*` or
  `application/connect+*` and no `content-length` starts its handler as soon as its
  body does not arrive within one read, and `r.Body` returns data as it arrives.
  The stream's flow-control window is given back as the handler reads, so a fast
  client waits for a slow handler instead of being reset, and at most one window
  (1 MiB, or less with a smaller `MaxRequestBodySize`) of unread body is held per stream. Other requests are buffered whole
  before the handler runs, as before.

## Benchmarks

h2load, "Hello, World!" response, 1 vCPU shared by server and load generator,
Go 1.27.3. Requests/second (connections × streams per connection). Same gorilla/mux
app, only `ConfigureServer` differs. Measured before the connection limits and
timeouts were added; in a local comparison they cost 0–4% CPU per request.
Re-measure on your own hardware.

| route, load | h2c net/http → fasth2 | TLS net/http → fasth2 |
|---|---|---|
| `/` 100×100 | 30k → 98k (×3.3) | 27k → 79k (×3.0) |
| `/users/{id}` JSON 100×100 | 25k → 65k (×2.6) | 22k → 61k (×2.7) |
| `/sleep` (1 ms) 100×100 | 32k → 66k (×2.0) | 30k → 60k (×2.0) |

Script: `scripts/bench_mux.sh`.

## Testing

Every push runs in CI:

| suite | what it checks |
|---|---|
| [h2spec](https://github.com/summerwind/h2spec) | 146 RFC 7540/7541 conformance tests against the `net/http` drop-in over TLS, and over h2c except 3.5/2 (there `net/http` reads the client preface) |
| [hpack-test-case](https://github.com/http2jp/hpack-test-case) | 47,142 header blocks encoded by 14 independent HPACK encoders (nghttp2, Go, node, python, haskell, swift-nio) |
| RFC 7541 Appendix C | official HPACK examples with and without Huffman coding |
| interop | curl, nghttp and h2load (h2c and TLS), Go `net/http` client, HTTP/1.1 fallback |
| compatibility | `net/http` drop-in: gorilla/mux, `http.ServeMux`, context cancellation, `Shutdown`, large bodies |
| streaming | `stream_test.go`: trailers (frames, flow control), `Flush` (backpressure, timeout, client reset, leftover goroutine), full duplex (ping-pong, early return, reset while reading, read timeout, body budget) |
| fuzzing | `go test -fuzz` on the HPACK decoder, Huffman codec and whole connections through the `net/http` adapter (arbitrary frames after a valid preface); panics and hangs fail the run |
| race detector | all tests run with `-race` on Go 1.24 and the latest Go |
| security | `security_test.go`: Rapid Reset, non-reading client, header-list amplification, SETTINGS flood, blocked writer + connection error, handler panics, slot leak, buffer reuse after the handler returns, field validation, all timeouts, body budget, TLS policy |

Locally:

```sh
go test -race ./...
git clone --depth 1 https://github.com/http2jp/hpack-test-case /tmp/htc
HPACK_TEST_CASE_DIR=/tmp/htc go test -run HPACKTestCase -v .
go test -run '^$' -fuzz '^FuzzConn$' -fuzztime 5m .
go build ./cmd/muxapp && ./muxapp -addr :8086 -fasth2 & h2spec -h 127.0.0.1 -p 8086
```

## Limits and timeouts

Every connection is bounded. Zero means the default, a negative timeout disables it.
With `ConfigureServer`, a zero field takes the `http.Server` value (read when a
connection starts).

| `Server` field | default | from `http.Server` | what it bounds |
|---|---|---|---|
| `MaxConcurrentStreams` | 250 | — | open streams, **including streams reset by the client while their handler still runs** (Rapid Reset, CVE-2023-44487) |
| `MaxRequestBodySize` | 16 MiB | — | one request body buffered before the handler runs. Also caps the stream receive window we advertise (`min(1 MiB, MaxRequestBodySize)`, not below 64 KiB), so a streaming RPC holds at most that much unread; its total over the stream's life is not limited, as in `net/http` and gRPC (limit message size in the RPC layer, e.g. connect-go `WithReadMaxBytes`) |
| `MaxConnBodySize` | 64 MiB | — | request body bytes buffered on one connection and not yet read by handlers; a stream over it gets `REFUSED_STREAM` (`ENHANCE_YOUR_CALM` if its handler already runs: `REFUSED_STREAM` would invite a retry) |
| `MaxHeaderListSize` | 1 MiB | `MaxHeaderBytes` | decoded header list (name+value+32 per field); larger requests get 431 |
| `HandshakeTimeout` | 10s | — | client preface + first SETTINGS |
| `ReadTimeout` | 60s | `ReadTimeout` | HEADERS → END_STREAM of a request (also of a streaming RPC whose handler already runs: long bidi streams need a larger value), and an unfinished header block |
| `IdleTimeout` | 120s | `IdleTimeout` (else `ReadTimeout`) | connection without open streams (then GOAWAY) |
| `WriteByteTimeout` | 30s | `WriteTimeout` | one 64 KiB write chunk; waiting for flow-control credit (also inside `Flush`) |
| `ErrorLog` | `log` | `ErrorLog` | where handler panics are logged |

Also: a client that does not read stops being read (at most 256 KiB of output is queued
behind a blocked write); at most 100 SETTINGS frames with `INITIAL_WINDOW_SIZE` per 10 s;
requests with invalid field names or values (CR, LF, NUL, other controls), invalid
`:method`, `:scheme`, `:path`, `:authority`/`Host`, or `Host` ≠ `:authority` are reset with
`PROTOCOL_ERROR`; TLS below 1.2, or TLS 1.2 without an ECDHE AEAD suite, gets
`INADEQUATE_SECURITY` (RFC 9113 §9.2).

Handlers are not time-limited (as in `net/http`). A handler that keeps running after
its stream was reset still holds a slot until it returns, so watch `r.Context()`.
When all slots are taken this way, new streams get `REFUSED_STREAM` (clients retry
them); `net/http` queues such requests instead.

## Limitations

- Drop-in adapter: no `Hijacker` or 1xx responses; request trailers are not passed
  to the handler. Request bodies are buffered whole before the handler runs, except
  streaming RPC (see above); without `Flush`, the response is buffered whole too.
  `r.Body` and the `ResponseWriter` stop working when the handler returns
  (reads, writes and `Flush` from a leftover goroutine get an error).
- Stream priorities are ignored; no server push.

---

## Кратко по-русски

Быстрый HTTP/2-сервер для Go: проходит все 146 тестов h2spec и подменяет HTTP/2
в существующем `net/http`-сервисе одной строкой `fasth2.ConfigureServer(srv, nil)`.
В тестах на gorilla/mux-приложении — ускорение ×2–3. Работают трейлеры ответа, `Flush` и full duplex
для потоковых RPC, то есть gRPC и Connect (проверено с connect-go). Статус — экспериментальный: перед продом
прогоните на стейдже и учтите ограничения выше. Лимиты и таймауты
соединений включены по умолчанию, `ConfigureServer` берёт их из `http.Server`
(см. «Limits and timeouts»).

## License

MIT
