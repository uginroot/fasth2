# fasth2

[![CI](https://github.com/uginroot/fasth2/actions/workflows/ci.yml/badge.svg)](https://github.com/uginroot/fasth2/actions/workflows/ci.yml)

A fast HTTP/2 server for Go. Passes all 146 [h2spec](https://github.com/summerwind/h2spec)
conformance tests and can replace the HTTP/2 implementation of an existing
`net/http` server with one line.

> **Status: experimental.** Well tested for protocol conformance, not yet battle-tested
> in production. See [Limitations](#limitations).

## Why it is fast

The design follows hyper/h2 rather than `net/http`:

- one goroutine per connection, no goroutine + channels per stream;
- all frames produced while handling one socket read leave in a **single `write`**
  (~0.2 syscalls per request vs ~4 for `net/http`);
- reusable buffers: **zero allocations per request** in steady state (native API);
- own HPACK decoder; in async mode responses from many workers are coalesced
  into shared writes (write combining).

## Usage

### Drop-in for an existing `net/http` service

```go
srv := &http.Server{Addr: ":8443", Handler: router} // gorilla/mux, chi, http.ServeMux, middleware...
fasth2.ConfigureServer(srv, nil)                   // the whole migration
log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
```

HTTP/1.1, TLS, `Shutdown` and your handlers stay `net/http`; only HTTP/2
connections are served by fasth2 (via the standard `http.Server.TLSNextProto`
hook, Go 1.24+). For h2c enable `srv.Protocols.SetUnencryptedHTTP2(true)` as usual.
If you build your own `tls.Listener`, add `"h2"` to `NextProtos`.

### Native API (fastest)

```go
srv := &fasth2.Server{Handler: func(req *fasth2.Request, resp *fasth2.Response) {
	resp.AddHeader("content-type", "text/plain")
	resp.WriteString("Hello, World!")
}}
log.Fatal(srv.ListenAndServe(":8080")) // h2c, prior knowledge
```

Handlers run inline on the connection goroutine and **must not block**.
Set `Async: true` to run them on a worker pool (they may then block on DB/RPC calls).

## Benchmarks

h2load, "Hello, World!" response, 1 vCPU shared by server and load generator,
Go 1.27.3, Rust 1.75 + hyper 1.4. Requests/second (connections × streams per connection).
Re-measure on your own hardware.

**Drop-in** (same gorilla/mux app, only `ConfigureServer` differs):

| route, load | h2c net/http → fasth2 | TLS net/http → fasth2 |
|---|---|---|
| `/` 100×100 | 30k → 98k (×3.3) | 27k → 79k (×3.0) |
| `/users/{id}` JSON 100×100 | 25k → 65k (×2.6) | 22k → 61k (×2.7) |
| `/sleep` (1 ms) 100×100 | 32k → 66k (×2.0) | 30k → 60k (×2.0) |

**Native API:**

| load | net/http | fasth2 inline | fasth2 async | Rust hyper |
|---|---|---|---|---|
| 10×10 | 46k | 603k | 300k | 191k |
| 100×100 | 39k | 932k | 305k | 164k |

Scripts: `scripts/bench_native.sh`, `scripts/bench_mux.sh`.

## Testing

Every push runs in CI:

| suite | what it checks |
|---|---|
| [h2spec](https://github.com/summerwind/h2spec) | 146 RFC 7540/7541 conformance tests against inline, async and the `net/http` drop-in (TLS) |
| [hpack-test-case](https://github.com/http2jp/hpack-test-case) | 47,142 header blocks encoded by 14 independent HPACK encoders (nghttp2, Go, node, python, haskell, swift-nio) |
| RFC 7541 Appendix C | official HPACK examples with and without Huffman coding |
| interop | curl, nghttp and h2load (h2c and TLS), Go `net/http` client, HTTP/1.1 fallback |
| compatibility | `net/http` drop-in: gorilla/mux, `http.ServeMux`, context cancellation, `Shutdown`, large bodies |
| fuzzing | `go test -fuzz` on the HPACK decoder, Huffman codec and whole connections (arbitrary frames after a valid preface), inline and async; panics and hangs fail the run |
| race detector | all tests run with `-race` on Go 1.24 and the latest Go |
| security | `security_test.go`: Rapid Reset, non-reading client, header-list amplification, SETTINGS flood, blocked writer + connection error, handler panics, slot leak, buffer reuse after the handler returns, field validation, all timeouts, body budget, TLS policy |

Locally:

```sh
go test -race ./...
git clone --depth 1 https://github.com/http2jp/hpack-test-case /tmp/htc
HPACK_TEST_CASE_DIR=/tmp/htc go test -run HPACKTestCase -v .
go test -run '^$' -fuzz '^FuzzConnAsync$' -fuzztime 5m .
go build ./cmd/fasth2server && ./fasth2server -addr :8085 & h2spec -h 127.0.0.1 -p 8085
```

## Limits and timeouts

Every connection is bounded. Zero means the default, a negative timeout disables it.
With `ConfigureServer`, a zero field takes the `http.Server` value (read when a
connection starts).

| `Server` field | default | from `http.Server` | what it bounds |
|---|---|---|---|
| `MaxConcurrentStreams` | 250 | — | open streams, **including streams reset by the client while their handler still runs** (Rapid Reset, CVE-2023-44487) |
| `MaxRequestBodySize` | 16 MiB | — | one request body |
| `MaxConnBodySize` | 64 MiB | — | request bodies buffered on one connection; a stream over it gets `REFUSED_STREAM` |
| `MaxHeaderListSize` | 1 MiB | `MaxHeaderBytes` | decoded header list (name+value+32 per field); larger requests get 431 |
| `HandshakeTimeout` | 10s | — | client preface + first SETTINGS |
| `ReadTimeout` | 60s | `ReadTimeout` | HEADERS → END_STREAM of a request, and an unfinished header block |
| `IdleTimeout` | 120s | `IdleTimeout` (else `ReadTimeout`) | connection without open streams (then GOAWAY) |
| `WriteByteTimeout` | 30s | `WriteTimeout` | one 64 KiB write chunk; waiting for flow-control credit |
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

- Drop-in adapter: no `http.Flusher` (SSE/streaming), `Hijacker`, 1xx responses or
  trailers (so not for gRPC); request and response bodies are fully buffered.
  `r.Body` and the `ResponseWriter` stop working when the handler returns
  (reads/writes from a leftover goroutine get an error).
- Response headers are HPACK-encoded without the dynamic table (slightly larger headers).
- Stream priorities are ignored; no server push.
- Native inline handlers must not block.

---

## Кратко по-русски

Быстрый HTTP/2-сервер для Go: проходит все 146 тестов h2spec и подменяет HTTP/2
в существующем `net/http`-сервисе одной строкой `fasth2.ConfigureServer(srv, nil)`.
В тестах на gorilla/mux-приложении — ускорение ×2–3; нативный API быстрее
`net/http` в 10–20 раз. Статус — экспериментальный: перед продом прогоните на
стейдже и учтите ограничения выше (нет стриминга ответов). Лимиты и таймауты
соединений включены по умолчанию, `ConfigureServer` берёт их из `http.Server`
(см. «Limits and timeouts»).

## License

MIT
