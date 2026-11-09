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

```sh
go test -race ./...                     # RFC 7541 vectors, interop with net/http client,
                                        # TLS/h2c drop-in, gorilla/mux, ServeMux, ctx cancel, Shutdown
go build ./cmd/fasth2server && ./fasth2server -addr :8085 &
h2spec -h 127.0.0.1 -p 8085             # 146/146
```

CI runs vet, race tests (Go 1.24 and stable) and h2spec against the inline, async
and drop-in (TLS) servers on every push.

## Limitations

- Drop-in adapter: no `http.Flusher` (SSE/streaming), `Hijacker`, 1xx responses or
  trailers (so not for gRPC); request and response bodies are fully buffered
  (request body limit 16 MiB by default).
- `net/http` `ReadTimeout`/`WriteTimeout`/`IdleTimeout` are **not** applied to HTTP/2
  connections yet — add a proxy or timeouts before exposing to the internet.
- Response headers are HPACK-encoded without the dynamic table (slightly larger headers).
- Stream priorities are ignored; no server push.
- Native inline handlers must not block.

---

## Кратко по-русски

Быстрый HTTP/2-сервер для Go: проходит все 146 тестов h2spec и подменяет HTTP/2
в существующем `net/http`-сервисе одной строкой `fasth2.ConfigureServer(srv, nil)`.
В тестах на gorilla/mux-приложении — ускорение ×2–3; нативный API быстрее
`net/http` в 10–20 раз. Статус — экспериментальный: перед продом прогоните на
стейдже и учтите ограничения выше (нет стриминга ответов, таймаутов HTTP/2-соединений).

## License

MIT
