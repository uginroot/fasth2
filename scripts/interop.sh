#!/usr/bin/env bash
# Interop with independent HTTP/2 clients: curl (libcurl+nghttp2), nghttp, h2load.
# Expects: fasth2server on :8085 (inline), :8086 (async); muxapp -fasth2 -tls on :8093.
set -u
fail=0
check() { # name, expected, actual
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2] got [$3]"; fail=1; fi
}
for p in 8085 8086; do
  check "curl h2c GET :$p" "Hello, World!|2|200" \
    "$(curl -s --http2-prior-knowledge -w '|%{http_version}|%{http_code}' http://127.0.0.1:$p/)"
  check "curl h2c POST :$p" "Hello, World!|200" \
    "$(curl -s --http2-prior-knowledge -d 'payload' -w '|%{http_code}' http://127.0.0.1:$p/)"
  out=$(nghttp -nv http://127.0.0.1:$p/ 2>&1)
  check "nghttp :status 200 :$p" "1" "$(echo "$out" | grep -c ':status: 200')"
  check "nghttp END_STREAM :$p" "1" "$(echo "$out" | grep -E 'recv DATA frame.*flags=0x01' | wc -l | tr -d ' ')"
  check "h2load 20k reqs :$p" "20000 succeeded, 0 failed" \
    "$(h2load -n 20000 -c 4 -m 50 http://127.0.0.1:$p/ | grep -oE '[0-9]+ succeeded, [0-9]+ failed')"
done
# net/http drop-in over TLS (ALPN h2) and HTTP/1.1 fallback on the same port
check "curl TLS h2 /users/5" '{"id":"5","name":"Anton"}|2' \
  "$(curl -sk -w '|%{http_version}' https://127.0.0.1:8093/users/5 | tr -d '\n')"
check "curl TLS http/1.1 /users/5" '{"id":"5","name":"Anton"}|1.1' \
  "$(curl -sk --http1.1 -w '|%{http_version}' https://127.0.0.1:8093/users/5 | tr -d '\n')"
check "nghttp TLS" "1" "$(nghttp -nv https://127.0.0.1:8093/ 2>&1 | grep -c ':status: 200')"
check "h2load TLS 10k reqs" "10000 succeeded, 0 failed" \
  "$(h2load -n 10000 -c 4 -m 20 https://127.0.0.1:8093/ | grep -oE '[0-9]+ succeeded, [0-9]+ failed')"
exit $fail
