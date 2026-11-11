package fasth2

// Тесты исправлений третьего ревью: окно соединения, окно за тело, которое уже
// никто не прочтёт, ReadTimeout потоковых RPC и HEAD с трейлерами.

import (
	"encoding/binary"
	"net"
	"net/http"
	"testing"
	"time"
)

// Окно соединения, которое сервер объявляет в преамбуле: 65535 + 1 МиБ, как в
// x/net, и не зависит от MaxConnBodySize (см. conn.connWindow).
func TestConnWindowLikeXNet(t *testing.T) {
	cases := []struct {
		name string
		s    *Server
	}{
		{"по умолчанию", nil},
		{"большой MaxConnBodySize", &Server{MaxConnBodySize: 1 << 30}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, tc.s)
			c := dialH2(t, addr, true)
			f := c.await(3*time.Second, "WINDOW_UPDATE соединения", func(f tframe) bool {
				return f.sid == 0 && f.typ == frWindowUpdate
			})
			if got := binary.BigEndian.Uint32(f.p) & 0x7fffffff; got != ourConnWindow {
				t.Fatalf("приращение окна соединения %d, ждали %d", got, ourConnWindow)
			}
		})
	}
}

// duplexUnread шлёт потоковый запрос: HEADERS, паузу (обработчик уже запущен и
// данные считаются потоковыми) и n байт DATA без END_STREAM.
func duplexUnread(c *tclient, n int) {
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
	time.Sleep(100 * time.Millisecond)
	chunk := make([]byte, 16<<10)
	var b []byte
	for ; n > 0; n -= len(chunk) {
		b = append(b, frame(frData, 0, 1, chunk)...)
	}
	c.send(b)
}

// awaitConnCredit ждёт WINDOW_UPDATE соединения не меньше min после преамбулы.
func awaitConnCredit(c *tclient, d time.Duration, min uint32) {
	c.t.Helper()
	c.await(d, "WINDOW_UPDATE соединения за непрочитанное тело", func(f tframe) bool {
		return f.sid == 0 && f.typ == frWindowUpdate && binary.BigEndian.Uint32(f.p)&0x7fffffff >= min
	})
}

// Клиент сбросил потоковый запрос, обработчик ещё работает и тело не читал:
// окно соединения за непрочитанное возвращается сразу, а не когда обработчик
// вернётся (иначе соединение стоит без окна).
func TestResetStreamingReturnsConnWindow(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release })
	// Маленькое окно соединения: WINDOW_UPDATE уходит, когда набралась половина.
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxConnBodySize: 1 << 20})
	c := dialH2(t, addr, true)
	c.await(3*time.Second, "WINDOW_UPDATE преамбулы", func(f tframe) bool { return f.sid == 0 && f.typ == frWindowUpdate })
	duplexUnread(c, 768<<10)
	c.send(frame(frRSTStream, 0, 1, u32(codeCancel)))
	awaitConnCredit(c, 2*time.Second, 768<<10)
}

// Обработчик вернулся, не прочитав потоковое тело, а ответ ждёт окна потока
// (клиент дал окно 0): окно соединения за непрочитанное возвращается сразу, а
// не когда ответ уйдёт.
func TestHandlerReturnReturnsConnWindow(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // данные приходят, пока обработчик работает
		w.Write([]byte("x"))
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxConnBodySize: 1 << 20})
	c := dialH2(t, addr, true, 4, 0) // SETTINGS_INITIAL_WINDOW_SIZE = 0: тело ответа не уйдёт
	c.await(3*time.Second, "WINDOW_UPDATE преамбулы", func(f tframe) bool { return f.sid == 0 && f.typ == frWindowUpdate })
	duplexUnread(c, 768<<10)
	c.await(2*time.Second, "HEADERS ответа", func(f tframe) bool { return f.sid == 1 && f.typ == frHeaders })
	awaitConnCredit(c, 2*time.Second, 768<<10)
}

// pipeConn запускает serveConn на net.Pipe со своим обработчиком и возвращает
// клиента. Нужен, когда тесту нужен поток (req.st), а не http.Request.
func pipeConn(t *testing.T, s *Server, h handlerFunc) *tclient {
	t.Helper()
	srvSide, cliSide := net.Pipe()
	go s.serveConn(srvSide, connOpts{handler: h})
	t.Cleanup(func() { cliSide.Close() })
	c := &tclient{t: t, nc: cliSide, frames: make(chan tframe, 4096), eof: make(chan struct{})}
	go c.readLoop() // net.Pipe без буфера: сервер сначала пишет свою преамбулу
	c.send(append([]byte(clientPreface), secSettings()...))
	return c
}

// ReadTimeout по умолчанию (60 с) не ограничивает потоковый RPC: долгий bidi —
// обычный режим gRPC. Заданный явно — ограничивает (см. TestSecStreamReadTimeoutStreaming).
func TestStreamingReadTimeoutOnlyExplicit(t *testing.T) {
	cases := []struct {
		name    string
		s       *Server
		limited bool
	}{
		{"по умолчанию", &Server{}, false},
		{"явный", &Server{ReadTimeout: time.Hour}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan time.Time, 1)
			c := pipeConn(t, tc.s, func(req *request, resp *response) {
				req.c.mu.Lock()
				got <- req.st.deadline
				req.c.mu.Unlock()
			})
			c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
			select {
			case dl := <-got:
				if dl.IsZero() == tc.limited {
					t.Fatalf("срок потока %v, ограничен: ждали %v", dl, tc.limited)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("обработчик потокового запроса не запущен")
			}
		})
	}
}

// Ответ на HEAD с трейлерами: HEADERS с END_STREAM и content-length, без
// кадров после них (трейлеры не отправляются, как в x/net).
func TestHeadWithTrailers(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: trailerMux()}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqBlock("HEAD", "/prefix")))
	f := c.await(3*time.Second, "HEADERS", func(f tframe) bool { return f.sid == 1 && f.typ == frHeaders })
	m := respFields(t, f)
	if f.flags&flEndStream == 0 || m["content-length"] != "4" || m["grpc-status"] != "" {
		t.Fatalf("флаги %#x, поля %v", f.flags, m)
	}
	c.send(frame(frPing, 0, 0, make([]byte, 8)))
	c.await(2*time.Second, "PING ACK", func(f tframe) bool { return f.typ == frPing && f.flags&flAck != 0 })
	for _, f := range c.backlog {
		if f.sid == 1 {
			t.Fatalf("кадр %d потока 1 после HEADERS с END_STREAM", f.typ)
		}
	}
}
