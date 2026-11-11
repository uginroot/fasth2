package fasth2

// Тесты исправлений четвёртого ревью.

import (
	"net/http"
	"testing"
	"time"
)

// Поток закончился (обработчик вернулся), пока клиент присылал блок трейлеров
// частями (HEADERS без END_HEADERS, потом CONTINUATION). Конец блока не должен
// трогать освобождённую структуру потока: ни счётчик recvStreaming (его
// проверяет roundHook), ни повторный recycle (одна структура дважды в c.free).
func TestStreamReleasedDuringHeaderBlock(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Write([]byte("x"))
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
	time.Sleep(50 * time.Millisecond) // обработчик запущен до END_STREAM
	// Трейлеры запроса: HEADERS с END_STREAM без END_HEADERS.
	c.send(frame(frHeaders, flEndStream, 1, lit(nil, "x-trailer", "1")))
	time.Sleep(50 * time.Millisecond)
	close(release) // поток закончится, пока блок заголовков не закончен
	// Поток не дописал тело: после ответа сервер сбрасывает его с NO_ERROR.
	c.await(2*time.Second, "RST_STREAM потока 1 после ответа", func(f tframe) bool { return f.sid == 1 && f.typ == frRSTStream })
	c.send(frame(frContinuation, flEndHeaders, 1, nil))
	// Соединение живо, и новый потоковый RPC обслуживается как обычно.
	c.send(headers(3, true, reqGET))
	if s := c.awaitStatus(3); s != "200" {
		t.Fatalf("поток 3: статус %s", s)
	}
}

// То же для запрещённого HEADERS на полузакрытом потоке (kindRSTClosed): поток
// закончился, пока блок не закончен. Конец блока не освобождает структуру ещё
// раз (раньше одна структура попадала в c.free дважды и доставалась двум
// потокам) и разбирается как HEADERS на закрытый поток: GOAWAY STREAM_CLOSED,
// как в onHeaders, независимо от того, успел ли обработчик вернуться.
func TestHalfClosedStreamReleasedDuringHeaderBlock(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Write([]byte("x"))
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	panics := hookPanics.Load()
	c.send(headers(1, true, reqGET)) // запрос целиком, обработчик ждёт
	time.Sleep(50 * time.Millisecond)
	c.send(frame(frHeaders, 0, 1, lit(nil, "x-again", "1"))) // HEADERS на полузакрытом потоке, без END_HEADERS
	time.Sleep(50 * time.Millisecond)
	close(release)
	c.await(2*time.Second, "конец ответа потока 1", func(f tframe) bool {
		return f.sid == 1 && f.typ == frData && f.flags&flEndStream != 0
	})
	c.send(frame(frContinuation, flEndHeaders, 1, nil))
	if code := c.awaitGoAway(); code != codeStreamClosed {
		t.Fatalf("GOAWAY с кодом %d, ждали STREAM_CLOSED", code)
	}
	if n := hookPanics.Load() - panics; n > 0 {
		t.Fatalf("паник на сервере: %d", n)
	}
}
