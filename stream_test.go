package fasth2

// Тесты для gRPC и стриминга: трейлеры ответа, Flush и тело запроса, которое
// приходит, пока обработчик уже работает (full duplex, только для content-type
// потоковых RPC, см. isDuplexType).

import (
	"encoding/binary"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// trailerMux — обработчики, которые отдают трейлеры так же, как connect-go и
// net/http-приложения.
func trailerMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/prefix", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		io.WriteString(w, "body")
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "")
	})
	m.HandleFunc("/declared", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Sum, X-Count")
		io.WriteString(w, "body")
		w.Header().Set("X-Sum", "42")
		w.Header().Set("X-Count", "1")
	})
	m.HandleFunc("/only", func(w http.ResponseWriter, r *http.Request) {
		// Ответ без тела: только статус gRPC в трейлерах (так connect-go отдаёт ошибку).
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "5")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "not found")
	})
	return m
}

func TestTrailersGoClient(t *testing.T) {
	e := newH2CEnv(t, trailerMux())
	cases := []struct {
		path, body string
		trailers   map[string]string
	}{
		{"/prefix", "body", map[string]string{"Grpc-Status": "0", "Grpc-Message": ""}},
		{"/declared", "body", map[string]string{"X-Sum": "42", "X-Count": "1"}},
		{"/only", "", map[string]string{"Grpc-Status": "5", "Grpc-Message": "not found"}},
	}
	for _, tc := range cases {
		resp, err := e.client.Get(e.base + tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(b) != tc.body {
			t.Fatalf("%s: тело %q, ошибка %v", tc.path, b, err)
		}
		for k, v := range tc.trailers {
			if vs, ok := resp.Trailer[k]; !ok || vs[0] != v {
				t.Fatalf("%s: трейлер %s = %q, ожидался %q (все трейлеры %v)", tc.path, k, vs, v, resp.Trailer)
			}
			if _, ok := resp.Header[k]; ok {
				t.Fatalf("%s: %s пришёл заголовком, а не трейлером", tc.path, k)
			}
		}
		for k := range resp.Header {
			if len(k) > len(http.TrailerPrefix) && k[:len(http.TrailerPrefix)] == http.TrailerPrefix {
				t.Fatalf("%s: служебный ключ %q ушёл заголовком", tc.path, k)
			}
		}
	}
}

// collectStream читает кадры потока sid до END_STREAM и потом ещё 100 мс:
// второго END_STREAM и лишних кадров быть не должно.
func collectStream(t *testing.T, c *tclient, sid uint32) []tframe {
	t.Helper()
	var got []tframe
	for {
		f := c.await(3*time.Second, "кадр ответа", func(f tframe) bool { return f.sid == sid })
		if f.typ == frRSTStream {
			t.Fatalf("поток %d сброшен с кодом %d", sid, binary.BigEndian.Uint32(f.p))
		}
		got = append(got, f)
		if f.flags&flEndStream != 0 && (f.typ == frData || f.typ == frHeaders) {
			break
		}
	}
	deadline := time.After(100 * time.Millisecond)
	for {
		select {
		case f := <-c.frames:
			if f.sid == sid {
				t.Fatalf("лишний кадр после END_STREAM: тип %d, флаги %#x", f.typ, f.flags)
			}
		case <-deadline:
			return got
		}
	}
}

func TestTrailersFrames(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: trailerMux()}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqBlock("GET", "/prefix")))
	fs := collectStream(t, c, 1)
	if len(fs) != 3 || fs[0].typ != frHeaders || fs[1].typ != frData || fs[2].typ != frHeaders {
		t.Fatalf("ожидались HEADERS, DATA, HEADERS; пришло %d кадров", len(fs))
	}
	if fs[0].flags&flEndStream != 0 || fs[1].flags&flEndStream != 0 {
		t.Fatal("END_STREAM раньше трейлеров")
	}
	if _, ok := respFields(t, fs[0])["content-length"]; ok {
		t.Fatal("content-length при трейлерах")
	}
	if tr := respFields(t, fs[2]); tr["grpc-status"] != "0" {
		t.Fatalf("трейлеры %v", tr)
	}

	// Ответ только из трейлеров: HEADERS без END_STREAM, затем HEADERS с ним.
	c.send(headers(3, true, reqBlock("GET", "/only")))
	fs = collectStream(t, c, 3)
	if len(fs) != 2 || fs[0].typ != frHeaders || fs[1].typ != frHeaders || fs[0].flags&flEndStream != 0 {
		t.Fatalf("ожидались HEADERS, HEADERS(END_STREAM); пришло %d кадров", len(fs))
	}
	if tr := respFields(t, fs[1]); tr["grpc-status"] != "5" || tr["grpc-message"] != "not found" {
		t.Fatalf("трейлеры %v", tr)
	}
}

// Трейлеры ответа, который ждал окна, уходят после последнего DATA.
func TestTrailersAfterFlowControl(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: trailerMux()}, nil)
	c := dialH2(t, addr, true, 4, 2) // INITIAL_WINDOW_SIZE = 2
	c.send(headers(1, true, reqBlock("GET", "/prefix")))
	c.await(3*time.Second, "HEADERS", func(f tframe) bool { return f.sid == 1 && f.typ == frHeaders })
	f := c.await(3*time.Second, "DATA", func(f tframe) bool { return f.sid == 1 && f.typ == frData })
	if len(f.p) != 2 || f.flags&flEndStream != 0 {
		t.Fatalf("первый DATA: %d байт, флаги %#x", len(f.p), f.flags)
	}
	c.send(frame(frWindowUpdate, 0, 1, binary.BigEndian.AppendUint32(nil, 100)))
	fs := collectStream(t, c, 1)
	if len(fs) != 2 || fs[0].typ != frData || len(fs[0].p) != 2 || fs[1].typ != frHeaders {
		t.Fatalf("после WINDOW_UPDATE ожидались DATA(2) и HEADERS; пришло %d кадров", len(fs))
	}
	if tr := respFields(t, fs[1]); tr["grpc-status"] != "0" {
		t.Fatalf("трейлеры %v", tr)
	}
}

// Flush: первая часть ответа приходит, пока обработчик ещё работает.
func TestFlushStreamsResponse(t *testing.T) {
	release := make(chan struct{})
	m := http.NewServeMux()
	m.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "second")
		w.Header().Set(http.TrailerPrefix+"X-Done", "1")
	})
	e := newH2CEnv(t, m)
	got := make(chan *http.Response, 1)
	go func() {
		resp, err := e.client.Get(e.base + "/stream")
		if err != nil {
			t.Error(err)
			close(got)
			return
		}
		got <- resp
	}()
	var resp *http.Response
	select {
	case resp = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("заголовки не пришли до конца обработчика")
	}
	if resp == nil {
		t.FailNow()
	}
	defer resp.Body.Close()
	b := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, b); err != nil || string(b) != "first" {
		t.Fatalf("первая часть %q, ошибка %v", b, err)
	}
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != "second" {
		t.Fatalf("остаток %q, ошибка %v", rest, err)
	}
	if resp.Trailer.Get("X-Done") != "1" {
		t.Fatalf("трейлеры %v", resp.Trailer)
	}
}

// flushLoop пишет блоки по 64 КиБ с Flush, пока Flush не вернёт ошибку
// (или n блоков, если n > 0).
func flushLoop(w http.ResponseWriter, n int, written *atomic.Int64) error {
	chunk := make([]byte, 64<<10)
	rc := http.NewResponseController(w)
	for i := 0; n <= 0 || i < n; i++ {
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		if err := rc.Flush(); err != nil {
			return err
		}
		if written != nil {
			written.Add(1)
		}
	}
	return nil
}

// Клиент не даёт окна: Flush останавливает обработчик, очередь потока не растёт
// без предела. Когда окно открывается, ответ приходит целиком.
func TestFlushBackpressure(t *testing.T) {
	var written atomic.Int64
	done := make(chan error, 1)
	m := http.NewServeMux()
	m.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { done <- flushLoop(w, 10, &written) })
	addr, _ := startMux(t, &http.Server{Handler: m}, nil)
	c := dialH2(t, addr, true, 4, 0) // INITIAL_WINDOW_SIZE = 0: DATA не уходит
	c.send(headers(1, true, reqBlock("GET", "/big")))
	time.Sleep(300 * time.Millisecond)
	if n := written.Load(); n > int64(maxStreamOut/(64<<10))+1 {
		t.Fatalf("обработчик записал %d блоков по 64 КиБ при нулевом окне", n)
	}
	c.send(frame(frWindowUpdate, 0, 1, u32(1<<30)), frame(frWindowUpdate, 0, 0, u32(1<<30)))
	if body := c.awaitBody(1); len(body) != 10<<16 {
		t.Fatalf("пришло %d байт, ожидалось %d", len(body), 10<<16)
	}
	if err := <-done; err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// Ответ, который ждёт окна в Flush, сбрасывается по WriteByteTimeout, а Flush
// возвращает ошибку.
func TestFlushPendingTimeout(t *testing.T) {
	errc := make(chan error, 1)
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { errc <- flushLoop(w, 0, nil) })
	addr, _ := startMux(t, &http.Server{Handler: m}, &Server{WriteByteTimeout: 300 * time.Millisecond})
	c := dialH2(t, addr, true, 4, 0)
	c.send(headers(1, true, reqGET))
	c.awaitStatus(1)
	if code := c.awaitRST(1); code != codeCancel {
		t.Fatalf("RST code %d, want CANCEL", code)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Flush не вернул ошибку")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("обработчик остался в Flush")
	}
}

// Клиент сбрасывает поток, пока обработчик ждёт в Flush: Flush сразу возвращает ошибку.
func TestFlushClientReset(t *testing.T) {
	errc := make(chan error, 1)
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { errc <- flushLoop(w, 0, nil) })
	addr, _ := startMux(t, &http.Server{Handler: m}, nil)
	c := dialH2(t, addr, true, 4, 0)
	c.send(headers(1, true, reqGET))
	c.awaitStatus(1)
	c.send(frame(frRSTStream, 0, 1, u32(codeCancel)))
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Flush не вернул ошибку")
		}
	case <-time.After(time.Second):
		t.Fatal("обработчик остался в Flush после RST_STREAM")
	}
}

// Горутина, которая осталась в Flush, когда обработчик вернулся, выходит с
// ошибкой и не держит конец обработчика.
func TestFlushLeftoverGoroutine(t *testing.T) {
	errc := make(chan error, 1)
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		go func() { errc <- flushLoop(w, 0, nil) }()
		time.Sleep(100 * time.Millisecond)
	})
	addr, _ := startMux(t, &http.Server{Handler: m}, nil)
	c := dialH2(t, addr, true, 4, 0)
	c.send(headers(1, true, reqGET))
	c.awaitStatus(1)
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Flush после конца обработчика не вернул ошибку")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("горутина осталась в Flush после конца обработчика")
	}
}

// echoHandler отвечает на каждый прочитанный кусок тела тем же куском и Flush
// (пинг-понг, как bidi в gRPC).
func echoHandler(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			w.(http.Flusher).Flush()
		}
		if err != nil {
			return
		}
	}
}

// Full duplex на сырых кадрах: ответ на первую часть тела приходит до того,
// как клиент пошлёт вторую. Так работают только потоковые RPC (isDuplexType).
func TestDuplexPingPongFrames(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(echoHandler)}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")), frame(frData, 0, 1, []byte("ping1")))
	if st := c.awaitStatus(1); st != "200" {
		t.Fatalf("status %q", st)
	}
	for i, msg := range []string{"ping1", "ping2", "ping3"} {
		if i > 0 {
			c.send(frame(frData, 0, 1, []byte(msg)))
		}
		f := c.await(3*time.Second, "DATA "+msg, func(f tframe) bool { return f.sid == 1 && f.typ == frData })
		if string(f.p) != msg || f.flags&flEndStream != 0 {
			t.Fatalf("раунд %d: DATA %q, флаги %#x", i, f.p, f.flags)
		}
	}
	c.send(frame(frData, flEndStream, 1, nil))
	fs := collectStream(t, c, 1)
	if last := fs[len(fs)-1]; last.flags&flEndStream == 0 {
		t.Fatal("нет END_STREAM после конца тела")
	}
}

// Full duplex через Go-клиент: тело запроса — io.Pipe.
func TestDuplexGoClient(t *testing.T) {
	e := newH2CEnv(t, http.HandlerFunc(echoHandler))
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", e.base+"/", pr)
	req.Header.Set("Content-Type", "application/grpc+proto")
	resp, err := func() (*http.Response, error) {
		type res struct {
			r *http.Response
			e error
		}
		ch := make(chan res, 1)
		go func() { r, err := e.client.Do(req); ch <- res{r, err} }()
		pw.Write([]byte("a"))
		select {
		case x := <-ch:
			return x.r, x.e
		case <-time.After(2 * time.Second):
			return nil, io.ErrNoProgress
		}
	}()
	if err != nil {
		t.Fatalf("заголовки ответа не пришли, пока тело открыто: %v", err)
	}
	defer resp.Body.Close()
	b := make([]byte, 1)
	for _, want := range "abc" {
		if want != 'a' {
			pw.Write([]byte(string(want)))
		}
		if _, err := io.ReadFull(resp.Body, b); err != nil || rune(b[0]) != want {
			t.Fatalf("эхо %q, ошибка %v", b, err)
		}
	}
	pw.Close()
	if rest, err := io.ReadAll(resp.Body); err != nil || len(rest) != 0 {
		t.Fatalf("после конца тела: %q, %v", rest, err)
	}
}

// Обработчик вернулся, пока клиент ещё шлёт тело: полный ответ, затем
// RST_STREAM(NO_ERROR); поздние DATA не ломают соединение.
func TestDuplexHandlerReturnsEarly(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")), frame(frData, 0, 1, []byte("part")))
	if body := c.awaitBody(1); body != "ok" {
		t.Fatalf("тело ответа %q", body)
	}
	if code := c.awaitRST(1); code != codeNo {
		t.Fatalf("RST code %d, want NO_ERROR", code)
	}
	c.send(frame(frData, flEndStream, 1, []byte("late")), headers(3, true, reqGET))
	if st := c.awaitStatus(3); st != "200" {
		t.Fatalf("следующий запрос: status %q", st)
	}
}

// Клиент сбрасывает поток, пока обработчик ждёт в Read: Read сразу возвращает ошибку.
func TestDuplexClientResetWhileReading(t *testing.T) {
	readErr := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		readErr <- err
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")), frame(frData, 0, 1, []byte("part")))
	time.Sleep(50 * time.Millisecond)
	c.send(frame(frRSTStream, 0, 1, u32(codeCancel)))
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("Read не вернул ошибку после RST_STREAM")
		}
	case <-time.After(time.Second):
		t.Fatal("обработчик остался в Read после RST_STREAM")
	}
}

// ReadTimeout действует на всё потоковое тело (HEADERS → END_STREAM), даже
// если данные идут: долгому bidi нужен больший ReadTimeout или отрицательный.
func TestDuplexReadTimeoutCoversWholeStream(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(echoHandler), ReadTimeout: 300 * time.Millisecond}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
	start := time.Now()
	stop := time.After(time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			c.send(frame(frData, 0, 1, []byte("x")))
			continue
		case <-stop:
			t.Fatal("поток жив через 1 с при ReadTimeout 300 мс")
		case f := <-c.frames:
			if f.sid != 1 || f.typ != frRSTStream {
				continue
			}
			if code := binary.BigEndian.Uint32(f.p); code != codeCancel {
				t.Fatalf("RST code %d, want CANCEL", code)
			}
			if d := time.Since(start); d < 250*time.Millisecond {
				t.Fatalf("сброс через %v, раньше ReadTimeout", d)
			}
			return
		}
	}
}

// Прочитанное тело освобождает бюджет соединения и лимит тела: через поток
// проходит больше MaxConnBodySize и MaxRequestBodySize, если обработчик
// успевает читать (лимит считает непрочитанные байты, как в net/http и gRPC).
func TestDuplexBudgetReleasedOnRead(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 256<<10)
		for {
			if _, err := io.ReadFull(r.Body, buf); err != nil {
				return
			}
			io.WriteString(w, "k") // кусок прочитан целиком
			w.(http.Flusher).Flush()
		}
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxConnBodySize: 1 << 20, MaxRequestBodySize: 512 << 10})
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/connect+proto")))
	chunk := make([]byte, 16<<10)
	for i := 0; i < 12; i++ { // 12 × 256 КиБ = 3 МиБ при бюджете 1 МиБ
		var b []byte
		for j := 0; j < 16; j++ {
			b = append(b, frame(frData, 0, 1, chunk)...)
		}
		c.send(b)
		f := c.await(3*time.Second, "подтверждение куска", func(f tframe) bool {
			return f.sid == 1 && (f.typ == frData || f.typ == frRSTStream)
		})
		if f.typ == frRSTStream {
			t.Fatalf("кусок %d: RST code %d", i, binary.BigEndian.Uint32(f.p))
		}
	}
}

// Обычный POST без content-length (не потоковый RPC) буферизуется целиком:
// обработчик запускается только после END_STREAM.
func TestNoEarlyDispatchForPlainPOST(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/json")), frame(frData, 0, 1, []byte("part")))
	select {
	case f := <-c.frames:
		if f.sid == 1 {
			t.Fatalf("ответ до END_STREAM: тип %d", f.typ)
		}
	case <-time.After(200 * time.Millisecond):
	}
	c.send(frame(frData, flEndStream, 1, []byte("end")))
	if body := c.awaitBody(1); body != "ok" {
		t.Fatalf("тело ответа %q", body)
	}
}

// Склейка ответов и корректное завершение: после Shutdown два обработчика
// одного соединения возвращаются вместе — оба ответа должны дойти (соединение
// не закрывается, пока горутина, уступившая процессор, не сбросила буфер).
func TestShutdownKeepsBatchedResponses(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1)) // так уступка процессора срабатывает всегда
	release := make(chan struct{})
	var started atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		<-release
		io.WriteString(w, "ok")
	})
	addr, fs := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqGET), headers(3, true, reqGET))
	for deadline := time.Now().Add(2 * time.Second); started.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("обработчики не запустились")
		}
		time.Sleep(5 * time.Millisecond)
	}
	fs.shutdown() // GOAWAY: соединение закроется, когда потоки закончатся
	close(release)
	for _, sid := range []uint32{1, 3} {
		if body := c.awaitBody(sid); body != "ok" {
			t.Fatalf("поток %d: тело %q", sid, body)
		}
	}
}

// Клиент дал большое окно, но не читает сокет: Flush должен остановиться,
// а не копить ответ в буфере записи соединения. Два потока: один обработчик
// застревает в write как писатель, второй продолжает Flush — он и должен ждать.
func TestFlushBoundedWhenClientStopsReading(t *testing.T) {
	var written atomic.Int64
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { flushLoop(w, 4096, &written) })
	addr, _ := startMux(t, &http.Server{Handler: m}, &Server{WriteByteTimeout: 5 * time.Second})
	c := dialH2(t, addr, false, 4, 1<<30) // окно потока 1 ГиБ, сокет не читается
	c.send(frame(frWindowUpdate, 0, 0, u32(1<<30)), headers(1, true, reqGET), headers(3, true, reqGET))
	time.Sleep(time.Second)
	a := written.Load()
	time.Sleep(300 * time.Millisecond)
	b := written.Load()
	if b != a || b >= 2*4096 {
		t.Fatalf("обработчик продолжает писать: %d → %d блоков по 64 КиБ", a, b)
	}
}

// Окно потокового тела возвращается, когда обработчик читает, а не когда
// данные пришли: пока обработчик не читает, WINDOW_UPDATE для потока нет.
func TestDuplexWindowReturnedOnRead(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		io.Copy(io.Discard, r.Body)
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
	chunk := make([]byte, 16<<10)
	var b []byte
	for i := 0; i < 48; i++ { // 768 КиБ: больше половины окна потока (1 МиБ)
		b = append(b, frame(frData, 0, 1, chunk)...)
	}
	c.send(b)
	deadline := time.After(300 * time.Millisecond)
wait:
	for {
		select {
		case f := <-c.frames:
			if f.sid == 1 && f.typ == frWindowUpdate {
				t.Fatal("окно потока вернулось, хотя обработчик не читал")
			}
			if f.sid == 1 && f.typ == frRSTStream {
				t.Fatalf("поток сброшен с кодом %d", binary.BigEndian.Uint32(f.p))
			}
		case <-deadline:
			break wait
		}
	}
	close(release)
	c.await(2*time.Second, "WINDOW_UPDATE потока после чтения", func(f tframe) bool {
		return f.sid == 1 && f.typ == frWindowUpdate
	})
	c.send(frame(frData, flEndStream, 1, nil))
}

// Обработчик читает потоковое тело чуть медленнее, чем оно приходит: буфер
// тела не растёт на весь объём потока (непрочитанный хвост сдвигается в начало).
func TestStreamBodyBufferCompacts(t *testing.T) {
	c := &conn{initWindow: ourInitWindow}
	st := &stream{}
	st.cond.L = &c.mu
	st.inHandler, st.streaming, st.credited = true, true, 1<<30 // окно не возвращаем: без записи в сокет
	chunk := make([]byte, 1000)
	p := make([]byte, 900)
	for i := 0; i < 1000; i++ { // 1 МБ пришло, отставание растёт до 100 КБ
		c.mu.Lock()
		st.body = append(st.body, chunk...)
		c.mu.Unlock()
		if _, err := c.readBody(st, st.gen, p); err != nil {
			t.Fatal(err)
		}
	}
	if cap(st.body) > 512<<10 {
		t.Fatalf("буфер тела вырос до %d байт при %d непрочитанных", cap(st.body), len(st.body)-st.bodyRead)
	}
}

// MaxRequestBodySize меньше окна по умолчанию: сервер объявляет окно потока не
// больше лимита, и клиент, который соблюдает окно, не получает сброс.
func TestStreamWindowFollowsBodyLimit(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		io.Copy(io.Discard, r.Body)
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxRequestBodySize: 256 << 10})
	c := dialH2(t, addr, true)
	f := c.await(3*time.Second, "SETTINGS сервера", func(f tframe) bool { return f.typ == frSettings && f.flags&flAck == 0 })
	win := uint32(0)
	for p := f.p; len(p) >= 6; p = p[6:] {
		if binary.BigEndian.Uint16(p) == 4 {
			win = binary.BigEndian.Uint32(p[2:])
		}
	}
	if win != 256<<10 {
		t.Fatalf("INITIAL_WINDOW_SIZE %d, ожидалось %d", win, 256<<10)
	}
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
	chunk := make([]byte, 16<<10)
	var b []byte
	for i := 0; i < 16; i++ { // ровно окно: 256 КиБ, обработчик не читает
		b = append(b, frame(frData, 0, 1, chunk)...)
	}
	c.send(b)
	select {
	case f := <-c.frames:
		if f.sid == 1 && f.typ == frRSTStream {
			t.Fatalf("поток сброшен с кодом %d при теле в пределах окна", binary.BigEndian.Uint32(f.p))
		}
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	c.send(frame(frData, flEndStream, 1, nil))
}

// Первый Flush отправил только часть ответа (окно клиента 64 КиБ), дальше
// клиент окна не даёт: поток сбрасывается по WriteByteTimeout.
func TestFlushPartialSendTimeout(t *testing.T) {
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 200<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	addr, _ := startMux(t, &http.Server{Handler: m}, &Server{WriteByteTimeout: 300 * time.Millisecond})
	c := dialH2(t, addr, true) // окно потока по умолчанию: 65535
	c.send(headers(1, true, reqGET))
	c.awaitStatus(1)
	if code := c.awaitRST(1); code != codeCancel {
		t.Fatalf("RST code %d, want CANCEL", code)
	}
}

// MaxRequestBodySize меньше первого сообщения потокового RPC: сообщение в
// пределах окна потока доходит до обработчика (общий лимит не для потоковых RPC).
func TestDuplexFirstMessageOverSmallLimit(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		io.WriteString(w, strconv.Itoa(len(b)))
	})
	addr, _ := startMux(t, &http.Server{Handler: h}, &Server{MaxRequestBodySize: 16 << 10})
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")),
		frame(frData, 0, 1, make([]byte, 16<<10)), frame(frData, 0, 1, make([]byte, 16<<10)))
	c.send(frame(frData, flEndStream, 1, nil))
	if body := c.awaitBody(1); body != "32768" {
		t.Fatalf("тело ответа %q, ожидалось 32768", body)
	}
}
