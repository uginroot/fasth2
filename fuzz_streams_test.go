package fasth2

// FuzzStreams — смысловой фаззер: вход задаёт последовательность действий
// клиента (открыть поток, DATA, трейлеры, RST_STREAM, WINDOW_UPDATE, PING,
// SETTINGS, граница записи с паузой), блоки заголовков бывают разбиты на HEADERS
// и CONTINUATION с паузой между ними. Харнесс знает путь каждого потока и
// проверяет, что каждый ответ (заголовки, тело, трейлер) пришёл в свой поток.
// Соединение — настоящий TCP (serveRaw), сервер один на процесс. Инварианты
// соединения проверяет roundHook (fuzz_test.go).

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// streamsHandler отвечает так, что ответ можно сверить с запросом:
// x-path и трейлер x-done — путь запроса; тело — "<путь>:<байт тела>".
// Суффикс пути меняет поведение: /early — ответ сразу, тело не читается;
// /late — ответ через 300 мкс без чтения тела (обработчик заканчивает поток,
// пока клиент ещё шлёт); /flush — путь уходит через Flush до чтения тела.
func streamsHandler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	w.Header().Set("X-Path", p)
	w.Header().Set(http.TrailerPrefix+"X-Done", p)
	switch {
	case strings.HasSuffix(p, "/early"):
		io.WriteString(w, "early")
		return
	case strings.HasSuffix(p, "/late"):
		time.Sleep(300 * time.Microsecond)
		io.WriteString(w, "late")
		return
	case strings.HasSuffix(p, "/flush"):
		io.WriteString(w, p)
		w.(http.Flusher).Flush()
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, ":%d", n)
		return
	}
	n, _ := io.Copy(io.Discard, r.Body)
	fmt.Fprintf(w, "%s:%d", p, n)
}

var streamsSrv struct {
	once sync.Once
	addr string
}

func streamsAddr(t *testing.T) string {
	streamsSrv.once.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		hs := &http.Server{Handler: http.HandlerFunc(streamsHandler)}
		hs.Protocols = new(http.Protocols)
		hs.Protocols.SetHTTP1(true)
		hs.Protocols.SetUnencryptedHTTP2(true)
		ConfigureServer(hs, &Server{ReadTimeout: 2 * time.Second})
		go hs.Serve(ln)
		streamsSrv.addr = ln.Addr().String()
	})
	return streamsSrv.addr
}

// fstream — поток с точки зрения клиента.
type fstream struct {
	path        string
	sent        int  // байт тела, отправленных клиентом
	ended       bool // клиент послал END_STREAM
	reset       bool // клиент послал RST_STREAM
	gotHeaders  bool
	status      string
	body        []byte
	done        bool // ответ закончился (END_STREAM от сервера)
	trailerSeen bool
}

func runFuzzStreams(t *testing.T, data []byte) {
	panics := hookPanics.Load()
	c := dialH2(t, streamsAddr(t), true)
	c.send(frame(frWindowUpdate, 0, 0, u32(1<<30)))
	streams := map[uint32]*fstream{}
	var order []uint32
	next := uint32(1)
	var buf []byte
	flush := func(pause byte) {
		if len(buf) > 0 {
			c.send(buf)
			buf = buf[:0]
		}
		if pause%8 == 0 {
			return
		}
		time.Sleep(time.Duration(pause%8) * 100 * time.Microsecond)
	}
	// pick — поток клиента, в который ещё можно писать (не закрыт и не сброшен).
	pick := func(b byte) (uint32, *fstream) {
		var open []uint32
		for _, sid := range order {
			if st := streams[sid]; !st.ended && !st.reset {
				open = append(open, sid)
			}
		}
		if len(open) == 0 {
			return 0, nil
		}
		sid := open[int(b)%len(open)]
		return sid, streams[sid]
	}
	// block — блок заголовков; split — HEADERS без END_HEADERS, граница записи
	// с паузой и CONTINUATION с остатком.
	block := func(sid uint32, end bool, b []byte, split, pause byte) {
		fl := byte(0)
		if end {
			fl = flEndStream
		}
		if split&1 == 0 || len(b) < 2 {
			buf = append(buf, frame(frHeaders, fl|flEndHeaders, sid, b)...)
			return
		}
		cut := 1 + int(split>>1)%(len(b)-1)
		buf = append(buf, frame(frHeaders, fl, sid, b[:cut])...)
		flush(pause)
		buf = append(buf, frame(frContinuation, flEndHeaders, sid, b[cut:])...)
	}
	arg := func() byte {
		if len(data) == 0 {
			return 0
		}
		b := data[0]
		data = data[1:]
		return b
	}
	for len(data) > 0 {
		op := arg()
		switch op % 8 {
		case 0: // открыть поток
			if len(order) >= 32 {
				continue
			}
			a, b := arg(), arg()
			sid := next
			next += 2
			path := fmt.Sprintf("/s%d%s", sid, []string{"", "/early", "/late", "/flush"}[int(a>>2)%4])
			st := &fstream{path: path}
			streams[sid] = st
			order = append(order, sid)
			switch a % 4 {
			case 0:
				st.ended = true
				block(sid, true, reqBlock("GET", path), b, b>>4)
			case 1:
				block(sid, false, reqBlock("POST", path), b, b>>4)
			case 2:
				block(sid, false, reqBlock("POST", path, "content-type", "application/grpc"), b, b>>4)
			case 3:
				block(sid, false, reqBlock("POST", path, "content-type", "application/connect+proto"), b, b>>4)
			}
		case 1: // DATA
			a, b := arg(), arg()
			sid, st := pick(a)
			if st == nil {
				continue
			}
			p := bytes.Repeat([]byte{'d'}, int(b)%64)
			fl := byte(0)
			if a&0x80 != 0 {
				fl = flEndStream
				st.ended = true
			}
			st.sent += len(p)
			buf = append(buf, frame(frData, fl, sid, p)...)
		case 2: // трейлеры запроса (END_STREAM)
			a, b := arg(), arg()
			sid, st := pick(a)
			if st == nil {
				continue
			}
			st.ended = true
			block(sid, true, lit(nil, "x-trailer", "1"), b, b>>4)
		case 3: // RST_STREAM
			sid, st := pick(arg())
			if st == nil {
				continue
			}
			st.reset = true
			buf = append(buf, frame(frRSTStream, 0, sid, u32(codeCancel))...)
		case 4: // WINDOW_UPDATE соединения или потока
			a, b := arg(), arg()
			sid := uint32(0)
			if a&1 != 0 {
				if s, st := pick(a >> 1); st != nil {
					sid = s
				}
			}
			buf = append(buf, frame(frWindowUpdate, 0, sid, u32(1+uint32(b)*256))...)
		case 5: // PING
			buf = append(buf, frame(frPing, 0, 0, make([]byte, 8))...)
		case 6: // граница записи и пауза
			flush(arg())
		case 7: // SETTINGS_INITIAL_WINDOW_SIZE: маленькое окно — ответы ждут окна
			buf = append(buf, secSettings(4, uint32(arg())*64)...)
		}
	}
	// Большое окно в конце: ответы, которые ждали окна, уходят.
	buf = append(buf, secSettings(4, 1<<20)...)
	flush(0)

	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("FuzzStreams: "+format, args...)
	}
	quiet := time.NewTimer(15 * time.Millisecond)
	deadline := time.After(time.Second)
	check := func(f tframe) {
		if f.sid == 0 {
			return
		}
		st := streams[f.sid]
		switch f.typ {
		case frHeaders:
			if st == nil {
				fail("HEADERS на поток %d, который клиент не открывал", f.sid)
			}
			if f.hdr == nil {
				return // ошибка декодирования: соединение закрывается
			}
			if _, isResp := f.hdr[":status"]; isResp {
				if st.gotHeaders {
					fail("поток %d (%s): второй блок ответа %v", f.sid, st.path, f.hdr)
				}
				st.gotHeaders = true
				st.status = f.hdr[":status"]
				if st.status == "200" && f.hdr["x-path"] != st.path {
					fail("поток %d: ответ запроса %q пришёл в поток запроса %q", f.sid, f.hdr["x-path"], st.path)
				}
			} else {
				if !st.gotHeaders {
					fail("поток %d (%s): трейлеры без заголовков ответа", f.sid, st.path)
				}
				st.trailerSeen = true
				if v := f.hdr["x-done"]; v != st.path {
					fail("поток %d: трейлер x-done %q, а путь %q", f.sid, v, st.path)
				}
			}
			if f.flags&flEndStream != 0 {
				st.done = true
			}
		case frData:
			if st == nil {
				fail("DATA на поток %d, который клиент не открывал", f.sid)
			}
			if !st.gotHeaders {
				fail("поток %d (%s): DATA до заголовков ответа", f.sid, st.path)
			}
			if st.done {
				fail("поток %d (%s): DATA после END_STREAM", f.sid, st.path)
			}
			st.body = append(st.body, f.p...)
			if f.flags&flEndStream != 0 {
				st.done = true
			}
		}
	}
wait:
	for {
		select {
		case f := <-c.frames:
			check(f)
			quiet.Reset(15 * time.Millisecond)
		case <-c.eof:
			for len(c.frames) > 0 {
				check(<-c.frames)
			}
			break wait
		case <-quiet.C:
			break wait
		case <-deadline:
			break wait
		}
	}
	if n := hookPanics.Load() - panics; n > 0 {
		fail("паника на сервере (%d): нарушен инвариант соединения или ошибка разбора", n)
	}
	// Законченные ответы со статусом 200: тело соответствует запросу.
	for _, sid := range order {
		st := streams[sid]
		if !st.done || st.status != "200" {
			continue
		}
		var want string
		switch {
		case strings.HasSuffix(st.path, "/early"):
			want = "early"
		case strings.HasSuffix(st.path, "/late"):
			want = "late"
		default:
			if !st.ended || st.reset {
				fail("поток %d (%s): полный ответ, хотя клиент не закончил тело: %q", sid, st.path, st.body)
			}
			want = fmt.Sprintf("%s:%d", st.path, st.sent)
		}
		if string(st.body) != want {
			fail("поток %d: тело %q, ждали %q", sid, st.body, want)
		}
	}
}

func FuzzStreams(f *testing.F) {
	// Сценарий четвёртого ревью: обработчик /late заканчивает поток между
	// HEADERS трейлеров и CONTINUATION.
	f.Add([]byte{0, 0x0a, 0x00, 6, 0, 2, 0, 0xf1})
	f.Add([]byte{0, 0x01, 0x00, 1, 0x80, 10, 6, 0, 0, 0x00, 0x00})
	f.Add([]byte{0, 0x02, 0x00, 1, 0, 5, 6, 3, 2, 0, 0x71, 6, 0})
	f.Add([]byte{7, 1, 0, 0x0d, 0x00, 1, 0x80, 40, 4, 0, 200, 6, 1})
	f.Add([]byte{0, 0x03, 0x01, 3, 0, 0, 0x0c, 0x00, 1, 0, 3, 2, 1, 0x33, 6, 2})
	f.Fuzz(runFuzzStreams)
}
