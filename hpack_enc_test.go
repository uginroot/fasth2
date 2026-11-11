package fasth2

// Тесты кодера заголовков ответа с динамической таблицей HPACK.

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func encMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if id := r.URL.Query().Get("id"); id != "" {
			w.Header().Set("X-Id", strings.Repeat(id, 100/len(id)+1)) // запись около 140 байт
		}
		io.WriteString(w, "ok")
	})
	return m
}

// Повторный ответ на том же соединении: поля берутся из таблицы.
func TestHPACKEncoderReuse(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: encMux()}, nil)
	c := dialH2(t, addr, true)
	var sizes []int
	for sid := uint32(1); sid <= 5; sid += 2 {
		c.send(headers(sid, true, reqGET))
		f := c.await(3e9, "HEADERS", func(f tframe) bool { return f.sid == sid && f.typ == frHeaders })
		m := respFields(t, f)
		if m[":status"] != "200" || m["content-type"] != "text/plain" || m["date"] == "" || m["content-length"] != "2" {
			t.Fatalf("поток %d: поля %v", sid, m)
		}
		sizes = append(sizes, len(f.p))
		c.awaitBody(sid)
	}
	// :status (1) + content-type (1) + date (1 или новая запись) + content-length (4)
	if sizes[2] > 10 || sizes[2] >= sizes[0] {
		t.Fatalf("размеры блоков %v: повторный ответ не сжался", sizes)
	}
}

// Клиент запретил динамическую таблицу (SETTINGS_HEADER_TABLE_SIZE = 0):
// первый блок начинается с обновления размера 0, литералов с индексированием нет.
func TestHPACKEncoderTableSizeZero(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: encMux()}, nil)
	c := dialH2(t, addr, true, 1, 0)
	dec := newDecoder()
	dec.allowed = 0 // мы объявили таблицу 0: декодер не примет индексирование
	for sid := uint32(1); sid <= 5; sid += 2 {
		c.send(headers(sid, true, reqGET))
		f := c.await(3e9, "HEADERS", func(f tframe) bool { return f.sid == sid && f.typ == frHeaders })
		if sid == 1 && (len(f.p) == 0 || f.p[0] != 0x20) {
			t.Fatalf("первый блок без обновления размера таблицы до 0: % x", f.p)
		}
		var arena []byte
		var fields []headerField
		if _, err := dec.decode(f.p, &arena, &fields, 1<<20); err != nil {
			t.Fatalf("поток %d: %v", sid, err)
		}
		if len(dec.dyn) != 0 {
			t.Fatalf("поток %d: в таблице декодера %d записей", sid, len(dec.dyn))
		}
		c.awaitBody(sid)
	}
}

// 200 ответов с разными значениями X-Id вытесняют записи: таблицы кодера и
// декодера не расходятся (decode в readLoop падал бы на чужом индексе).
func TestHPACKEncoderEviction(t *testing.T) {
	addr, _ := startMux(t, &http.Server{Handler: encMux()}, nil)
	c := dialH2(t, addr, true)
	for i := 0; i < 200; i++ {
		sid := uint32(2*i + 1)
		id := strconv.Itoa(i % 50) // часть значений повторяется: и индексы, и вытеснение
		c.send(headers(sid, true, reqBlock("GET", "/?id="+id)))
		f := c.await(3e9, "HEADERS", func(f tframe) bool { return f.sid == sid && f.typ == frHeaders })
		m := respFields(t, f)
		if want := strings.Repeat(id, 100/len(id)+1); m["x-id"] != want || m["content-type"] != "text/plain" {
			t.Fatalf("ответ %d: x-id %q, content-type %q", i, m["x-id"], m["content-type"])
		}
		c.awaitBody(sid)
	}
}
