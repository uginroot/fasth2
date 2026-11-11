package fasth2

// Тесты быстрых путей адаптера net/http: разбор пути без url.ParseRequestURI и
// контекст запроса без регистрации в контексте соединения.

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"
)

// fastURL должен давать тот же url.URL, что url.ParseRequestURI, или nil.
func TestFastURLMatchesParseRequestURI(t *testing.T) {
	cases := []string{
		"/", "/a", "/a/b.c", "/pkg.Service/Method", "//x", "/a?", "/a?b=1&c=2", "/a?b=%20",
		"/a?b#c", "/%41", "/a;b", "/a b", "/ä", "/a/../b", "/a?b?c", "/~u/_x-y",
	}
	r := rand.New(rand.NewSource(1))
	alphabet := []byte("/aZ09-_.~?=&%#;:@!$'()*+,")
	for i := 0; i < 20000; i++ {
		b := []byte{'/'}
		for n := r.Intn(12); n > 0; n-- {
			b = append(b, alphabet[r.Intn(len(alphabet))])
		}
		cases = append(cases, string(b))
	}
	for _, s := range cases {
		got := fastURL(s)
		if got == nil {
			continue
		}
		want, err := url.ParseRequestURI(s)
		if err != nil {
			t.Fatalf("%q: fastURL разобрал, а ParseRequestURI вернул ошибку %v", s, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: fastURL %#v, ParseRequestURI %#v", s, got, want)
		}
	}
}

// Отмена BaseContext сервера отменяет контекст запроса, а значения из
// ConnContext доходят до обработчика.
func TestRequestContextFromBase(t *testing.T) {
	type key struct{}
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	started := make(chan string, 1)
	done := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := r.Context().Value(key{}).(string)
		started <- v
		select {
		case <-r.Context().Done():
			done <- r.Context().Err()
		case <-time.After(3 * time.Second):
			done <- nil
		}
	})
	hs := &http.Server{
		Handler:     h,
		BaseContext: func(net.Listener) context.Context { return base },
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context { return context.WithValue(ctx, key{}, "conn") },
	}
	addr, _ := startMux(t, hs, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, true, reqGET))
	select {
	case v := <-started:
		if v != "conn" {
			t.Fatalf("значение из ConnContext: %q", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("обработчик не запустился")
	}
	cancelBase()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("контекст запроса не отменён после отмены BaseContext")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("обработчик не дождался отмены")
	}
}

// Отмена BaseContext будит обработчик, который ждёт в Read потокового тела.
func TestBaseCancelWakesBodyRead(t *testing.T) {
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	reading := make(chan struct{})
	readErr := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reading)
		_, err := io.ReadAll(r.Body)
		readErr <- err
	})
	hs := &http.Server{Handler: h, BaseContext: func(net.Listener) context.Context { return base }}
	addr, _ := startMux(t, hs, nil)
	c := dialH2(t, addr, true)
	c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")), frame(frData, 0, 1, []byte("x")))
	<-reading
	time.Sleep(50 * time.Millisecond)
	cancelBase()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("Read вернул тело без ошибки после отмены BaseContext")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("обработчик остался в Read после отмены BaseContext")
	}
}
