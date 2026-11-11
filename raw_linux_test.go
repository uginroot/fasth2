//go:build linux

package fasth2

// Тесты цикла чтения serveRaw (h2c на unix): EOF, который пришёл в одном
// TCP-сегменте с последними данными, не даёт новой готовности сокета.

import (
	"io"
	"net"
	"net/http"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Клиент шлёт GOAWAY и закрывает соединение; TCP_CORK склеивает данные и FIN
// в один сегмент. Сервер должен закрыть соединение сразу, а не по IdleTimeout.
func TestRawEOFWithLastData(t *testing.T) {
	// С одним P читатель не проснётся между данными и FIN: пробуждения сольются.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for i := 0; i < 20; i++ {
		addr, fs := startMux(t, &http.Server{Handler: http.HandlerFunc(okHandler)}, nil)
		c := dialH2(t, addr, true) // клиент читает всё: иначе close пошлёт RST, а не FIN
		for deadline := time.Now().Add(2 * time.Second); connCount(fs) == 0; {
			if time.Now().After(deadline) {
				t.Fatal("соединение не дошло до fasth2")
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond) // читатель ждёт готовности, клиент прочитал SETTINGS сервера
		rc, err := c.nc.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CORK, 1) })
		c.nc.Write(frame(frGoAway, 0, 0, make([]byte, 8)))
		c.nc.Close() // данные и FIN уходят одним сегментом
		for deadline := time.Now().Add(time.Second); connCount(fs) != 0; {
			if time.Now().After(deadline) {
				t.Fatalf("прогон %d: соединение не закрыто через 1 с после GOAWAY и FIN", i)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// Обработчик ещё работает, а клиент шлёт одним сегментом с FIN RST_STREAM
// (поток становится сиротой) или GOAWAY (поток открыт). Сервер должен заметить
// EOF сразу, а не по IdleTimeout.
func TestRawEOFWithOrphanOrGoAway(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	cases := []struct {
		name string
		last []byte
	}{
		{"RST_STREAM", frame(frRSTStream, 0, 1, u32(codeCancel))},
		{"GOAWAY", frame(frGoAway, 0, 0, make([]byte, 8))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				started := make(chan struct{}, 1)
				release := make(chan struct{})
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					started <- struct{}{}
					<-release
				})
				addr, fs := startMux(t, &http.Server{Handler: h}, nil)
				c := dialH2(t, addr, true)
				c.send(headers(1, true, reqGET))
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("обработчик не запустился")
				}
				time.Sleep(20 * time.Millisecond) // читатель ждёт готовности
				rc, err := c.nc.(*net.TCPConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CORK, 1) })
				c.nc.Write(tc.last)
				c.nc.Close() // данные и FIN уходят одним сегментом
				for deadline := time.Now().Add(time.Second); connCount(fs) != 0; {
					if time.Now().After(deadline) {
						close(release)
						t.Fatalf("прогон %d: соединение не закрыто через 1 с после %s и FIN", i, tc.name)
					}
					time.Sleep(time.Millisecond)
				}
				close(release)
			}
		})
	}
}

// Потоковый обработчик ждёт в Read (срока нет: ReadTimeout по умолчанию его не
// ограничивает), клиент шлёт последнее DATA и FIN одним сегментом без GOAWAY.
// Сервер должен заметить EOF сразу: другой готовности сокета не будет.
func TestRawEOFWhileStreamingRead(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for i := 0; i < 10; i++ {
		started := make(chan struct{}, 1)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			io.Copy(io.Discard, r.Body)
		})
		addr, fs := startMux(t, &http.Server{Handler: h}, nil)
		c := dialH2(t, addr, true)
		c.send(headers(1, false, reqBlock("POST", "/", "content-type", "application/grpc")))
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("обработчик не запустился")
		}
		time.Sleep(20 * time.Millisecond) // обработчик ждёт в Read, читатель — готовности
		rc, err := c.nc.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CORK, 1) })
		c.nc.Write(frame(frData, 0, 1, []byte("x")))
		c.nc.Close() // данные и FIN уходят одним сегментом
		for deadline := time.Now().Add(time.Second); connCount(fs) != 0; {
			if time.Now().After(deadline) {
				t.Fatalf("прогон %d: соединение не закрыто через 1 с после DATA и FIN", i)
			}
			time.Sleep(time.Millisecond)
		}
	}
}
