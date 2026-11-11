//go:build linux

package fasth2

// Тесты цикла чтения serveRaw (h2c на unix): EOF, который пришёл в одном
// TCP-сегменте с последними данными, не даёт новой готовности сокета.

import (
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
