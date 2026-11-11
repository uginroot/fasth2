//go:build unix

package fasth2

import (
	"io"
	"net"
	"os"
	"syscall"
)

// serveRawIfPossible запускает serveRaw для h2c-соединения (*net.TCPConn).
// Для TLS и прочих net.Conn — false, читатель работает через net.Conn.Read.
func (c *conn) serveRawIfPossible() bool {
	tc, ok := c.nc.(*net.TCPConn)
	if !ok {
		return false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return false
	}
	c.serveRaw(rc)
	return true
}

// serveRaw — цикл чтения h2c-соединения (*net.TCPConn) внутри одного
// RawConn.Read на всё время жизни соединения. После короткого read колбэк
// возвращает false, и рантайм ждёт готовности сокета без лишнего read, который
// вернул бы EAGAIN (net.Conn.Read делает его на каждый раунд: при одном запросе
// на соединение это второй read на запрос). Готовность, пришедшая после
// короткого read, не теряется: рантайм сбрасывает её только при входе в
// RawConn.Read. Читатель держит ссылку на fd всё время, поэтому из-под c.mu
// соединение закрывается через abortLocked (shutdown), а Close делает читатель.
func (c *conn) serveRaw(rc syscall.RawConn) {
	c.mu.Lock()
	c.raw = rc // abortLocked читает его под c.mu
	c.mu.Unlock()
	end := roundGoOn
	for end == roundGoOn {
		deadline := false
		err := rc.Read(func(fd uintptr) bool {
			for {
				free := len(c.rbuf) - c.rend
				n, rerr := syscall.Read(int(fd), c.rbuf[c.rend:])
				if rerr == syscall.EINTR {
					continue
				}
				if rerr == syscall.EAGAIN {
					return false // данных нет: ждать готовности
				}
				if n < 0 {
					n = 0
				}
				if n == 0 && rerr == nil {
					rerr = io.EOF
				}
				if end = c.round(n, rerr); end != roundGoOn {
					return true
				}
				// Короткое чтение: сокет пуст, ждать готовности без read. FIN,
				// пришедший в одном сегменте с последними данными (GOAWAY,
				// RST_STREAM, DATA и close клиента), новой готовности не даёт.
				// Поэтому читаем ещё раз, если открытых потоков нет, клиент
				// прислал GOAWAY или тело потокового RPC ещё приходит (его
				// обработчик ждёт в Read без срока) — см. c.readAgain. Под
				// нагрузкой unary-запросами лишнего read нет. Если FIN пропущен
				// при открытом обычном потоке, клиент, закрывший сокет, ответит
				// RST на ответ обработчика, и следующий read вернёт ошибку. Долгий
				// обработчик без записи ограничен TCP keepalive (net.Listen
				// включает его по умолчанию): общего признака FIN у готовности
				// сокета в рантайме Go нет (EPOLLRDHUP не виден).
				if n < free && !c.readAgain {
					return false
				}
				// Полный буфер: читаем дальше без ожидания готовности, где рантайм
				// проверил бы срок. Проверяем его сами, иначе клиент, который держит
				// сокет полным, обходит таймауты потоков (ReadTimeout, WriteByteTimeout).
				if n == free && c.readDeadlinePassed() {
					deadline = true
					return true
				}
			}
		})
		if deadline {
			err = os.ErrDeadlineExceeded
		}
		if end == roundGoOn { // истёк срок чтения или соединение закрыто
			end = c.round(0, err)
		}
	}
	c.finish(end)
}

// shutdownRaw будит читателя serveRaw: read вернёт 0, и Close сделает он сам.
func shutdownRaw(rc syscall.RawConn) {
	rc.Control(func(fd uintptr) { syscall.Shutdown(int(fd), syscall.SHUT_RDWR) })
}
