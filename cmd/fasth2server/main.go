package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/uginroot/fasth2"
)

var hello = []byte("Hello, World!")

func main() {
	addr := flag.String("addr", ":8085", "listen address")
	async := flag.Bool("async", false, "run handlers on worker goroutines (may block)")
	flag.Parse()
	// SIGUSR1 prints allocation counter (for allocs-per-request measurement).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1)
	go func() {
		for range sig {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			fmt.Fprintf(os.Stderr, "mallocs=%d numgc=%d\n", ms.Mallocs, ms.NumGC)
		}
	}()
	srv := &fasth2.Server{Async: *async, Handler: func(req *fasth2.Request, resp *fasth2.Response) {
		if string(req.Path) == "/sleep" { // simulates a 1 ms DB/RPC call
			time.Sleep(time.Millisecond)
		}
		resp.AddHeader("content-type", "text/plain")
		resp.Write(hello)
	}}
	log.Fatal(srv.ListenAndServe(*addr))
}
