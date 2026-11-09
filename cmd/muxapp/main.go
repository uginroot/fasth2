// muxapp is an ordinary net/http + gorilla/mux service. The only difference
// between the two benchmark variants is the -fasth2 flag (one line below).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/uginroot/fasth2"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	useFast := flag.Bool("fasth2", false, "replace HTTP/2 with fasth2")
	useTLS := flag.Bool("tls", false, "serve HTTPS (h2 via ALPN) instead of h2c")
	flag.Parse()

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello, World!"))
	})
	r.HandleFunc("/sleep", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond) // simulated DB call
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello, World!"))
	})
	r.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": mux.Vars(r)["id"], "name": "Anton"})
	})

	hs := &http.Server{Addr: *addr, Handler: r, Protocols: new(http.Protocols)}
	hs.Protocols.SetHTTP1(true)
	hs.Protocols.SetHTTP2(true)
	hs.Protocols.SetUnencryptedHTTP2(true)
	if *useFast {
		fasth2.ConfigureServer(hs, nil) // <- the whole migration
	}
	if *useTLS {
		hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSigned()}}
		log.Fatal(hs.ListenAndServeTLS("", ""))
	}
	log.Fatal(hs.ListenAndServe())
}

func selfSigned() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(),
		NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"localhost"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
