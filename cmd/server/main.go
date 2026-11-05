// Command server runs the identity / zero-trust / OIDC platform over HTTP.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/yourname/zt-ciam/internal/app"
	"github.com/yourname/zt-ciam/internal/clock"
	"github.com/yourname/zt-ciam/internal/httpapi"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	issuer := flag.String("issuer", "http://127.0.0.1:8080", "OIDC issuer URL (must match what clients use)")
	flag.Parse()

	key := []byte(os.Getenv("ZTCIAM_SIGNING_KEY"))
	if len(key) < 32 { // generate an ephemeral key so a secret is never hard-coded; tokens die on restart
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		key = []byte(hex.EncodeToString(b))
		log.Println("ZTCIAM_SIGNING_KEY not set: using an ephemeral signing key")
	}

	a := app.New(clock.Real{}, *issuer, key)
	a.OIDC.RegisterClient("demo-spa", "Demo SPA", []string{"http://127.0.0.1:3000/callback"})

	srv := &http.Server{Addr: *addr, Handler: httpapi.New(a), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on http://%s (issuer %s)", *addr, *issuer)
	log.Fatal(srv.ListenAndServe())
}
