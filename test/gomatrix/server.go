package main

import (
	"fmt"
	"net/http"
)

// Tiny HTTPS server used by the Phase 3 multi-Go-version test matrix.
// Built once per Go toolchain in docs/phases/phase-3-matrix.md.
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
	_ = http.ListenAndServeTLS(":9443",
		"/etc/nginx-https/cert.pem",
		"/etc/nginx-https/key.pem", nil)
}
