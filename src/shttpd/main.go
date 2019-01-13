package main

import (
	"crypto/rand"
	"io"
	"net/http"
)

func main() {
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("./"))))

	http.HandleFunc("/speed", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="account.bin"`)
		w.Header().Set("Content-Length", "104857600")
		w.WriteHeader(200)
		io.CopyN(w, rand.Reader, 104857600)
	})

	http.ListenAndServe(":http", nil)
}

