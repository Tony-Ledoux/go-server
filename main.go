package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	log.Println("Starting server on :8080")

	mux.HandleFunc("/healthz", func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Add("Content-Type", "text/plain; charset=utf-8")
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
	})

	mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
