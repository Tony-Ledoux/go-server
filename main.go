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

	mux.Handle("/", http.FileServer(http.Dir(".")))

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
