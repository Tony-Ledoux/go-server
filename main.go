package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
}

type Chirp struct {
	Body string `json:"body"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	hits := cfg.fileServerHits.Load()
	template := fmt.Sprintf(`<html>
	<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)
	fmt.Fprintf(w, "%s", template)
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileServerHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	apiCfg := &apiConfig{}
	log.Println("Starting server on :8080")

	mux.HandleFunc("GET /api/healthz", func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Add("Content-Type", "text/plain; charset=utf-8")
		resp.WriteHeader(200)
		resp.Write([]byte("OK"))
	})

	fileServerHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServerHandler))

	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)

	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)

	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if !strings.HasPrefix(ct, "application/json") {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			w.Write([]byte(`{"error": "something went wrong"}`))
			return
		}
		// try to decode the body
		var chirp Chirp
		if err := json.NewDecoder(r.Body).Decode(&chirp); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "something went wrong"}`))
			return
		}
		// now valid json and in chirp
		if len(chirp.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Chirp is to long"}`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"valid":true}`))
		}
	})

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
