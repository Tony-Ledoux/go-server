package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Tony-Ledoux/go-server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	dbQueries      *database.Queries
}

type Chirp struct {
	Body string `json:"body"`
}

type UserRequest struct {
	Email string `json:"email"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
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
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		respondWithError(w, http.StatusForbidden, "only allowed in dev.")
		return
	}
	cfg.fileServerHits.Store(0)
	// clear users table
	cfg.dbQueries.Clearusers(r.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	errorstr := fmt.Sprintf(`{"error":"%s"}`, msg)
	w.Write([]byte(errorstr))
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	data, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "can't marchal payload")
		return
	}
	w.WriteHeader(code)
	w.Write([]byte(data))
}

func main() {
	godotenv.Load()
	apiCfg := &apiConfig{}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("database error: ")
		os.Exit(1)
	}
	dbQueries := database.New(db)
	apiCfg.dbQueries = dbQueries
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
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
		if !strings.HasPrefix(ct, "application/json") {
			respondWithError(w, http.StatusUnsupportedMediaType, "something went wrong")
			return
		}
		// try to decode the body
		var chirp Chirp
		if err := json.NewDecoder(r.Body).Decode(&chirp); err != nil {
			respondWithError(w, http.StatusBadRequest, "can't decode json")
			return
		}
		// now valid json and in chirp
		if len(chirp.Body) > 140 {
			respondWithError(w, http.StatusBadRequest, "Chirp is to long")
		} else {
			// replace bad words in body with asterix
			bad_words := map[string]bool{
				"kerfuffle": true,
				"sharbert":  true,
				"fornax":    true,
			}
			words := strings.Split(chirp.Body, " ")
			for i, word := range words {
				if bad_words[strings.ToLower(word)] {
					words[i] = "****"
				}
			}
			res := strings.Join(words, " ")
			respondWithJSON(w, http.StatusOK, map[string]string{"cleaned_body": res})
		}
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			respondWithError(w, http.StatusUnsupportedMediaType, "something went wrong")
			return
		}
		// try to decode the body
		var ur UserRequest
		if err := json.NewDecoder(r.Body).Decode(&ur); err != nil {
			respondWithError(w, http.StatusBadRequest, "can't decode json")
			return
		}
		// now valid json and in ur
		if len(ur.Email) == 0 {
			respondWithError(w, http.StatusBadRequest, "please provide a email")
			return
		} else {
			user, err := apiCfg.dbQueries.CreateUser(r.Context(), ur.Email)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "can't create user")
				return
			}
			uj := User{
				ID:        user.ID,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				Email:     user.Email,
			}
			respondWithJSON(w, http.StatusCreated, uj)
		}
	})

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
