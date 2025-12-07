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

	"github.com/Tony-Ledoux/go-server/internal/auth"
	"github.com/Tony-Ledoux/go-server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileServerHits atomic.Int32
	dbQueries      *database.Queries
}

type ChirpRequest struct {
	Body   string    `json:"body"`
	UserId uuid.UUID `json:"user_id"`
}

type ChirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type UserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
	cfg.dbQueries.ClearUsers(r.Context())
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
	// CREATE USER
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
		if len(ur.Email) == 0 || len(ur.Password) == 0 {
			respondWithError(w, http.StatusBadRequest, "please provide a email and password")
			return
		} else {
			hash, err := auth.HashPassword(ur.Password)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "can't hash password")
				return
			}
			params := database.CreateUserParams{
				Email:          ur.Email,
				HashedPassword: hash,
			}
			user, err := apiCfg.dbQueries.CreateUser(r.Context(), params)
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
	// LOGIN USER
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
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
		if len(ur.Email) == 0 || len(ur.Password) == 0 {
			respondWithError(w, http.StatusBadRequest, "please provide a email and password")
			return
		}
		// get the user from the database
		dbUser, err := apiCfg.dbQueries.GetUserByName(r.Context(), ur.Email)
		if err != nil {
			respondWithError(w, http.StatusForbidden, "incorrect user or password")
			return
		}
		//should be a valid user in the database, check the hashed password
		validPassword, err := auth.CheckPasswordHash(ur.Password, dbUser.HashedPassword)
		if err != nil || !validPassword {
			respondWithError(w, http.StatusUnauthorized, "incorrect user or password")
			return
		}
		//should be a valid password
		u := User{
			ID:        dbUser.ID,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
			Email:     dbUser.Email,
		}
		respondWithJSON(w, http.StatusOK, u)
	})
	// handle chirps
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			respondWithError(w, http.StatusUnsupportedMediaType, "something went wrong")
			return
		}
		var cr ChirpRequest
		if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
			respondWithError(w, http.StatusBadRequest, "can't decode json")
			return
		}
		// chirps must have a body and a user_id
		if len(cr.Body) == 0 || len(cr.UserId) == 0 {
			respondWithError(w, http.StatusBadRequest, "invalid format")
			return
		}
		if len(cr.Body) > 140 {
			respondWithError(w, http.StatusBadRequest, "Chirp is to long")
			return
		}
		// this is a valid chirp store in the database and return it
		params := database.CreateChirpParams{
			Body:   cr.Body,
			UserID: cr.UserId,
		}
		chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), params)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "can't create chirp")
			return
		}
		ch := ChirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		respondWithJSON(w, http.StatusCreated, ch)

	})
	// GET ALL CHIRPS
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		dbChirps, err := apiCfg.dbQueries.ListChrips(r.Context())
		if err != nil {
			respondWithError(w, http.StatusServiceUnavailable, "a problem getting chirps")
			return
		}
		// Convert []database.Chirp -> []chirpResponse
		chirps := make([]ChirpResponse, 0, len(dbChirps))
		for _, c := range dbChirps {
			chirps = append(chirps, ChirpResponse{
				ID:        c.ID,
				CreatedAt: c.CreatedAt,
				UpdatedAt: c.UpdatedAt,
				Body:      c.Body,
				UserID:    c.UserID,
			})
		}
		respondWithJSON(w, http.StatusOK, chirps)

	})
	// GET CHIRP BY ID
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "chirp id not valid")
			return
		}
		dbChirp, err := apiCfg.dbQueries.GetChirpById(r.Context(), id)
		if err != nil {
			respondWithError(w, http.StatusNotFound, "chirp not found")
			return
		}
		ch := ChirpResponse{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		}
		respondWithJSON(w, http.StatusOK, ch)

	})
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
