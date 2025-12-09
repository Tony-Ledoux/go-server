package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
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
	JWTSigningKey  string
	PolkaKey       string
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
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
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
	// load the env file
	godotenv.Load()
	// create a empty apicfg struct
	apiCfg := &apiConfig{}
	// get db info and load queries
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("database error: ")
		os.Exit(1)
	}
	dbQueries := database.New(db)
	apiCfg.dbQueries = dbQueries
	// load JWT signing key and store it
	JWTKey := os.Getenv("JWT_SECRET")
	apiCfg.JWTSigningKey = JWTKey
	//load polka API KEY
	PolkaKey := os.Getenv("POLKA_KEY")
	apiCfg.PolkaKey = PolkaKey
	// load the server
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
	// update USER
	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		//validate the request and the body
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

		//get the accesstoken
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error :%v", err))
			return
		}
		// now token should be validated by resulting in an id
		id, err := auth.ValidateJWT(token, apiCfg.JWTSigningKey)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error :%v", err))
			return
		}
		// now i have an Id get the user assosiated with it from the database
		_, err = apiCfg.dbQueries.GetUserByID(r.Context(), id)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error :%v", err))
			return
		}
		// now you know the user exists in the database and the inserted is valid, update it
		hs_pw, err := auth.HashPassword(ur.Password)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error :%v", err))
			return
		}

		p := database.UpdateUserParams{
			ID:             id,
			Email:          ur.Email,
			HashedPassword: hs_pw,
		}
		upU, err := apiCfg.dbQueries.UpdateUser(r.Context(), p)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error :%v", err))
			return
		}
		rU := User{
			ID:        upU.ID,
			Email:     upU.Email,
			CreatedAt: upU.CreatedAt,
			UpdatedAt: upU.UpdatedAt,
		}
		respondWithJSON(w, http.StatusOK, rU)

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
		// generate the token
		token, err := auth.MakeJWT(dbUser.ID, apiCfg.JWTSigningKey, time.Duration(3600)*time.Second)
		if err != nil {
			respondWithError(w, http.StatusServiceUnavailable, "cannot create JWT token")
			return
		}
		// create refresh token
		rft, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, http.StatusServiceUnavailable, "cannot create refresh token")
			return
		}
		params := database.CreateTokenParams{
			Token:     rft,
			UserID:    dbUser.ID,
			ExpiresAt: time.Now().Add(1440 * time.Hour),
			RevokedAt: sql.NullTime{},
		}
		//store token in db
		_, err = apiCfg.dbQueries.CreateToken(r.Context(), params)
		if err != nil {
			respondWithError(w, http.StatusServiceUnavailable, "cannot store refresh token")
			return
		}

		u := User{
			ID:           dbUser.ID,
			CreatedAt:    dbUser.CreatedAt,
			UpdatedAt:    dbUser.UpdatedAt,
			Email:        dbUser.Email,
			Token:        token,
			RefreshToken: rft,
			IsChirpyRed:  dbUser.IsChirpyRed.Bool,
		}
		respondWithJSON(w, http.StatusOK, u)
	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error: %v", err))
			return
		}
		// chould have a token now
		db_id, err := apiCfg.dbQueries.GenerateAccessFromRefreshToken(r.Context(), token)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error: %v", err))
			return
		}
		tokenString, err := auth.MakeJWT(db_id, apiCfg.JWTSigningKey, time.Duration(3600)*time.Second)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error: %v", err))
			return
		}
		respondWithJSON(w, http.StatusOK, struct {
			Token string `json:"token"`
		}{
			Token: tokenString,
		})

	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, fmt.Sprintf("error: %v", err))
			return
		}
		// chould have a token now
		_, err = apiCfg.dbQueries.RevokeTokenByID(r.Context(), token)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, fmt.Sprintf("error: %v", err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// handle chirps
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error: %v", err))
			return
		}
		Uid, err := auth.ValidateJWT(token, apiCfg.JWTSigningKey)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("error: %v", err))
			return
		}

		if !strings.HasPrefix(ct, "application/json") {
			respondWithError(w, http.StatusUnsupportedMediaType, "something went wrong")
			return
		}
		var cr ChirpRequest
		if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
			respondWithError(w, http.StatusBadRequest, "can't decode json")
			return
		}
		// override the uiser id in the chirpRequest
		cr.UserId = Uid
		// chirps must have a body and a user_id
		if len(cr.Body) == 0 {
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
		author_id_q := r.URL.Query().Get("author_id")
		sort := r.URL.Query().Get("sort")
		if len(sort) == 0 || sort != "desc" {
			sort = "asc"
		}

		var dbChirps []database.Chirp
		var err error

		if len(author_id_q) == 0 {
			dbChirps, err = apiCfg.dbQueries.ListChrips(r.Context())
		} else {
			author_id, parseErr := uuid.Parse(author_id_q)
			if parseErr != nil {
				respondWithError(w, http.StatusBadRequest, "invalid author_id")
				return
			}
			dbChirps, err = apiCfg.dbQueries.ListChirpsFromAuthor(r.Context(), author_id)
		}

		if err != nil {
			respondWithError(w, http.StatusServiceUnavailable, "a problem getting chirps")
			return
		}

		// Convert []database.Chirp -> []ChirpResponse
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

		// Sort chirps by CreatedAt
		if sort == "asc" {
			slices.SortFunc(chirps, func(a, b ChirpResponse) int {
				return a.CreatedAt.Compare(b.CreatedAt)
			})
		} else {
			slices.SortFunc(chirps, func(a, b ChirpResponse) int {
				return b.CreatedAt.Compare(a.CreatedAt)
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
	// DELETE CHIRP
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpId, err := uuid.Parse(r.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Id malformed")
			return
		}
		// search the chirp in the database
		dbChirp, err := apiCfg.dbQueries.GetChirpById(r.Context(), chirpId)
		if err != nil {
			// no chirp found
			respondWithError(w, http.StatusNotFound, "chirp not found")
			return
		}
		// now i know the exits get the token
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "auth malformed")
			return
		}
		// validate the token
		userId, err := auth.ValidateJWT(token, apiCfg.JWTSigningKey)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "auth malformed")
			return
		}
		// check the id vs the owner of the chirp
		if userId != dbChirp.UserID {
			respondWithError(w, http.StatusForbidden, "Naughty Boy, this is not your Chirp")
			return
		}
		// delete the chirp
		err = apiCfg.dbQueries.DeleteChirpById(r.Context(), dbChirp.ID)
		if err != nil {
			respondWithError(w, http.StatusServiceUnavailable, "Deleting chirp Failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)

	})
	// webhooks
	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		type Req struct {
			Event string `json:"event"`
			Data  struct {
				UserId uuid.UUID `json:"user_id"`
			} `json:"data"`
		}
		hapi, err := auth.GetAPIKey(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if hapi != apiCfg.PolkaKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ct := r.Header.Get("Content-Type")
		var rs Req
		if !strings.HasPrefix(ct, "application/json") {
			respondWithError(w, http.StatusUnsupportedMediaType, "something went wrong")
			return
		}
		// try to decode the body
		if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
			respondWithError(w, http.StatusBadRequest, "can't decode json")
			return
		}
		if rs.Event != "user.upgraded" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			//upgrade the user
			_, err := apiCfg.dbQueries.UpgradeUserToRed(r.Context(), rs.Data.UserId)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}

	})
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}
